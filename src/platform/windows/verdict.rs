//! Verdict synthesis: how a finished run maps onto the frozen `Status`
//! contract (`AC | TLE | MLE | OLE | RE | SE` + synthesized signal).
//!
//! S9 principle: **evidence beats exit code**. A sandbox-enforced limit or a
//! sandbox kill is authoritative; the raw exit code of a terminated process
//! must not downgrade the verdict (a killed process often exits with an
//! arbitrary NTSTATUS that would otherwise read as `RE`).
//!
//! Priority (highest first):
//! 1. `SE` — residual descendants after the main process exited (anti-cheat)
//! 2. `OLE` — output kill: a channel passed its kill threshold and the
//!    sandbox reaped the job mid-run (`KillReason::OutputLimit`). Direct
//!    sandbox observation outranks inferred evidence.
//! 3. `MLE` — abnormal end (killed or nonzero exit) with peak memory at the
//!    job's commit limit: the commit cap made an allocation fail, so the
//!    failure *is* the memory-limit event. Ranked above `TLE` because a
//!    malloc bomb is usually *reaped by the wall watchdog* — the memory
//!    evidence identifies what actually ended the run.
//! 4. `TLE` — sandbox wall-clock kill, or measured CPU over the CPU limit
//! 5. exit code mapping — `AC` on clean 0; otherwise `RE`, with the NTSTATUS
//!    table below keeping abnormal terminations classified `RE`, code passed
//!    through (S10)

use crate::platform::windows::monitor::KillReason;

pub(crate) const AC: &str = "AC";
pub(crate) const TLE: &str = "TLE";
pub(crate) const MLE: &str = "MLE";
pub(crate) const OLE: &str = "OLE";
pub(crate) const RE: &str = "RE";
pub(crate) const SE: &str = "SE";

/// Synthesized signal values (Windows has no signals; we mimic the Linux
/// convention for caller portability — see DESIGN.md §2.3).
pub(crate) const SIGKILL: i32 = 9;
pub(crate) const SIG_NONE: i32 = 0;

/// Tolerance when matching peak memory against the job's commit limit.
///
/// The job limit makes oversized allocations *fail* rather than succeed, so
/// the observed peak typically lands below the limit — by up to the size of
/// the allocation that was refused (a few pages for CRT growth, several MiB
/// for doubling reallocs). One page-granular minimum plus 1/8 of the limit
/// covers that gap without ever crediting a run that stayed well clear.
fn mle_peak_slack_bytes(limit_bytes: u64) -> u64 {
    const FLOOR: u64 = 1024 * 1024;
    FLOOR.max(limit_bytes / 8)
}

pub(crate) struct Verdict {
    pub status: &'static str,
    pub signal: i32,
}

/// True when the exit code is an NTSTATUS (abnormal termination) rather than
/// a normal exit code.
pub(crate) fn is_ntstatus(exit_code: u32) -> bool {
    // NTSTATUS severity/facility layout: 0xC000xxxx are customer-facility
    // failures raised by the kernel (access violation, stack overflow, ...).
    (exit_code & 0xF000_0000) == 0xC000_0000
}

/// Human-readable name for known abnormal-termination NTSTATUS codes. The
/// verdict for every entry is `RE` with `exit_code` passed through unchanged
/// — the table exists so each abnormal end is *documented and reviewed*, not
/// bucketed by a pattern. Codes not in the table still map to `RE` via
/// `is_ntstatus`.
pub(crate) fn ntstatus_name(code: u32) -> Option<&'static str> {
    Some(match code {
        // Memory / address errors
        0xC000_0005 => "STATUS_ACCESS_VIOLATION",
        0xC000_0006 => "STATUS_IN_PAGE_ERROR",
        0xC000_00FD => "STATUS_STACK_OVERFLOW",
        0xC000_0409 => "STATUS_STACK_BUFFER_OVERRUN", // __fastfail
        // Instruction / arithmetic
        0xC000_001D => "STATUS_ILLEGAL_INSTRUCTION",
        0xC000_0025 => "STATUS_NONCONTINUABLE_EXCEPTION",
        0xC000_0094 => "STATUS_INTEGER_DIVIDE_BY_ZERO",
        0xC000_0095 => "STATUS_INTEGER_OVERFLOW",
        0xC000_008D..=0xC000_0093 => "STATUS_FLOAT_FAULT", // FPU exceptions block
        // Loader / runtime startup failures
        0xC000_0135 => "STATUS_DLL_NOT_FOUND",
        0xC000_0139 => "STATUS_ENTRYPOINT_NOT_FOUND",
        0xC000_0142 => "STATUS_DLL_INIT_FAILED",
        // CRT / runtime aborts
        0xC000_0404 => "STATUS_INVALID_CRT_PARAMETER", // invalid parameter handler
        _ => return None,
    })
}

/// True when the process did not reach a normal, clean end: either we killed
/// it or it terminated abnormally. Only such runs may be reclassified as
/// `MLE`/`TLE` from evidence — a program that exited 0 *finished* within the
/// limits it was given.
fn ended_abnormally(kill_reason: &KillReason, exit_code: u32) -> bool {
    !matches!(kill_reason, KillReason::None) || exit_code != 0
}

/// Peak commit memory within `limit` (slack-tolerant)?
fn peak_hits_commit_limit(peak_bytes: u64, limit_bytes: Option<u64>) -> bool {
    match limit_bytes {
        Some(limit) => {
            peak_bytes.saturating_add(mle_peak_slack_bytes(limit)) >= limit
        }
        None => false,
    }
}

/// Evidence-driven classification. `cpu_time_limit_ms` / `memory_limit_bytes`
/// are the *effective* limits the job was created with (user limit or the
/// internal safety ceiling — `None` only when there is nothing to compare).
#[allow(clippy::too_many_arguments)]
pub(crate) fn classify_with_evidence(
    kill_reason: &KillReason,
    exit_code: u32,
    residual_processes: u32,
    cpu_time_limit_ms: Option<u64>,
    cpu_time_used_ms: u64,
    memory_limit_bytes: Option<u64>,
    peak_memory_bytes: u64,
) -> Verdict {
    // 1. Anti-cheat: the program must not outlive its main process.
    if residual_processes > 0 && matches!(kill_reason, KillReason::None) {
        return Verdict {
            status: SE,
            signal: SIGKILL,
        };
    }
    // 2. Output: an overflow kill is a *direct* sandbox observation (the
    //    reader thread fired past the kill threshold and we terminated the
    //    job) — it outranks the inferred memory/time evidence below.
    if matches!(kill_reason, KillReason::OutputLimit) {
        return Verdict {
            status: OLE,
            signal: SIGKILL,
        };
    }
    // 3. Memory: an abnormal end with the peak pinned at the commit limit is
    //    the malloc-bomb signature — report MLE, not the exit code or the
    //    watchdog kill that reaped it.
    if ended_abnormally(kill_reason, exit_code)
        && peak_hits_commit_limit(peak_memory_bytes, memory_limit_bytes)
    {
        return Verdict {
            status: MLE,
            signal: SIGKILL,
        };
    }
    // 4. Time: the watchdog kill, or the measured CPU past the limit
    //    (covers both the job's PROCESS_TIME kill and a fast program that
    //    still burned more CPU than allowed before exiting).
    let cpu_over = match cpu_time_limit_ms {
        Some(limit) => cpu_time_used_ms > limit,
        None => false,
    };
    if matches!(kill_reason, KillReason::WallTimeout) || cpu_over {
        return Verdict {
            status: TLE,
            signal: SIGKILL,
        };
    }
    // 5. Plain exit-code mapping.
    if exit_code == 0 {
        Verdict {
            status: AC,
            signal: SIG_NONE,
        }
    } else {
        Verdict {
            status: RE,
            signal: SIG_NONE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classify(kill_reason: &KillReason, exit_code: u32) -> Verdict {
        classify_with_evidence(kill_reason, exit_code, 0, None, 0, None, 0)
    }

    #[test]
    fn normal_exit_zero_is_ac() {
        let v = classify(&KillReason::None, 0);
        assert_eq!(v.status, "AC");
        assert_eq!(v.signal, 0);
    }

    #[test]
    fn nonzero_exit_is_re() {
        let v = classify(&KillReason::None, 5);
        assert_eq!(v.status, "RE");
        assert_eq!(v.signal, 0);
    }

    #[test]
    fn ntstatus_exit_is_re() {
        let v = classify(&KillReason::None, 0xC000_0005);
        assert_eq!(v.status, "RE");
    }

    #[test]
    fn kill_by_timeout_is_tle_with_signal_9() {
        let v = classify(&KillReason::WallTimeout, 1);
        assert_eq!(v.status, "TLE");
        assert_eq!(v.signal, 9);
    }

    #[test]
    fn residual_descendants_are_se() {
        let v = classify_with_evidence(&KillReason::None, 0, 2, None, 0, None, 0);
        assert_eq!(v.status, "SE");
        assert_eq!(v.signal, 9);
    }

    #[test]
    fn cpu_evidence_upgrades_clean_exit_to_tle() {
        let v = classify_with_evidence(
            &KillReason::None,
            0,
            0,
            Some(1000),
            1500, // measured CPU over the limit
            None,
            0,
        );
        assert_eq!(v.status, "TLE");
        assert_eq!(v.signal, 9);
    }

    #[test]
    fn cpu_under_limit_keeps_ac() {
        let v = classify_with_evidence(
            &KillReason::None,
            0,
            0,
            Some(1000),
            900,
            None,
            0,
        );
        assert_eq!(v.status, "AC");
    }

    #[test]
    fn peak_at_commit_limit_upgrades_abnormal_end_to_mle() {
        let limit = 64 * 1024 * 1024;
        // malloc bomb killed by the watchdog with the peak pinned at the cap.
        let v = classify_with_evidence(
            &KillReason::WallTimeout,
            1,
            0,
            None,
            0,
            Some(limit),
            limit - 4096, // just under: allocation at the cap failed
        );
        assert_eq!(v.status, "MLE");
        assert_eq!(v.signal, 9);
        // Same evidence on a crash exit code (heap failure abort).
        let v = classify_with_evidence(
            &KillReason::None,
            0xC000_0005,
            0,
            None,
            0,
            Some(limit),
            limit,
        );
        assert_eq!(v.status, "MLE");
    }

    #[test]
    fn peak_below_limit_is_not_mle() {
        let limit = 64 * 1024 * 1024;
        let v = classify_with_evidence(
            &KillReason::None,
            0xC000_0005,
            0,
            None,
            0,
            Some(limit),
            limit / 2,
        );
        assert_eq!(v.status, "RE");
    }

    #[test]
    fn clean_exit_at_the_limit_stays_ac() {
        let limit = 64 * 1024 * 1024;
        let v = classify_with_evidence(
            &KillReason::None,
            0,
            0,
            None,
            0,
            Some(limit),
            limit - 4096,
        );
        assert_eq!(v.status, "AC");
    }

    #[test]
    fn mle_beats_tle_when_the_watchdog_reaps_a_malloc_bomb() {
        let limit = 64 * 1024 * 1024;
        let v = classify_with_evidence(
            &KillReason::WallTimeout,
            1,
            0,
            None,
            0,
            Some(limit),
            limit,
        );
        assert_eq!(v.status, "MLE");
    }

    #[test]
    fn ntstatus_detection() {
        assert!(is_ntstatus(0xC000_0005)); // access violation
        assert!(is_ntstatus(0xC000_00FD)); // stack overflow
        assert!(!is_ntstatus(0));
        assert!(!is_ntstatus(1));
        assert!(!is_ntstatus(255));
    }

    #[test]
    fn output_limit_kill_is_ole() {
        let v = classify_with_evidence(
            &KillReason::OutputLimit,
            1,
            0,
            None,
            0,
            None,
            0,
        );
        assert_eq!(v.status, "OLE");
        assert_eq!(v.signal, 9);
        // Direct output observation outranks inferred memory evidence.
        let limit = 64 * 1024 * 1024;
        let v = classify_with_evidence(
            &KillReason::OutputLimit,
            1,
            0,
            None,
            0,
            Some(limit),
            limit,
        );
        assert_eq!(v.status, "OLE");
    }

    /// Each documented NTSTATUS entry must resolve to a stable name; the
    /// full table is in `ntstatus_name` and reviewed entry by entry.
    #[test]
    fn ntstatus_table_covers_known_abnormal_ends() {
        for (code, expected) in [
            (0xC000_0005, "STATUS_ACCESS_VIOLATION"),
            (0xC000_0006, "STATUS_IN_PAGE_ERROR"),
            (0xC000_00FD, "STATUS_STACK_OVERFLOW"),
            (0xC000_0409, "STATUS_STACK_BUFFER_OVERRUN"),
            (0xC000_001D, "STATUS_ILLEGAL_INSTRUCTION"),
            (0xC000_0025, "STATUS_NONCONTINUABLE_EXCEPTION"),
            (0xC000_0094, "STATUS_INTEGER_DIVIDE_BY_ZERO"),
            (0xC000_0095, "STATUS_INTEGER_OVERFLOW"),
            (0xC000_008E, "STATUS_FLOAT_FAULT"), // FPU block interior
            (0xC000_0135, "STATUS_DLL_NOT_FOUND"),
            (0xC000_0139, "STATUS_ENTRYPOINT_NOT_FOUND"),
            (0xC000_0142, "STATUS_DLL_INIT_FAILED"),
            (0xC000_0404, "STATUS_INVALID_CRT_PARAMETER"),
        ] {
            assert_eq!(ntstatus_name(code), Some(expected), "code {code:#x}");
            assert!(is_ntstatus(code));
        }
        // Unknown NTSTATUS still classifies RE (generic path).
        assert_eq!(ntstatus_name(0xC000_9999), None);
        assert!(is_ntstatus(0xC000_9999));
    }

    /// A clean 0 exit is never disturbed by NTSTATUS classification.
    #[test]
    fn clean_exit_stays_ac_even_with_table() {
        assert_eq!(classify(&KillReason::None, 0).status, "AC");
        // Abnormal NTSTATUS lands RE, code passthrough is the caller's info.
        assert_eq!(classify(&KillReason::None, 0xC000_0005).status, "RE");
    }
}
