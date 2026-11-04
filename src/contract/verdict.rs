//! Evidence-driven verdict classification (a pure, platform-neutral function).
//!
//! Core principle: **evidence beats exit code**. A sandbox-enforced limit or a
//! sandbox kill is authoritative; the raw exit code of a terminated process
//! must not downgrade the verdict (a killed process often exits with an
//! arbitrary code — on Windows an NTSTATUS — that would otherwise read as
//! `RE`).
//!
//! A platform backend runs the process, then reports *what it observed* as a
//! [`RunEvidence`]; `classify` turns that evidence into a [`Verdict`]. The
//! priority order below is the single source of truth for all platforms.
//!
//! Priority (highest first):
//! 1. `SE` — residual descendants after the main process exited (anti-cheat)
//! 2. `OLE` — output kill: a channel passed its kill threshold and the
//!    sandbox reaped the job mid-run (`KillOrigin::OutputLimit`). Direct
//!    sandbox observation outranks inferred evidence.
//! 3. `MLE` — abnormal end (killed or nonzero exit) with peak memory at the
//!    limit: the memory cap made an allocation fail, so the failure *is* the
//!    memory-limit event. Ranked above `TLE` because an allocation bomb is
//!    usually *reaped by the wall watchdog* — the memory evidence identifies
//!    what actually ended the run.
//! 4. `TLE` — sandbox wall-clock kill, or measured CPU over the CPU limit
//! 5. exit code mapping — `AC` on clean 0; otherwise `RE`

/// Why (and whether) the sandbox ended the run itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum KillOrigin {
    /// The process exited on its own.
    #[default]
    None,
    /// Wall clock limit exceeded; the sandbox terminated the process tree.
    WallTimeout,
    /// CPU time limit exceeded (measured against the enforced limit while
    /// the process was still running); the sandbox terminated the tree.
    /// Linux-only in practice — Windows relies on the wall watchdog plus
    /// the post-exit CPU evidence check.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    CpuLimit,
    /// A stdout/stderr channel produced more than its kill threshold; the
    /// sandbox reaped the job mid-run.
    OutputLimit,
}

/// Everything the sandbox observed about one finished run. Backends fill
/// this in; [`classify`] turns it into a [`Verdict`].
///
/// The `*_limit` fields are the *effective* limits the backend enforced
/// (user limit or the internal safety ceiling) — `None` only when there is
/// nothing to compare against.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct RunEvidence {
    pub kill: KillOrigin,
    /// Raw exit code of the main process (NTSTATUS on abnormal Windows ends).
    pub exit_code: u32,
    /// Processes still alive in the sandbox after the main process exited.
    pub residual_processes: u32,
    /// The kernel OOM killer reaped a task in the sandbox cgroup during this
    /// run (`memory.events` `oom_kill` > 0). Linux-only signal; always false
    /// on Windows.
    pub oom_killed: bool,
    pub cpu_time_limit_ms: Option<u64>,
    pub cpu_time_used_ms: u64,
    pub memory_limit_bytes: Option<u64>,
    pub peak_memory_bytes: u64,
}

/// The frozen verdict set: `AC | TLE | MLE | OLE | RE | SE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    Ac,
    Tle,
    Mle,
    Ole,
    Re,
    Se,
}

impl Verdict {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Verdict::Ac => "AC",
            Verdict::Tle => "TLE",
            Verdict::Mle => "MLE",
            Verdict::Ole => "OLE",
            Verdict::Re => "RE",
            Verdict::Se => "SE",
        }
    }

    /// Synthesized signal: the sandbox killed the process tree for every
    /// sandbox-decided verdict (Windows has no signals; this mimics the
    /// Linux convention — DESIGN.md §2.3).
    pub(crate) fn synthesized_signal(&self) -> i32 {
        match self {
            Verdict::Tle | Verdict::Mle | Verdict::Ole | Verdict::Se => 9,
            Verdict::Ac | Verdict::Re => 0,
        }
    }
}

/// Tolerance when matching peak memory against the enforced memory limit.
///
/// The limit makes oversized allocations *fail* rather than succeed, so the
/// observed peak typically lands below the limit — by up to the size of the
/// allocation that was refused (a few pages for CRT growth, several MiB for
/// doubling reallocs). One page-granular minimum plus 1/8 of the limit
/// covers that gap without ever crediting a run that stayed well clear.
fn mle_peak_slack_bytes(limit_bytes: u64) -> u64 {
    const FLOOR: u64 = 1024 * 1024;
    FLOOR.max(limit_bytes / 8)
}

/// True when the process did not reach a normal, clean end: either the
/// sandbox killed it or it terminated abnormally. Only such runs may be
/// reclassified as `MLE`/`TLE` from evidence — a program that exited 0
/// *finished* within the limits it was given.
fn ended_abnormally(evidence: &RunEvidence) -> bool {
    evidence.kill != KillOrigin::None || evidence.exit_code != 0
}

/// Peak memory within `limit` (slack-tolerant)?
fn peak_hits_limit(peak_bytes: u64, limit_bytes: Option<u64>) -> bool {
    match limit_bytes {
        Some(limit) => peak_bytes.saturating_add(mle_peak_slack_bytes(limit)) >= limit,
        None => false,
    }
}

/// Evidence-driven classification — the single, platform-neutral authority
/// for mapping a finished run onto the frozen verdict set.
pub(crate) fn classify(evidence: &RunEvidence) -> Verdict {
    // 1. Anti-cheat: the program must not outlive its main process.
    if evidence.residual_processes > 0 && evidence.kill == KillOrigin::None {
        return Verdict::Se;
    }
    // 2. Output: an overflow kill is a *direct* sandbox observation (the
    //    reader fired past the kill threshold and the job was terminated
    //    mid-run) — it outranks the inferred memory/time evidence below.
    if evidence.kill == KillOrigin::OutputLimit {
        return Verdict::Ole;
    }
    // 3. Memory: an OOM kill is direct kernel evidence, and an abnormal end
    //    with the peak pinned at the limit is the allocation-bomb signature —
    //    report MLE, not the exit code or the watchdog kill that reaped it.
    if ended_abnormally(evidence)
        && (evidence.oom_killed
            || peak_hits_limit(evidence.peak_memory_bytes, evidence.memory_limit_bytes))
    {
        return Verdict::Mle;
    }
    // 4. Time: the watchdog kill, an explicit CPU-limit kill, or the
    //    measured CPU past the limit (covers both a backend time-limit kill
    //    and a fast program that still burned more CPU than allowed before
    //    exiting).
    let cpu_over = evidence
        .cpu_time_limit_ms
        .is_some_and(|limit| evidence.cpu_time_used_ms > limit);
    if matches!(
        evidence.kill,
        KillOrigin::WallTimeout | KillOrigin::CpuLimit
    ) || cpu_over
    {
        return Verdict::Tle;
    }
    // 5. Plain exit-code mapping.
    if evidence.exit_code == 0 {
        Verdict::Ac
    } else {
        Verdict::Re
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(kill: KillOrigin, exit_code: u32) -> RunEvidence {
        RunEvidence {
            kill,
            exit_code,
            ..Default::default()
        }
    }

    fn classify_ev(evidence: RunEvidence) -> Verdict {
        classify(&evidence)
    }

    // -- exit code mapping -------------------------------------------------

    #[test]
    fn normal_exit_zero_is_ac() {
        let v = classify_ev(ev(KillOrigin::None, 0));
        assert_eq!(v, Verdict::Ac);
        assert_eq!(v.as_str(), "AC");
        assert_eq!(v.synthesized_signal(), 0);
    }

    #[test]
    fn nonzero_exit_is_re() {
        let v = classify_ev(ev(KillOrigin::None, 5));
        assert_eq!(v, Verdict::Re);
        assert_eq!(v.synthesized_signal(), 0);
    }

    #[test]
    fn ntstatus_exit_is_re() {
        let v = classify_ev(ev(KillOrigin::None, 0xC000_0005));
        assert_eq!(v, Verdict::Re);
    }

    // -- sandbox kills -----------------------------------------------------

    #[test]
    fn kill_by_timeout_is_tle_with_signal_9() {
        let v = classify_ev(ev(KillOrigin::WallTimeout, 1));
        assert_eq!(v, Verdict::Tle);
        assert_eq!(v.synthesized_signal(), 9);
    }

    #[test]
    fn residual_descendants_are_se() {
        let mut e = ev(KillOrigin::None, 0);
        e.residual_processes = 2;
        let v = classify_ev(e);
        assert_eq!(v, Verdict::Se);
        assert_eq!(v.synthesized_signal(), 9);
    }

    #[test]
    fn output_limit_kill_is_ole() {
        let v = classify_ev(ev(KillOrigin::OutputLimit, 1));
        assert_eq!(v, Verdict::Ole);
        assert_eq!(v.synthesized_signal(), 9);
    }

    #[test]
    fn direct_output_observation_outranks_inferred_memory() {
        let limit = 64 * 1024 * 1024;
        let mut e = ev(KillOrigin::OutputLimit, 1);
        e.memory_limit_bytes = Some(limit);
        e.peak_memory_bytes = limit;
        assert_eq!(classify_ev(e), Verdict::Ole);
    }

    // -- CPU evidence -------------------------------------------------------

    #[test]
    fn cpu_evidence_upgrades_clean_exit_to_tle() {
        let mut e = ev(KillOrigin::None, 0);
        e.cpu_time_limit_ms = Some(1000);
        e.cpu_time_used_ms = 1500; // measured CPU over the limit
        assert_eq!(classify_ev(e), Verdict::Tle);
    }

    #[test]
    fn cpu_under_limit_keeps_ac() {
        let mut e = ev(KillOrigin::None, 0);
        e.cpu_time_limit_ms = Some(1000);
        e.cpu_time_used_ms = 900;
        assert_eq!(classify_ev(e), Verdict::Ac);
    }

    // -- memory evidence -----------------------------------------------------

    #[test]
    fn peak_at_limit_upgrades_abnormal_end_to_mle() {
        let limit = 64 * 1024 * 1024;
        // Allocation bomb killed by the watchdog with the peak pinned at the cap.
        let mut e = ev(KillOrigin::WallTimeout, 1);
        e.memory_limit_bytes = Some(limit);
        e.peak_memory_bytes = limit - 4096; // just under: allocation at the cap failed
        let v = classify_ev(e);
        assert_eq!(v, Verdict::Mle);
        assert_eq!(v.synthesized_signal(), 9);
        // Same evidence on a crash exit code (heap failure abort).
        let mut e = ev(KillOrigin::None, 0xC000_0005);
        e.memory_limit_bytes = Some(limit);
        e.peak_memory_bytes = limit;
        assert_eq!(classify_ev(e), Verdict::Mle);
    }

    #[test]
    fn peak_below_limit_is_not_mle() {
        let limit = 64 * 1024 * 1024;
        let mut e = ev(KillOrigin::None, 0xC000_0005);
        e.memory_limit_bytes = Some(limit);
        e.peak_memory_bytes = limit / 2;
        assert_eq!(classify_ev(e), Verdict::Re);
    }

    #[test]
    fn clean_exit_at_the_limit_stays_ac() {
        let limit = 64 * 1024 * 1024;
        let mut e = ev(KillOrigin::None, 0);
        e.memory_limit_bytes = Some(limit);
        e.peak_memory_bytes = limit - 4096;
        assert_eq!(classify_ev(e), Verdict::Ac);
    }

    #[test]
    fn mle_beats_tle_when_the_watchdog_reaps_an_allocation_bomb() {
        let limit = 64 * 1024 * 1024;
        let mut e = ev(KillOrigin::WallTimeout, 1);
        e.memory_limit_bytes = Some(limit);
        e.peak_memory_bytes = limit;
        assert_eq!(classify_ev(e), Verdict::Mle);
    }

    #[test]
    fn cpu_limit_kill_is_tle_with_signal_9() {
        let mut e = ev(KillOrigin::CpuLimit, 137);
        e.cpu_time_limit_ms = Some(500);
        e.cpu_time_used_ms = 500;
        let v = classify_ev(e);
        assert_eq!(v, Verdict::Tle);
        assert_eq!(v.synthesized_signal(), 9);
    }

    #[test]
    fn oom_kill_evidence_is_mle_even_below_the_peak_slack() {
        // The kernel OOM-killed a task: that is direct evidence, no need to
        // infer it from the peak.
        let limit = 64 * 1024 * 1024;
        let mut e = ev(KillOrigin::WallTimeout, 137);
        e.oom_killed = true;
        e.memory_limit_bytes = Some(limit);
        e.peak_memory_bytes = limit / 4;
        assert_eq!(classify_ev(e), Verdict::Mle);
    }

    #[test]
    fn verdict_strings_are_frozen() {
        assert_eq!(Verdict::Ac.as_str(), "AC");
        assert_eq!(Verdict::Tle.as_str(), "TLE");
        assert_eq!(Verdict::Mle.as_str(), "MLE");
        assert_eq!(Verdict::Ole.as_str(), "OLE");
        assert_eq!(Verdict::Re.as_str(), "RE");
        assert_eq!(Verdict::Se.as_str(), "SE");
    }
}
