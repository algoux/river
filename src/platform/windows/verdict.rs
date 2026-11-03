//! Verdict synthesis: how a finished run maps onto the frozen `Status`
//! contract (`AC | TLE | MLE | OLE | RE | SE` + synthesized signal).
//!
//! S3 scope: AC/RE plus the wall-timeout path. S9 adds MLE and job-CPU TLE;
//! S10 adds the full NTSTATUS table and OLE.

use crate::platform::windows::monitor::KillReason;

pub(crate) const AC: &str = "AC";
pub(crate) const TLE: &str = "TLE";
pub(crate) const RE: &str = "RE";
pub(crate) const SE: &str = "SE";

/// Synthesized signal values (Windows has no signals; we mimic the Linux
/// convention for caller portability — see DESIGN.md §2.3).
pub(crate) const SIGKILL: i32 = 9;
pub(crate) const SIG_NONE: i32 = 0;

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

pub(crate) fn classify(kill_reason: &KillReason, exit_code: u32) -> Verdict {
    match kill_reason {
        KillReason::WallTimeout => Verdict {
            status: TLE,
            signal: SIGKILL,
        },
        KillReason::None => {
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn kill_by_timeout_is_tle_with_signal_9() {
        let v = classify(&KillReason::WallTimeout, 1);
        assert_eq!(v.status, "TLE");
        assert_eq!(v.signal, 9);
    }

    #[test]
    fn ntstatus_detection() {
        assert!(is_ntstatus(0xC000_0005)); // access violation
        assert!(is_ntstatus(0xC000_00FD)); // stack overflow
        assert!(!is_ntstatus(0));
        assert!(!is_ntstatus(1));
        assert!(!is_ntstatus(255));
    }
}
