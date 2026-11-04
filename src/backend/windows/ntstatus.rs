//! Windows-specific exit-code interpretation: NTSTATUS detection and the
//! reviewed table of known abnormal-termination codes. The verdict for
//! every entry is `RE` with `exit_code` passed through — the table exists so
//! each abnormal end is *documented and reviewed*, not bucketed by a
//! pattern. Classification itself lives in the platform-neutral contract
//! (`contract::verdict`).

/// True when the exit code is an NTSTATUS (abnormal termination) rather than
/// a normal exit code.
pub(crate) fn is_ntstatus(exit_code: u32) -> bool {
    // NTSTATUS severity/facility layout: 0xC000xxxx are customer-facility
    // failures raised by the kernel (access violation, stack overflow, ...).
    (exit_code & 0xF000_0000) == 0xC000_0000
}

/// Human-readable name for known abnormal-termination NTSTATUS codes.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntstatus_detection() {
        assert!(is_ntstatus(0xC000_0005)); // access violation
        assert!(is_ntstatus(0xC000_00FD)); // stack overflow
        assert!(!is_ntstatus(0));
        assert!(!is_ntstatus(1));
        assert!(!is_ntstatus(255));
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
        // Unknown NTSTATUS still classifies RE via the generic path.
        assert_eq!(ntstatus_name(0xC000_9999), None);
        assert!(is_ntstatus(0xC000_9999));
    }
}
