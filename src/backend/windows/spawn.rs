//! Bare process creation for the sandbox child: `CreateProcessW` in suspended
//! state, attach to the Job, then resume. Judger-side stdio handle copies are
//! closed before this function returns (the S1 lesson: a surviving write end
//! starves the reader threads of EOF).

use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::Path;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Security::SECURITY_CAPABILITIES;
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, InitializeProcThreadAttributeList,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, PROCESS_INFORMATION, ResumeThread,
    STARTF_USESTDHANDLES, STARTUPINFOEXW, STARTUPINFOW, UpdateProcThreadAttribute,
};

/// Mitigation-policy encodings from the official UpdateProcThreadAttribute
/// documentation (each policy is one 2-bit field in a u64):
/// 0 = deferred, 1 = ALWAYS_ON, 2 = ALWAYS_OFF, 3 = reserved/opt-out.
const MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON: u64 = 0x1 << 28;
const MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON: u64 = 0x1 << 32;

/// The kernel attack-surface policies set on every sandboxed child (§1 第三层).
/// Both policies live in the *first* u64 of the MITIGATION_POLICY attribute.
///
/// Deliberately excludes CHILD_PROCESS_DISABLED — it conflicts with the agreed
/// wrapper process strategy (see DESIGN.md); "main process only" is enforced
/// by the monitor's residual-detection instead.
pub(crate) fn mitigation_policies() -> u64 {
    MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON
        | MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON
}

use crate::backend::windows::job::{Job, wait_process_exit};
use crate::backend::windows::stdio::StdioSet;

/// Silence the Windows "crash" dialog for sandboxed children.
///
/// `SEM_NOGPFAULTERRORBOX` suppresses the pop-up the system would show when
/// a child dies from an unhandled exception (the classic "This program has
/// encountered a serious problem" dialog). The child inherits the error
/// mode of the process that created it, so setting it in the judger before
/// the spawn is enough.
///
/// The mode is process-global, so the previous value is restored right
/// after the spawn to avoid changing the judger's own behaviour.
pub(crate) fn with_silent_crash_dialog<T>(f: impl FnOnce() -> T) -> T {
    use windows_sys::Win32::System::Diagnostics::Debug::{
        SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SetErrorMode,
    };
    // SAFETY: SetErrorMode takes/returns an error mode bitmask; no pointers.
    let previous = unsafe { SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS) };
    let result = f();
    // SAFETY: restoring the previously observed mode.
    unsafe { SetErrorMode(previous) };
    result
}

/// A spawned, still-owned child. The process starts suspended inside `job`;
/// call [`SpawnedChild::resume`] to let it run.
pub(crate) struct SpawnedChild {
    pub process: OwnedHandle,
    pub thread: OwnedHandle,
    pub pid: u32,
}

impl SpawnedChild {
    /// Let the (suspended) initial thread run.
    pub(crate) fn resume(&self) -> io::Result<()> {
        // SAFETY: thread handle is owned and valid.
        let prev = unsafe { ResumeThread(self.thread.as_raw_handle() as HANDLE) };
        if prev == u32::MAX {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Block until the process exits; returns its exit code.
    pub(crate) fn wait_exit(&self) -> io::Result<u32> {
        // SAFETY: process handle is owned and valid.
        wait_process_exit(self.process.as_raw_handle() as HANDLE)
    }
}

/// Windows command-line quoting (roughly `argv_to_cmdline` semantics):
/// wrap in quotes when the argument contains whitespace or quotes, doubling
/// backslashes that precede a quote and escaping the quote itself.
pub(crate) fn quote_arg(s: &str) -> String {
    if s.is_empty() {
        return "\"\"".to_string();
    }
    if !s.contains([' ', '\t', '"']) {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for c in s.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                for _ in 0..backslashes * 2 + 1 {
                    out.push('\\');
                }
                out.push('"');
                backslashes = 0;
            }
            other => {
                for _ in 0..backslashes {
                    out.push('\\');
                }
                out.push(other);
                backslashes = 0;
            }
        }
    }
    for _ in 0..backslashes {
        out.push('\\');
    }
    out.push('"');
    out
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Security configuration for a sandboxed spawn: the AppContainer SID the
/// child adopts and the whitelisted environment block it sees.
///
/// A null `appcontainer_sid` spawns with the judger token — only the
/// mitigation policies are applied (used to isolate policy effects in tests).
/// Security configuration for a sandboxed spawn: the AppContainer identity
/// the child adopts (if any), the mitigation policies, and the whitelisted
/// environment block it sees.
///
/// A null `appcontainer_sid` spawns with the judger token — only the
/// mitigation policies are applied (used to isolate policy effects in
/// tests); prefer the constructors below over hand-building the struct.
pub(crate) struct SpawnProfile {
    pub appcontainer_sid: *mut core::ffi::c_void,
    pub env_block: Vec<u16>,    // UTF-16 "K=V\0" pairs, double-NUL terminated
    pub mitigation_policy: u64, // MITIGATION_POLICY attribute word
}

impl SpawnProfile {
    /// The production profile: AppContainer identity + kernel attack-surface
    /// policies + whitelisted environment.
    pub(crate) fn sandboxed(appcontainer_sid: *mut core::ffi::c_void, env_block: Vec<u16>) -> Self {
        SpawnProfile {
            appcontainer_sid,
            env_block,
            mitigation_policy: mitigation_policies(),
        }
    }

    pub(crate) fn has_appcontainer(&self) -> bool {
        !self.appcontainer_sid.is_null()
    }
}

/// RAII wrapper around a `PROC_THREAD_ATTRIBUTE` list.
///
/// Every `add_*` call fails closed: on error the list stays valid and the
/// error is returned, and `Drop` always calls
/// `DeleteProcThreadAttributeList` exactly once (the hand-rolled cleanup
/// this replaces could leak the list on a mid-way `return Err`).
struct AttributeList {
    buf: Vec<u8>,
    initialized: bool,
}

impl AttributeList {
    fn new(count: u32) -> io::Result<Self> {
        let mut size = 0usize;
        // SAFETY: first call with a null list only queries the required size.
        unsafe {
            InitializeProcThreadAttributeList(std::ptr::null_mut(), count, 0, &mut size);
        }
        let mut list = AttributeList {
            buf: vec![0u8; size],
            initialized: false,
        };
        // SAFETY: buffer holds `size` bytes for the attribute list.
        let ok = unsafe {
            InitializeProcThreadAttributeList(list.buf.as_mut_ptr() as *mut _, count, 0, &mut size)
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        list.initialized = true;
        Ok(list)
    }

    fn add(
        &mut self,
        attribute: usize,
        value: *mut core::ffi::c_void,
        size: usize,
    ) -> io::Result<()> {
        // SAFETY: list is initialized; `value` points at `size` bytes of
        // attribute data that stay valid through the CreateProcessW call.
        let ok = unsafe {
            UpdateProcThreadAttribute(
                self.buf.as_mut_ptr() as *mut _,
                0,
                attribute,
                value,
                size,
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn as_ptr(&mut self) -> *mut core::ffi::c_void {
        self.buf.as_mut_ptr() as *mut _
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        if self.initialized {
            // SAFETY: the list was initialized and is deleted exactly once.
            unsafe { DeleteProcThreadAttributeList(self.buf.as_mut_ptr() as *mut _) };
        }
    }
}

/// Build a UTF-16 environment block (sorted, case-insensitive on the name —
/// what CreateProcessW expects) from `vars`.
pub(crate) fn env_block(vars: &[(String, String)]) -> Vec<u16> {
    let mut sorted = vars.to_vec();
    // Case-insensitive order without allocating per key (the old
    // `to_uppercase()` allocated one String per variable on every run).
    sorted.sort_unstable_by(|(a, _), (b, _)| {
        a.bytes()
            .map(|c| c.to_ascii_lowercase())
            .cmp(b.bytes().map(|c| c.to_ascii_lowercase()))
    });
    let mut block = Vec::new();
    for (k, v) in sorted {
        block.extend(k.encode_utf16());
        block.push('=' as u16);
        block.extend(v.encode_utf16());
        block.push(0);
    }
    block.push(0); // terminating extra NUL
    block
}

/// Guard for a freshly created, still-suspended child: if anything fails
/// between `CreateProcessW` and the successful job assignment, the child is
/// terminated on drop. Closing its handles alone is NOT enough — a suspended
/// process survives handle closure and would leak forever as an orphan
/// outside any job.
struct SuspendedGuard {
    /// `None` once the child has been handed off successfully (disarmed).
    child: Option<SpawnedChild>,
}

impl SuspendedGuard {
    fn new(child: SpawnedChild) -> Self {
        SuspendedGuard { child: Some(child) }
    }

    /// Take ownership of the child, disarming the kill-on-drop.
    fn disarm(mut self) -> SpawnedChild {
        self.child.take().expect("guard disarmed twice")
    }
}

impl Drop for SuspendedGuard {
    fn drop(&mut self) {
        use windows_sys::Win32::System::Threading::TerminateProcess;
        if let Some(child) = &self.child {
            // SAFETY: process handle is owned and valid.
            unsafe {
                TerminateProcess(child.process.as_raw_handle() as HANDLE, 1);
            }
            // Reap so the pid is released promptly; best effort.
            let _ = child.wait_exit();
        }
    }
}

/// Spawn `executable` with `args` inside `job`, wired to the stdio of
/// `stdio_set`. The child is suspended and job-assigned on success; the
/// judger-side duplicates of the child-facing stdio handles are closed here.
///
/// When `profile` is given, the child gets the mitigation policies always;
/// with an AppContainer identity it additionally becomes an AppContainer at
/// creation time (`PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`), only the
/// three std handles are inheritable (`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`),
/// and it runs with the whitelisted environment block instead of the
/// judger's env.
pub(crate) fn spawn_bare(
    executable: &Path,
    args: &[String],
    job: &Job,
    stdio_set: &mut StdioSet,
    cwd: Option<&Path>,
    profile: Option<&SpawnProfile>,
) -> io::Result<SpawnedChild> {
    let (child_stdin, child_stdout, child_stderr) = stdio_set.take_child_ends()?;

    let cmdline = {
        let mut line = quote_arg(&executable.display().to_string());
        for a in args {
            line.push(' ');
            line.push_str(&quote_arg(a));
        }
        to_wide(&line)
    };

    let si = STARTUPINFOW {
        cb: if profile.is_some() {
            std::mem::size_of::<STARTUPINFOEXW>() as u32
        } else {
            std::mem::size_of::<STARTUPINFOW>() as u32
        },
        dwFlags: STARTF_USESTDHANDLES,
        hStdInput: child_stdin.as_raw_handle() as _,
        hStdOutput: child_stdout.as_raw_handle() as _,
        hStdError: child_stderr.as_raw_handle() as _,
        ..Default::default()
    };
    // EXW wrapper: carries the attribute list; its first member is the
    // STARTUPINFOW CreateProcessW reads.
    let mut si_ex = STARTUPINFOEXW {
        StartupInfo: si,
        lpAttributeList: std::ptr::null_mut(),
    };
    let mut pi = PROCESS_INFORMATION::default();

    let cwd_wide = cwd.map(|c| to_wide(&c.display().to_string()));

    // Attribute list for the sandboxed spawn: HANDLE_LIST (only with an
    // AppContainer identity) + SECURITY_CAPABILITIES (same) + MITIGATION_POLICY.
    let mut attr_list = None;
    let mut sec_caps = SECURITY_CAPABILITIES {
        AppContainerSid: std::ptr::null_mut(),
        Capabilities: std::ptr::null_mut(),
        CapabilityCount: 0,
        Reserved: 0,
    };
    let handles = [
        child_stdin.as_raw_handle(),
        child_stdout.as_raw_handle(),
        child_stderr.as_raw_handle(),
    ];
    if let Some(profile) = profile {
        let has_ac = profile.has_appcontainer();
        let attr_count = if has_ac { 3 } else { 1 };
        let mut attrs = AttributeList::new(attr_count)?;

        // Only the three std handles are inherited into the child.
        if has_ac {
            attrs.add(
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_ptr() as *mut _,
                std::mem::size_of::<[*mut core::ffi::c_void; 3]>(),
            )?;
            sec_caps.AppContainerSid = profile.appcontainer_sid;
            attrs.add(
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                &mut sec_caps as *mut _ as *mut _,
                std::mem::size_of::<SECURITY_CAPABILITIES>(),
            )?;
        }
        // Kernel attack surface: win32k syscalls + DLL-injection hook
        // extension points are disabled for the child's lifetime.
        attrs.add(
            PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY as usize,
            &profile.mitigation_policy as *const u64 as *mut _,
            std::mem::size_of::<u64>(),
        )?;
        si_ex.lpAttributeList = attrs.as_ptr();
        attr_list = Some(attrs); // Drop deletes the list after CreateProcessW
    }

    let flags = CREATE_SUSPENDED
        | if profile.is_some() {
            EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT
        } else {
            0
        };
    let env_ptr = profile
        .map(|p| p.env_block.as_ptr() as *const core::ffi::c_void)
        .unwrap_or(std::ptr::null());

    // SAFETY: pointers are valid; stdio handles are inheritable (S1) and,
    // under the sandboxed spawn, restricted to the HANDLE_LIST above;
    // out-struct is valid.
    let ok = unsafe {
        CreateProcessW(
            std::ptr::null(),           // resolve executable from the command line
            cmdline.as_ptr() as *mut _, // mutable per Win32 contract
            std::ptr::null(),
            std::ptr::null(),
            1, // bInheritHandles
            flags,
            env_ptr,
            cwd_wide
                .as_ref()
                .map(|c| c.as_ptr())
                .unwrap_or(std::ptr::null()),
            &si_ex.StartupInfo, // EXW prefix shares the STARTUPINFOW layout
            &mut pi,
        )
    };
    let create_err = if ok == 0 {
        Some(io::Error::last_os_error())
    } else {
        None
    };
    // The attribute list may be deleted now that CreateProcessW returned
    // (RAII: `attr_list` drops here, `DeleteProcThreadAttributeList` runs
    // exactly once, also on the error path).
    drop(attr_list);
    if let Some(e) = create_err {
        return Err(e);
    }

    let child = SpawnedChild {
        process: unsafe { OwnedHandle::from_raw_handle(pi.hProcess as RawHandle) },
        thread: unsafe { OwnedHandle::from_raw_handle(pi.hThread as RawHandle) },
        pid: pi.dwProcessId,
    };
    // From here to the successful assign, any error must terminate the
    // suspended child (it is outside the job and would outlive its handles).
    let guarded = SuspendedGuard::new(child);

    // Attach before resume so no grandchild can escape the job. On error
    // the guard drops → suspended child terminated.
    job.assign(guarded.child.as_ref().unwrap().process.as_raw_handle() as HANDLE)?;

    let child = guarded.disarm();

    // Close the judger-side stdio duplicates: EOF on the reader side now
    // depends only on the child lifetime (S1 lesson).
    drop(child_stdin);
    drop(child_stdout);
    drop(child_stderr);

    Ok(child)
}
