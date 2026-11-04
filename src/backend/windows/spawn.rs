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

/// Extension-point policy alone (tests isolate its effect from win32k).
#[cfg(test)]
pub(crate) fn mitigation_policies_ext_only() -> u64 {
    MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON
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

    /// A judger-token child with chosen policies (test isolation only).
    #[cfg(test)]
    pub(crate) fn test_only(mitigation_policy: u64, env_block: Vec<u16>) -> Self {
        SpawnProfile {
            appcontainer_sid: std::ptr::null_mut(),
            env_block,
            mitigation_policy,
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
    sorted.sort_by(|a, b| a.0.to_uppercase().cmp(&b.0.to_uppercase()));
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
/// outside any job (S11).
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
        child_stdin.as_raw_handle() as *mut core::ffi::c_void,
        child_stdout.as_raw_handle() as *mut core::ffi::c_void,
        child_stderr.as_raw_handle() as *mut core::ffi::c_void,
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
            &mut si_ex.StartupInfo, // EXW prefix shares the STARTUPINFOW layout
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

    // Attach before resume so no grandchild can escape the job.
    if let Err(e) = job.assign(guarded.child.as_ref().unwrap().process.as_raw_handle() as HANDLE) {
        return Err(e); // guard drops → suspended child terminated
    }

    let child = guarded.disarm();

    // Close the judger-side stdio duplicates: EOF on the reader side now
    // depends only on the child lifetime (S1 lesson).
    drop(child_stdin);
    drop(child_stdout);
    drop(child_stderr);

    Ok(child)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::windows::job::{JobLimits, brief_pause};
    use crate::backend::windows::stdio::StdinSource;
    use std::time::Instant;

    fn limits() -> JobLimits {
        JobLimits {
            memory_limit_bytes: Some(512 * 1024 * 1024),
            cpu_time_limit_ms: None,
            max_processes: crate::contract::SafetyCeilings::default().max_processes,
        }
    }

    /// The error mode is process-global: the helper must restore whatever
    /// was set before, so the judger's own behaviour is untouched.
    #[test]
    fn silent_crash_dialog_restores_the_previous_error_mode() {
        use windows_sys::Win32::System::Diagnostics::Debug::SetErrorMode;
        // SAFETY: no pointers; returns the previous mode.
        let before = unsafe { SetErrorMode(0) };
        // SAFETY: restore the mode we just observed.
        unsafe { SetErrorMode(before) };

        with_silent_crash_dialog(|| {
            use windows_sys::Win32::System::Diagnostics::Debug::SetErrorMode;
            // SAFETY: read the current mode back.
            let inside = unsafe { SetErrorMode(0) };
            // SAFETY: restore it.
            unsafe { SetErrorMode(inside) };
            assert_ne!(
                inside, before,
                "SEM_NOGPFAULTERRORBOX was not applied inside the guard"
            );
        });

        // SAFETY: read the mode back after the guard.
        let after = unsafe { SetErrorMode(0) };
        // SAFETY: restore it.
        unsafe { SetErrorMode(after) };
        assert_eq!(after, before, "the error mode was not restored");
    }

    /// Spawn + resume + wait, returning (exit_code, outputs).
    fn run_to_completion(
        exe: &str,
        args: &[&str],
        stdin: StdinSource,
        limits: &JobLimits,
    ) -> io::Result<(
        u32,
        crate::backend::windows::stdio::Output,
        crate::backend::windows::stdio::Output,
    )> {
        let job = Job::new(limits)?;
        let mut set = StdioSet::new(stdin, None, None, None, None)?;
        let argvec: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let child = spawn_bare(Path::new(exe), &argvec, &job, &mut set, None, None)?;
        child.resume()?;
        let code = child.wait_exit()?;
        let (out, err) = set.finish()?;
        Ok((code, out, err))
    }

    #[test]
    fn spawn_capture_and_exit_code() {
        let (code, out, _) =
            run_to_completion("cmd", &["/c", "echo hi"], StdinSource::Null, &limits()).unwrap();
        assert_eq!(code, 0);
        assert_eq!(out.data, b"hi\r\n");
    }

    #[test]
    fn descendants_are_allowed_up_to_the_cap() {
        // `cmd /c cmd /c exit 5` needs two live processes; with the default
        // cap the wrapper works and the inner exit code propagates.
        let (code, _, _) = run_to_completion(
            "cmd",
            &["/c", "cmd /c exit 5"],
            StdinSource::Null,
            &limits(),
        )
        .unwrap();
        assert_eq!(code, 5);
    }

    #[test]
    fn process_cap_blocks_fork_bomb() {
        // A tight cap (2) must stop a process that keeps spawning children.
        let tight = JobLimits {
            memory_limit_bytes: Some(512 * 1024 * 1024),
            cpu_time_limit_ms: None,
            max_processes: 2,
        };
        let job = Job::new(&tight).unwrap();
        let mut set = StdioSet::new(StdinSource::Null, None, None, None, None).unwrap();
        let args: Vec<String> = ["/c", "for /l %i in (1,1,50) do @start /b cmd /c exit"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let child = spawn_bare(Path::new("cmd"), &args, &job, &mut set, None, None).unwrap();
        child.resume().unwrap();
        let _ = child.wait_exit();
        // The cap bounds the damage: far fewer than 50 children survive.
        let alive = job.alive_process_count().unwrap();
        assert!(alive <= 2, "alive processes: {alive}");
        let _ = job.terminate(1);
        set.finish().unwrap();
    }

    #[test]
    fn terminate_kills_the_tree() {
        let job = Job::new(&limits()).unwrap();
        let mut set = StdioSet::new(StdinSource::Null, None, None, None, None).unwrap();
        let args: Vec<String> = ["/n", "10", "127.0.0.1"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let child = spawn_bare(Path::new("ping"), &args, &job, &mut set, None, None).unwrap();
        child.resume().unwrap();
        brief_pause();
        let started = Instant::now();
        job.terminate(1).unwrap();
        let code = child.wait_exit().unwrap();
        let elapsed = started.elapsed();
        assert_eq!(code, 1);
        assert!(elapsed.as_secs() < 5, "terminate took {elapsed:?}");
    }

    #[test]
    fn peak_memory_is_tracked() {
        let job = Job::new(&limits()).unwrap();
        let mut set = StdioSet::new(StdinSource::Null, None, None, None, None).unwrap();
        let args: Vec<String> = ["/c", "echo hi"].iter().map(|s| s.to_string()).collect();
        let child = spawn_bare(Path::new("cmd"), &args, &job, &mut set, None, None).unwrap();
        child.resume().unwrap();
        let code = child.wait_exit().unwrap();
        assert_eq!(code, 0);
        let peak = job.peak_process_memory_used().unwrap();
        assert!(peak > 0, "peak memory: {peak}");
        set.finish().unwrap();
    }

    /// S7: the child really becomes an AppContainer — writes inside the
    /// granted cwd succeed, writes to C:\ are denied, and it runs on the
    /// whitelisted environment (cmd needs SystemRoot to even start).
    #[test]
    fn appcontainer_child_writes_cwd_but_not_c_root() {
        use crate::backend::windows::acl;
        use crate::backend::windows::token::AppContainer;
        use crate::backend::windows::workdir::WorkDir;
        use std::path::PathBuf;

        let ac = AppContainer::create_or_open().unwrap();
        let dir = WorkDir::create().unwrap();
        acl::grant_rw(dir.path(), ac.sid()).unwrap();

        // Whitelist base. Learned in S7: an AppContainer spawn REQUIRES
        // LOCALAPPDATA in the environment block — without it CreateProcessW
        // fails with ERROR_ENVVAR_NOT_FOUND (203). TEMP/TMP point inside the
        // granted cwd.
        let tmp = dir.path().join("tmp");
        std::fs::create_dir(&tmp).unwrap();
        let env_vars = vec![
            (
                "SystemRoot".to_string(),
                std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string()),
            ),
            (
                "LOCALAPPDATA".to_string(),
                std::env::var("LOCALAPPDATA").unwrap_or_default(),
            ),
            ("TEMP".to_string(), tmp.display().to_string()),
            ("TMP".to_string(), tmp.display().to_string()),
            (
                "RIVER_TEST_MARKER".to_string(),
                "marker-visible".to_string(),
            ),
        ];
        let security = SpawnProfile::sandboxed(ac.sid(), env_block(&env_vars));

        let comspec = PathBuf::from(std::env::var("ComSpec").unwrap());
        let run = |args: &[&str]| -> io::Result<(
            u32,
            crate::backend::windows::stdio::Output,
            crate::backend::windows::stdio::Output,
        )> {
            let job = Job::new(&limits())?;
            let mut set = StdioSet::new(StdinSource::Null, None, None, None, None)?;
            let argvec: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            let child = spawn_bare(
                &comspec,
                &argvec,
                &job,
                &mut set,
                Some(dir.path()),
                Some(&security),
            )?;
            child.resume()?;
            let code = child.wait_exit()?;
            let (out, err) = set.finish()?;
            Ok((code, out, err))
        };

        // Write inside the granted cwd succeeds...
        let (code, _, _) = run(&["/c", "echo hi> out.txt"]).unwrap();
        assert_eq!(code, 0);
        assert!(
            dir.path().join("out.txt").exists(),
            "write inside the granted cwd must succeed"
        );

        // ...while writing to C:\ is denied.
        let denied = PathBuf::from(r"C:\river-ac-denied.txt");
        let _ = std::fs::remove_file(&denied);
        let (code, _, err) = run(&["/c", "echo x> C:\\river-ac-denied.txt"]).unwrap();
        assert_ne!(
            code,
            0,
            "write to C:\\ must fail: {:?}",
            String::from_utf8_lossy(&err.data)
        );
        assert!(
            !denied.exists(),
            "the denied file must not have been created"
        );

        // Environment isolation: the child sees the whitelisted block plus a
        // marker variable, not the judger's environment. (TEMP/TMP themselves
        // are overwritten by the kernel with the AppContainer profile paths —
        // the profile Temp dir is sandbox-private, which is fine.)
        let (code, out, _) = run(&["/c", "echo %PATH%;%RIVER_TEST_MARKER%"]).unwrap();
        assert_eq!(code, 0);
        let text = String::from_utf8_lossy(&out.data);
        assert!(
            text.starts_with("%PATH%;"),
            "judger PATH must not leak: {text}"
        );
        assert!(
            text.contains("marker-visible"),
            "whitelisted env vars must be visible: {text}"
        );
    }

    /// S8: the mitigation policies are *enforced by the kernel*, verified
    /// with behavioral probes from the child itself (not just attribute API
    /// return values):
    /// - EXTENSION_POINT_DISABLE: `SetWindowsHookExW` must fail with
    ///   ERROR_ACCESS_DISABLED_BY_POLICY (1260);
    /// - WIN32K_SYSTEM_DISABLE: `GetCursorPos` (a win32k syscall) must fail
    ///   with the same code.
    /// Both probes are also run from a plain judger-token child to prove the
    /// delta comes from the policies, not from some environmental accident.
    #[test]
    fn mitigation_policies_are_enforced_by_the_kernel() -> io::Result<()> {
        use crate::backend::windows::acl;
        use crate::backend::windows::token::AppContainer;
        use crate::backend::windows::workdir::WorkDir;

        const ERROR_ACCESS_DISABLED_BY_POLICY: u32 = 1260;

        // Probe host: a tiny native exe compiled with rustc. We must NOT use
        // PowerShell (or any .NET host) here — under win32k lockdown the CLR
        // dies with STATUS_DLL_INIT_FAILED before reaching the probe. The
        // probe never links user32; it LoadLibraryA's it at probe time, so a
        // win32k-blocked child reports a clean, attributable failure.
        let work = WorkDir::create().unwrap();
        let probe_rs = work.path().join("probe.rs");
        let probe_exe = work.path().join("probe.exe");
        std::fs::write(
            &probe_rs,
            r#"fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    unsafe {
        #[link(name = "kernel32")]
        extern "system" {
            fn LoadLibraryA(name: *const u8) -> *mut core::ffi::c_void;
            fn GetProcAddress(m: *mut core::ffi::c_void, name: *const u8) -> *mut core::ffi::c_void;
            fn GetLastError() -> u32;
        }
        if mode == "query" {
            // Kernel-applied mitigation state of THIS process (not the
            // attribute API). PROCESS_MITIGATION_POLICY index 6 =
            // ProcessExtensionPointDisablePolicy; Flags bit0 = enabled.
            // Must run BEFORE any user32 load (win32k lockdown breaks it).
            #[link(name = "kernel32")]
            extern "system" {
                fn GetProcessMitigationPolicy(h: isize, policy: u32, buf: *mut u32, len: usize) -> i32;
            }
            let mut flags: u32 = 0;
            let ok = GetProcessMitigationPolicy(-1isize, 6, &mut flags, 4);
            println!("query ok={} ext={}", ok, flags & 1);
            std::process::exit(if ok != 0 && flags & 1 == 1 { 0 } else { 5 });
        }
        let u = LoadLibraryA(b"user32.dll\0".as_ptr());
        if u.is_null() {
            // user32 cannot initialize under win32k lockdown — that denial
            // IS the policy working (ERROR_DLL_INIT_FAILED).
            println!("load-denied");
            std::process::exit(GetLastError() as i32);
        }
        // NOTE: user32 must never be a static import of this exe — under
        // win32k lockdown the loader would kill the process (0xC0000142)
        // before main. Everything resolves through LoadLibraryA/ProcAddress.
        #[link(name = "kernel32")]
        extern "system" {
            fn SetLastError(e: u32);
        }
        let get_cursor_pos: extern "system" fn(*mut (i32, i32)) -> i32 =
            std::mem::transmute(GetProcAddress(u, b"GetCursorPos\0".as_ptr()));
        if mode == "win32k" {
            let mut p = (0i32, 0i32);
            if get_cursor_pos(&mut p) == 0 {
                println!("win32k-denied");
                std::process::exit(GetLastError() as i32);
            }
            println!("win32k-ok");
            std::process::exit(0);
        }
        // NOTE: the hookinject mode was removed on purpose. Its trigger was
        // `CreateProcessW("notepad")` + hook-DLL injection detection, but
        // (a) packaged Win11 notepad survives our TerminateProcess (the
        // handle covers only the execution-alias stub), leaking GUI windows
        // onto the user's desktop, and (b) the injection signal proved
        // unreliable on Win11 even with no policy. The ext-point policy is
        // verified via the "query" mode (kernel-applied state) instead.
        println!("unknown mode: {mode}");
        std::process::exit(2);
    }
}
"#,
        )
        .unwrap();
        // Compile once with rustc (which cargo put in our environment).
        {
            let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
            {
                let job = Job::new(&limits())?;
                let mut set = StdioSet::new(StdinSource::Null, None, None, None, None)?;
                let args = [
                    "-O".to_string(),
                    "--edition=2021".to_string(),
                    format!("-o{}", probe_exe.display()),
                    probe_rs.display().to_string(),
                ];
                let child = spawn_bare(
                    Path::new(&rustc),
                    &args,
                    &job,
                    &mut set,
                    Some(work.path()),
                    None,
                )?;
                child.resume()?;
                let code = child.wait_exit()?;
                let (out, err) = set.finish()?;
                assert_eq!(code, 0, "rustc probe compile failed: {out:?} {err:?}");
            }
        }

        let run = |args: &[&str],
                   cwd: Option<&std::path::Path>,
                   security: Option<&SpawnProfile>|
         -> io::Result<(
            u32,
            crate::backend::windows::stdio::Output,
            crate::backend::windows::stdio::Output,
        )> {
            let job = Job::new(&limits())?;
            let mut set = StdioSet::new(StdinSource::Null, None, None, None, None)?;
            let argvec: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            let child = spawn_bare(&probe_exe, &argvec, &job, &mut set, cwd, security)?;
            child.resume()?;
            let code = child.wait_exit()?;
            let (out, err) = set.finish()?;
            Ok((code, out, err))
        };

        // Plain child (judger token, no policies): probes succeed / policy off.
        let (code, out, _) = run(&["query"], Some(work.path()), None)?;
        assert_eq!(code, 5, "plain child must show ext policy OFF: {out:?}");

        let (code, out, _) = run(&["win32k"], Some(work.path()), None)?;
        assert_eq!(code, 0, "win32k probe on a plain child: {out:?}");

        // Sandboxed child (AppContainer + policies): both denied by policy.
        let ac = AppContainer::create_or_open().unwrap();
        acl::grant_rw(work.path(), ac.sid()).unwrap();
        let tmp = work.path().join("tmp");
        std::fs::create_dir(&tmp).unwrap();
        let env_vars = vec![
            (
                "SystemRoot".to_string(),
                std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string()),
            ),
            (
                "LOCALAPPDATA".to_string(),
                std::env::var("LOCALAPPDATA").unwrap_or_default(),
            ),
            ("TEMP".to_string(), tmp.display().to_string()),
            ("TMP".to_string(), tmp.display().to_string()),
        ];
        let security = SpawnProfile::sandboxed(ac.sid(), env_block(&env_vars));

        // Policy-isolated child A (judger token, EXTENSION_POINT policy only,
        // no AppContainer): the child's own kernel mitigation state must show
        // the policy ENABLED. (Behavioral global-hook injection is not
        // reliably observable on recent Windows builds even without the
        // policy, so the kernel-applied state is the verified contract; the
        // policy blocks AppInit DLLs / Winsock LSPs / global-hook /
        // legacy-IME extension points for the child's lifetime.)
        let system_root_env = || {
            env_block(&[(
                "SystemRoot".to_string(),
                std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string()),
            )])
        };
        let ext_only = SpawnProfile::test_only(mitigation_policies_ext_only(), system_root_env());
        let (code, out, _) = run(&["query"], Some(work.path()), Some(&ext_only))?;
        assert_eq!(
            code, 0,
            "ext-point policy must be enabled in the kernel: {out:?}"
        );

        // Policy-isolated child B (judger token, full policies, no AC): user32
        // cannot even initialize under win32k lockdown — LoadLibraryA fails
        // with DLL_INIT_FAILED (or the syscall with DISABLED_BY_POLICY).
        let full_no_ac = SpawnProfile::test_only(mitigation_policies(), system_root_env());
        let (code, out, _) = run(&["win32k"], Some(work.path()), Some(&full_no_ac))?;
        assert!(
            code != 0 && code != 7,
            "win32k access must fail under the policy (no-AC): exit={code:#x} {out:?}"
        );
        // The load must have been denied, not executed successfully.
        assert!(
            out.data.starts_with(b"load-denied") || code == ERROR_ACCESS_DISABLED_BY_POLICY,
            "expected a user32 denial: exit={code:#x} {out:?}"
        );

        // Sandboxed child (AppContainer + policies): ext policy enabled...
        let (code, out, _) = run(&["query"], Some(work.path()), Some(&security))?;
        assert_eq!(
            code, 0,
            "ext-point policy must be enabled in the sandbox: {out:?}"
        );

        // ...and the win32k lockdown must deny user32 access entirely (the
        // exact failure surface varies: ERROR_ACCESS_DISABLED_BY_POLICY from
        // a denied syscall, or the user32 load failing outright).
        let (code, out, _) = run(&["win32k"], Some(work.path()), Some(&security))?;
        assert!(code != 0, "win32k syscall must be policy-denied: {out:?}");
        assert!(
            out.data.starts_with(b"load-denied") || code == ERROR_ACCESS_DISABLED_BY_POLICY,
            "expected a win32k denial: exit={code:#x} {out:?}"
        );

        Ok(())
    }
}
