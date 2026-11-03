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
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
    EXTENDED_STARTUPINFO_PRESENT, InitializeProcThreadAttributeList,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
    PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW, STARTUPINFOW,
    UpdateProcThreadAttribute, DeleteProcThreadAttributeList,
};

use crate::platform::windows::job::{Job, wait_process_exit};
use crate::platform::windows::stdio::StdioSet;

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
pub(crate) struct SpawnSecurity {
    pub appcontainer_sid: *mut core::ffi::c_void,
    pub env_block: Vec<u16>, // UTF-16 "K=V\0" pairs, double-NUL terminated
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

/// Spawn `executable` with `args` inside `job`, wired to the stdio of
/// `stdio_set`. The child is suspended and job-assigned on success; the
/// judger-side duplicates of the child-facing stdio handles are closed here.
///
/// When `security` is given, the child becomes an AppContainer at creation
/// time (`PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`) and only the three
/// std handles are inheritable (`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`), and it
/// runs with the whitelisted environment block instead of the judger's env.
pub(crate) fn spawn_bare(
    executable: &Path,
    args: &[String],
    job: &Job,
    stdio_set: &mut StdioSet,
    cwd: Option<&Path>,
    security: Option<&SpawnSecurity>,
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

    let mut si = STARTUPINFOW {
        cb: if security.is_some() {
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

    // Attribute list for the sandboxed spawn (SECURITY_CAPABILITIES +
    // HANDLE_LIST). Built only when an AppContainer identity is requested.
    let mut attr_buf: Vec<u8> = Vec::new();
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
    if security.is_some() {
        let mut size = 0usize;
        // SAFETY: first call with a null list only queries the required size.
        unsafe {
            InitializeProcThreadAttributeList(std::ptr::null_mut(), 2, 0, &mut size);
        }
        attr_buf = vec![0u8; size];
        let list = attr_buf.as_mut_ptr() as *mut core::ffi::c_void;
        // SAFETY: buffer holds `size` bytes for a 2-attribute list.
        let ok = unsafe { InitializeProcThreadAttributeList(list, 2, 0, &mut size) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        // Only the three std handles are inherited into the child.
        // SAFETY: list is initialized; value points at a 3-handle array.
        let ok = unsafe {
            UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_ptr() as *mut _,
                std::mem::size_of::<[*mut core::ffi::c_void; 3]>(),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if let Some(sec) = security {
            sec_caps.AppContainerSid = sec.appcontainer_sid;
            // SAFETY: list is initialized; value points at a valid struct.
            let ok = unsafe {
                UpdateProcThreadAttribute(
                    list,
                    0,
                    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                    &mut sec_caps as *mut _ as *mut _,
                    std::mem::size_of::<SECURITY_CAPABILITIES>(),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
        }
        si_ex.lpAttributeList = list;
    }

    let flags = CREATE_SUSPENDED
        | if security.is_some() {
            EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT
        } else {
            0
        };
    let env_ptr = security
        .map(|s| s.env_block.as_ptr() as *const core::ffi::c_void)
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
    if !attr_buf.is_empty() {
        // SAFETY: the list was initialized above (non-empty buffer).
        unsafe { DeleteProcThreadAttributeList(attr_buf.as_mut_ptr() as *mut _) };
    }
    if let Some(e) = create_err {
        return Err(e);
    }

    let child = SpawnedChild {
        process: unsafe { OwnedHandle::from_raw_handle(pi.hProcess as RawHandle) },
        thread: unsafe { OwnedHandle::from_raw_handle(pi.hThread as RawHandle) },
        pid: pi.dwProcessId,
    };

    // Attach before resume so no grandchild can escape the job.
    job.assign(child.process.as_raw_handle() as HANDLE)?;

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
    use crate::platform::windows::job::{JobLimits, brief_pause};
    use crate::platform::windows::stdio::StdinSource;
    use std::time::Instant;

    fn limits() -> JobLimits {
        JobLimits {
            memory_limit_bytes: Some(512 * 1024 * 1024),
            cpu_time_limit_ms: None,
            max_processes: crate::platform::windows::job::DEFAULT_MAX_PROCESSES,
        }
    }

    /// Spawn + resume + wait, returning (exit_code, outputs).
    fn run_to_completion(
        exe: &str,
        args: &[&str],
        stdin: StdinSource,
        limits: &JobLimits,
    ) -> io::Result<(
        u32,
        crate::platform::windows::stdio::Output,
        crate::platform::windows::stdio::Output,
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
        use crate::platform::windows::acl;
        use crate::platform::windows::token::AppContainer;
        use crate::platform::windows::workdir::WorkDir;
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
        let security = SpawnSecurity {
            appcontainer_sid: ac.sid(),
            env_block: env_block(&env_vars),
        };
        // TODO(debug) TEMP/TMP isolated

        let comspec = PathBuf::from(std::env::var("ComSpec").unwrap());
        let run = |args: &[&str]| -> io::Result<(
            u32,
            crate::platform::windows::stdio::Output,
            crate::platform::windows::stdio::Output,
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
        assert_ne!(code, 0, "write to C:\\ must fail: {:?}", String::from_utf8_lossy(&err.data));
        assert!(!denied.exists(), "the denied file must not have been created");

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
}
