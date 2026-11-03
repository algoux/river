//! Bare process creation for the sandbox child: `CreateProcessW` in suspended
//! state, attach to the Job, then resume. Judger-side stdio handle copies are
//! closed before this function returns (the S1 lesson: a surviving write end
//! starves the reader threads of EOF).

use std::fs::File;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::Path;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CreateProcessW, PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES,
    STARTUPINFOW,
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

/// Spawn `executable` with `args` inside `job`, wired to the stdio of
/// `stdio_set`. The child is suspended and job-assigned on success; the
/// judger-side duplicates of the child-facing stdio handles are closed here.
pub(crate) fn spawn_bare(
    executable: &Path,
    args: &[String],
    job: &Job,
    stdio_set: &mut StdioSet,
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
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        dwFlags: STARTF_USESTDHANDLES,
        hStdInput: child_stdin.as_raw_handle() as _,
        hStdOutput: child_stdout.as_raw_handle() as _,
        hStdError: child_stderr.as_raw_handle() as _,
        ..Default::default()
    };
    let mut pi = PROCESS_INFORMATION::default();

    // SAFETY: pointers are valid; stdio handles are inheritable (S1);
    // out-struct is valid.
    let ok = unsafe {
        CreateProcessW(
            std::ptr::null(),           // resolve executable from the command line
            cmdline.as_ptr() as *mut _, // mutable per Win32 contract
            std::ptr::null(),
            std::ptr::null(),
            1, // bInheritHandles
            CREATE_SUSPENDED,
            std::ptr::null(), // inherit parent environment (P2 will change this)
            std::ptr::null(), // inherit cwd (P2: sandbox working dir)
            &mut si,
            &mut pi,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
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
        let child = spawn_bare(Path::new(exe), &argvec, &job, &mut set)?;
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
        let child = spawn_bare(Path::new("cmd"), &args, &job, &mut set).unwrap();
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
        let child = spawn_bare(Path::new("ping"), &args, &job, &mut set).unwrap();
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
        let child = spawn_bare(Path::new("cmd"), &args, &job, &mut set).unwrap();
        child.resume().unwrap();
        let code = child.wait_exit().unwrap();
        assert_eq!(code, 0);
        let peak = job.peak_process_memory_used().unwrap();
        assert!(peak > 0, "peak memory: {peak}");
        set.finish().unwrap();
    }
}
