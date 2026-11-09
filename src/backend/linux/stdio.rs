use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone)]
pub(crate) enum StdinSource {
    Null,
    Bytes(Vec<u8>),
    File(PathBuf),
}

pub(crate) struct OverflowFlags {
    pub(crate) stdout: AtomicBool,
    pub(crate) stderr: AtomicBool,
    event: Option<OwnedFd>,
}

impl Default for OverflowFlags {
    fn default() -> Self {
        OverflowFlags {
            stdout: AtomicBool::new(false),
            stderr: AtomicBool::new(false),
            event: make_eventfd(),
        }
    }
}

fn make_eventfd() -> Option<OwnedFd> {
    let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if fd < 0 {
        None
    } else {
        Some(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

impl OverflowFlags {
    pub(crate) fn any(&self) -> bool {
        self.stdout.load(Ordering::Relaxed) || self.stderr.load(Ordering::Relaxed)
    }

    pub(crate) fn event_fd(&self) -> Option<RawFd> {
        self.event.as_ref().map(|fd| fd.as_raw_fd())
    }

    pub(crate) fn drain_event(&self) {
        if let Some(fd) = &self.event {
            let mut buf = [0u8; 8];
            unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), 8) };
        }
    }

    pub(crate) fn fire(&self, index: usize) {
        let flag = if index == 0 {
            &self.stdout
        } else {
            &self.stderr
        };
        flag.store(true, Ordering::Relaxed);
        if let Some(fd) = &self.event {
            let one: u64 = 1;
            unsafe { libc::write(fd.as_raw_fd(), (&one as *const u64).cast(), 8) };
        }
    }
}

pub(crate) struct ChannelResult {
    pub(crate) data: Vec<u8>,
    pub(crate) truncated: bool,
    pub(crate) sink_truncated: bool,
}

struct ChannelPipe {
    read_end: OwnedFd,
    limit: Option<u64>,
    capture_ceiling: u64,
    sink_ceiling: u64,
    archive: Option<File>,
}

pub(crate) struct StdioSet {
    stdin: StdinSource,
    stdin_write: Option<OwnedFd>,
    stdin_read: Option<OwnedFd>,
    stdout_write: Option<OwnedFd>,
    stderr_write: Option<OwnedFd>,
    channels: Vec<ChannelPipe>,
    overflow: Arc<OverflowFlags>,
    feeder: Option<std::thread::JoinHandle<io::Result<()>>>,
    readers: Vec<std::thread::JoinHandle<io::Result<ChannelResult>>>,
    readers_started: bool,
}

impl StdioSet {
    pub(crate) fn new(
        stdin: StdinSource,
        stdout_limit_bytes: Option<u64>,
        stderr_limit_bytes: Option<u64>,
        stdout_file: Option<PathBuf>,
        stderr_file: Option<PathBuf>,
        ceilings: crate::contract::StdioCeilings,
    ) -> io::Result<Self> {
        let (stdin_read, stdin_write) = pipe_cloexec()?;
        let (stdout_read, stdout_write) = pipe_cloexec()?;
        let (stderr_read, stderr_write) = pipe_cloexec()?;
        Ok(StdioSet {
            stdin,
            stdin_write: Some(stdin_write),
            stdin_read: Some(stdin_read),
            stdout_write: Some(stdout_write),
            stderr_write: Some(stderr_write),
            channels: vec![
                ChannelPipe {
                    read_end: stdout_read,
                    limit: stdout_limit_bytes,
                    capture_ceiling: crate::contract::capture_ceiling(
                        stdout_limit_bytes,
                        ceilings.capture_limit_bytes,
                    ),
                    sink_ceiling: ceilings.sink_limit_bytes,
                    archive: open_archive(stdout_file)?,
                },
                ChannelPipe {
                    read_end: stderr_read,
                    limit: stderr_limit_bytes,
                    capture_ceiling: crate::contract::capture_ceiling(
                        stderr_limit_bytes,
                        ceilings.capture_limit_bytes,
                    ),
                    sink_ceiling: ceilings.sink_limit_bytes,
                    archive: open_archive(stderr_file)?,
                },
            ],
            overflow: Arc::new(OverflowFlags::default()),
            feeder: None,
            readers: Vec::new(),
            readers_started: false,
        })
    }

    pub(crate) fn child_fds(&self) -> (RawFd, RawFd, RawFd) {
        let as_raw = |fd: &Option<OwnedFd>| fd.as_ref().unwrap().as_raw_fd();
        (
            as_raw(&self.stdin_read),
            as_raw(&self.stdout_write),
            as_raw(&self.stderr_write),
        )
    }

    pub(crate) fn after_fork(&mut self) -> io::Result<()> {
        drop(self.stdin_read.take());
        drop(self.stdout_write.take());
        drop(self.stderr_write.take());
        let write_end = self
            .stdin_write
            .take()
            .ok_or_else(|| io::Error::other("stdin write end missing at after_fork"))?;
        self.feeder = start_feeder(&self.stdin, write_end)?;
        let overflow = Arc::clone(&self.overflow);
        for (index, ch) in std::mem::take(&mut self.channels).into_iter().enumerate() {
            let overflow = Arc::clone(&overflow);
            let handle = std::thread::Builder::new()
                .name(format!("river-stdio-{index}"))
                .spawn(move || drain_channel(ch, index, &overflow))
                .map_err(|e| io::Error::other(format!("spawn stdio reader thread: {e}")))?;
            self.readers.push(handle);
        }
        self.readers_started = true;
        Ok(())
    }

    pub(crate) fn overflow(&self) -> Arc<OverflowFlags> {
        Arc::clone(&self.overflow)
    }

    pub(crate) fn finish(self) -> io::Result<(ChannelResult, ChannelResult, bool)> {
        let StdioSet {
            stdin_write,
            feeder,
            mut readers,
            overflow,
            ..
        } = self;
        drop(stdin_write);
        if let Some(handle) = feeder {
            handle
                .join()
                .map_err(|_| io::Error::other("stdin feeder panicked"))??;
        }
        let mut results = Vec::with_capacity(2);
        for handle in readers.drain(..) {
            results.push(
                handle
                    .join()
                    .map_err(|_| io::Error::other("reader thread panicked"))??,
            );
        }
        let overflowed = overflow.any();
        let mut it = results.into_iter();
        Ok((it.next().unwrap(), it.next().unwrap(), overflowed))
    }
}

fn start_feeder(
    source: &StdinSource,
    write_end: OwnedFd,
) -> io::Result<Option<std::thread::JoinHandle<io::Result<()>>>> {
    let mut writer = File::from(write_end);
    match source {
        StdinSource::Null => Ok(None),
        StdinSource::Bytes(bytes) => {
            let bytes = bytes.clone();
            let handle = std::thread::Builder::new()
                .name("river-stdin".into())
                .spawn(move || writer.write_all(&bytes).or_else(ignore_epipe))
                .map_err(|e| io::Error::other(format!("spawn stdin feeder thread: {e}")))?;
            Ok(Some(handle))
        }
        StdinSource::File(path) => {
            let path = path.clone();
            let handle = std::thread::Builder::new()
                .name("river-stdin".into())
                .spawn(move || {
                    let mut file = match File::open(&path) {
                        Ok(f) => f,
                        Err(e) => return Err(e),
                    };
                    io::copy(&mut file, &mut writer)
                        .map(|_| ())
                        .or_else(ignore_epipe)
                })
                .map_err(|e| io::Error::other(format!("spawn stdin feeder thread: {e}")))?;
            Ok(Some(handle))
        }
    }
}

fn ignore_epipe(e: io::Error) -> io::Result<()> {
    if e.kind() == io::ErrorKind::BrokenPipe {
        Ok(())
    } else {
        Err(e)
    }
}

fn drain_channel(
    ch: ChannelPipe,
    index: usize,
    overflow: &OverflowFlags,
) -> io::Result<ChannelResult> {
    let ChannelPipe {
        read_end,
        limit,
        capture_ceiling,
        sink_ceiling,
        mut archive,
    } = ch;
    let mut reader = File::from(read_end);
    let mut sample: Vec<u8> = Vec::with_capacity((capture_ceiling as usize).min(1 << 20));
    let mut total: u64 = 0;
    let mut sink_bytes: u64 = 0;
    let mut sink_truncated = false;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        if let Some(archive) = archive.as_mut() {
            if sink_bytes < sink_ceiling {
                let room = ((sink_ceiling - sink_bytes) as usize).min(n);
                archive.write_all(&buf[..room])?;
                sink_bytes += room as u64;
                if room < n {
                    sink_truncated = true;
                }
            } else {
                sink_truncated = true;
            }
        }
        let remaining = (capture_ceiling.saturating_sub(sample.len() as u64) as usize).min(n);
        sample.extend_from_slice(&buf[..remaining]);
        total += n as u64;
        if let Some(limit) = limit
            && total > limit
        {
            overflow.fire(index);
        }
    }
    if let Some(archive) = archive.as_mut() {
        archive.flush()?;
    }
    let truncated = total > capture_ceiling;
    Ok(ChannelResult {
        data: sample,
        truncated,
        sink_truncated,
    })
}

fn open_archive(path: Option<PathBuf>) -> io::Result<Option<File>> {
    match path {
        Some(p) => Ok(Some(File::create(p)?)),
        None => Ok(None),
    }
}

fn pipe_cloexec() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((unsafe { OwnedFd::from_raw_fd(fds[0]) }, unsafe {
        OwnedFd::from_raw_fd(fds[1])
    }))
}
