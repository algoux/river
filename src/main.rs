use clap::Parser;
use clap_verbosity_flag::Verbosity;
use env_logger::Builder;

/// example: `river -- /usr/bin/echo hello world`
#[derive(Parser, Debug)]
#[clap(version = "1.0", author = "MeiK <meik2333@gmail.com>")]
struct Opts {
    /// Input stream. The default value is STDIN(0)
    #[clap(short, long, default_value = "/STDIN/")]
    input: String,

    /// Output stream. The default value is STDOUT(1)
    #[clap(short, long, default_value = "/STDOUT/")]
    output: String,

    /// Error stream. The default value is STDERR(2)
    #[clap(short, long, default_value = "/STDERR/")]
    error: String,

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    /// Working directory. The default value is the current directory.
    #[clap(short, long, default_value = "./")]
    workdir: String,

    /// Output location of the running result. The default value is STDOUT(1)
    #[clap(short, long, default_value = "/STDOUT/")]
    result: String,

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    /// Time limit, in ms. The default value is unlimited.
    #[clap(short, long, default_value = "0")]
    time_limit: i32,

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    /// Memory limit, in kib. The default value is unlimited.
    #[clap(short, long, default_value = "0")]
    memory_limit: i32,

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    /// Maximum number of files that can be written. The unit is bit. The default value is unlimited.
    #[clap(short, long, default_value = "0")]
    file_size_limit: i32,

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    /// Cgroup version, 1 or 2
    #[clap(short, long, default_value = "1")]
    cgroup: i32,

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    /// Number of processes that can be created. The default value is unlimited.
    #[clap(short, long, default_value = "0")]
    pids: i32,

    /// Program to run and command line arguments
    #[clap(last(true), required = true)]
    command: Vec<String>,

    /// A level of verbosity, and can be used multiple times
    #[command(flatten)]
    verbose: Verbosity,

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    /// Network enable
    #[clap(long, default_value = "false")]
    network: bool,
}

fn main() {
    let opts: Opts = Opts::parse();

    Builder::new()
        .filter_level(opts.verbose.log_level_filter())
        .init();

    println!("{:?}", opts);
}
