use clap::Parser;
use clap_verbosity_flag::Verbosity;
use env_logger::Builder;
use log::{error, trace};

#[cfg(target_os = "linux")]
use sys::linux::Sandbox;
#[cfg(target_os = "macos")]
use sys::macos::Sandbox;
#[cfg(target_os = "windows")]
use sys::windows::Sandbox;

use crate::sys::SandboxImpl;

mod error;
mod status;
mod sys;

/// example: `river -vvv -- /usr/bin/echo hello world`
#[derive(Parser, Debug)]
#[clap(version = "1.0.0", author = "MeiK <meik2333@gmail.com>")]
pub struct Opts {
    /// Input stream. The default value is STDIN(0)
    #[clap(short, long)]
    input: Option<String>,

    /// Output stream. The default value is STDOUT(1)
    #[clap(short, long)]
    output: Option<String>,

    /// Error stream. The default value is STDERR(2)
    #[clap(short, long)]
    error: Option<String>,

    /// Output location of the running result. The default value is STDOUT(1)
    #[clap(short, long)]
    result: Option<String>,

    /// Time limit, in ms. The default value is unlimited.
    #[clap(short, long)]
    time_limit: Option<u32>,

    /// CPU Time limit, in ms. The default value is unlimited.
    #[clap(short, long)]
    cpu_time_limit: Option<u32>,

    /// Memory limit, in kib. The default value is unlimited.
    #[clap(short, long)]
    memory_limit: Option<u32>,

    /// Program to run and command line arguments
    #[clap(last(true), required = true)]
    command: Vec<String>,

    /// A level of verbosity, and can be used multiple times
    #[command(flatten)]
    verbose: Verbosity,
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            input: None,
            output: None,
            error: None,
            result: None,
            time_limit: None,
            cpu_time_limit: None,
            memory_limit: None,
            command: vec![],
            verbose: Default::default(),
        }
    }
}

fn main() {
    let opts: Opts = Opts::parse();

    Builder::new()
        .filter_level(opts.verbose.log_level_filter())
        .init();

    trace!("{:?}", opts);
    let result = opts.result.clone();
    let status = unsafe { Sandbox::with_opts(opts).run() };
    match status {
        Ok(val) => {
            if let Err(e) = val.write(result) {
                error!("{}", e);
                std::process::exit(1);
            }
        }
        Err(e) => {
            error!("{}", e);
            std::process::exit(1);
        }
    }
}
