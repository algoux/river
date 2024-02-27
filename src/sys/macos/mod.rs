use crate::sys::SandboxImpl;

pub struct Sandbox {}

impl SandboxImpl for Sandbox {
    fn run() -> () {
        println!("macOS")
    }
}