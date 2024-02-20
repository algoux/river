use crate::sys::Sys;

pub struct S {}

impl Sys for S {
    fn run() -> () {
        println!("Linux")
    }
}