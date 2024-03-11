use std::thread;
use std::time::Duration;

fn main() {
    let sleep_duration = Duration::from_secs(30);
    thread::sleep(sleep_duration);
}
