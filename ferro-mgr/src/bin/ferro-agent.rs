#[cfg(target_os = "linux")]
include!("../ferro-agent-linux.rs");

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("ferro-agent is unsupported on this platform: Linux is required");
    std::process::exit(125);
}
