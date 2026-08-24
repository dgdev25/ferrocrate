#[cfg(target_os = "linux")]
include!("linux_main.rs");

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("ferro-cri is unsupported on this platform: Linux is required");
    std::process::exit(125);
}
