#![cfg(target_os = "linux")]

use std::{env, fs, path::PathBuf};

use ferro_net::{
    cleanup_security_monitor, embedded_security_object, install_security_monitor,
    SecurityMonitorBuffer, SecurityMonitorConfig, SecurityMonitorRingBuffer,
};

/// Run only on a privileged host with tracefs and bpffs mounted:
///
/// ```text
/// sudo -E FERROCRATE_RUN_LIVE_EBPF_SECURITY=1 \
///   cargo test -p ferro-net --test security_monitor_live -- --ignored --nocapture
/// ```
#[test]
#[ignore = "requires root, tracefs, and bpffs"]
fn security_monitor_loads_attaches_delivers_and_cleans_up() {
    if env::var("FERROCRATE_RUN_LIVE_EBPF_SECURITY").as_deref() != Ok("1") {
        return;
    }
    assert_eq!(nix::unistd::geteuid().as_raw(), 0, "run this fixture as root");

    let object_path = env::temp_dir().join(format!(
        "ferro-security-live-{}-{}.o",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    fs::write(&object_path, embedded_security_object()).expect("write security object");
    let pin_root = PathBuf::from(format!(
        "/sys/fs/bpf/ferrocrate-security-live-{}",
        std::process::id()
    ));
    let config = SecurityMonitorConfig {
        object_path: object_path.display().to_string(),
        pin_root: pin_root.display().to_string(),
        events: vec!["openat".to_string()],
    };
    fs::create_dir_all(&pin_root).expect("create bpffs pin root");

    let installed = install_security_monitor(&config).expect("load and attach producer");
    assert_eq!(installed, vec!["openat"]);
    let map_path = pin_root.join("openat-events");
    let mut ring = SecurityMonitorRingBuffer::open(&map_path).expect("open pinned ring map");

    let _ = fs::read_to_string("/etc/hostname").expect("trigger openat");
    let mut buffer = SecurityMonitorBuffer::default();
    let mut delivered = 0;
    for _ in 0..100 {
        delivered += ring.drain_to(&mut buffer).expect("drain ring map");
        if delivered > 0 {
            break;
        }
        std::thread::yield_now();
    }
    assert!(delivered > 0, "tracepoint did not deliver a ring record");
    let event = buffer.pop().expect("decoded event");
    assert_eq!(event.event, "syscall");
    assert!(event.pid > 0);

    cleanup_security_monitor(&config).expect("cleanup monitor pins");
    fs::remove_dir(&pin_root).expect("remove empty pin root");
    fs::remove_file(object_path).expect("remove temporary object");
}
