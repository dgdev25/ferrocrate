#![cfg(target_os = "linux")]

use ferro_net::ebpf::{build_bpftool_load_cmd, EbpfProgram};

#[test]
fn ebpf_program_builder_is_deterministic() {
    let prog = EbpfProgram {
        name: "xdp_prog".to_string(),
        object_path: "/opt/ferro/xdp.o".to_string(),
        section: "xdp".to_string(),
    };
    let cmd = build_bpftool_load_cmd(&prog, "/sys/fs/bpf/ferro/xdp");
    assert_eq!(
        cmd,
        vec![
            "bpftool",
            "prog",
            "load",
            "/opt/ferro/xdp.o",
            "/sys/fs/bpf/ferro/xdp",
            "type",
            "xdp"
        ]
    );
}
