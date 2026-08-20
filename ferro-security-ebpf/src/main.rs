#![cfg_attr(any(target_arch = "bpf", bpf_target_arch), no_std)]
#![cfg_attr(any(target_arch = "bpf", bpf_target_arch), no_main)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![allow(unexpected_cfgs)]

#[cfg(any(target_arch = "bpf", bpf_target_arch))]
mod producer {
    use aya_ebpf::{
        btf_maps::RingBuf,
        helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns},
        macros::{btf_map, tracepoint},
        programs::TracePointContext,
    };

    const EVENT_NAME_BYTES: usize = 32;
    const PAYLOAD_BYTES: usize = 256;
    const WIRE_BYTES: usize = EVENT_NAME_BYTES + 4 + 4 + 8 + PAYLOAD_BYTES;

    #[btf_map]
    pub static FERRO_SECURITY_EVENTS: RingBuf<(), { 1 << 20 }> = RingBuf::new();

    /// Generic syscall tracepoint producer. The userspace loader binds this
    /// section to each configured `sys_enter_*` event and identifies the
    /// selected event by its per-event map pin path.
    #[tracepoint]
    pub fn ferro_security_tracepoint(ctx: TracePointContext) -> u32 {
        let _ = ctx;
        let Some(mut record) = FERRO_SECURITY_EVENTS.reserve_bytes(WIRE_BYTES, 0) else {
            return 0;
        };
        record[..EVENT_NAME_BYTES].fill(0);
        record[..7].copy_from_slice(b"syscall");
        let pid = (bpf_get_current_pid_tgid() as u32).to_le_bytes();
        let uid = (bpf_get_current_uid_gid() as u32).to_le_bytes();
        // SAFETY: bpf_ktime_get_ns takes no pointers and returns a scalar.
        let timestamp = unsafe { bpf_ktime_get_ns() }.to_le_bytes();
        let offset = EVENT_NAME_BYTES;
        record[offset..offset + 4].copy_from_slice(&pid);
        record[offset + 4..offset + 8].copy_from_slice(&uid);
        record[offset + 8..offset + 16].copy_from_slice(&timestamp);
        record[offset + 16..].fill(0);
        record.submit(0);
        0
    }
}

#[cfg(not(any(target_arch = "bpf", bpf_target_arch)))]
fn main() {}

#[cfg(any(target_arch = "bpf", bpf_target_arch))]
use core::panic::PanicInfo;

#[cfg(any(target_arch = "bpf", bpf_target_arch))]
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
