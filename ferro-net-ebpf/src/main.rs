#![no_std]
#![no_main]
#![deny(clippy::undocumented_unsafe_blocks)]

mod abi;

use aya_ebpf::{macros::map, maps::HashMap};
use core::panic::PanicInfo;

use abi::{
    CONNTRACK_KEY_LEN, CONNTRACK_MAX_ENTRIES, CONNTRACK_VALUE_LEN, ENDPOINT_KEY_LEN,
    ENDPOINT_MAX_ENTRIES, ENDPOINT_VALUE_LEN, META_KEY_LEN, META_MAX_ENTRIES, META_VALUE_LEN,
    POLICY_KEY_LEN, POLICY_MAX_ENTRIES, POLICY_VALUE_LEN, PORT_KEY_LEN, PORT_MAX_ENTRIES,
    PORT_VALUE_LEN,
};

#[map]
static FERRO_ENDPOINTS: HashMap<[u8; ENDPOINT_KEY_LEN], [u8; ENDPOINT_VALUE_LEN]> =
    HashMap::with_max_entries(ENDPOINT_MAX_ENTRIES, 0);

#[map]
static FERRO_PORTS: HashMap<[u8; PORT_KEY_LEN], [u8; PORT_VALUE_LEN]> =
    HashMap::with_max_entries(PORT_MAX_ENTRIES, 0);

#[map]
static FERRO_CONNTRACK: HashMap<[u8; CONNTRACK_KEY_LEN], [u8; CONNTRACK_VALUE_LEN]> =
    HashMap::with_max_entries(CONNTRACK_MAX_ENTRIES, 0);

#[map]
static FERRO_POLICY: HashMap<[u8; POLICY_KEY_LEN], [u8; POLICY_VALUE_LEN]> =
    HashMap::with_max_entries(POLICY_MAX_ENTRIES, 0);

#[map]
static FERRO_META: HashMap<[u8; META_KEY_LEN], [u8; META_VALUE_LEN]> =
    HashMap::with_max_entries(META_MAX_ENTRIES, 0);

#[used]
static ABI_VERSION: u32 = abi::PROGRAM_ABI_VERSION;

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
