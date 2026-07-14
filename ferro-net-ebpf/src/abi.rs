pub const PROGRAM_ABI_VERSION: u32 = 1;

pub const ENDPOINT_KEY_LEN: usize = 4;
pub const ENDPOINT_VALUE_LEN: usize = 12;
pub const PORT_KEY_LEN: usize = 4;
pub const PORT_VALUE_LEN: usize = 8;
pub const CONNTRACK_KEY_LEN: usize = 16;
pub const CONNTRACK_VALUE_LEN: usize = 16;
pub const POLICY_KEY_LEN: usize = 8;
pub const POLICY_VALUE_LEN: usize = 4;
pub const META_KEY_LEN: usize = 4;
pub const META_VALUE_LEN: usize = 4;

pub const ENDPOINT_MAX_ENTRIES: u32 = 4_096;
pub const PORT_MAX_ENTRIES: u32 = 65_536;
pub const CONNTRACK_MAX_ENTRIES: u32 = 65_536;
pub const POLICY_MAX_ENTRIES: u32 = 16_384;
pub const META_MAX_ENTRIES: u32 = 1;
