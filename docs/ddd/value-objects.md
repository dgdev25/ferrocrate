# FerroCrate Value Objects

> Immutable, self-validating domain primitives with no identity. Implemented as Rust newtypes for type safety.

## Design Philosophy

Value objects in FerroCrate follow these Rust-centric principles:

1. **Newtype Pattern**: All value objects wrap primitive types in structs
2. **Immutability**: No `&mut self` methods; "mutations" return new instances
3. **Parse, Don't Validate**: Constructors return `Result<Self, Error>` enforcing validity
4. **Copy When Small**: Small value objects implement `Copy` for ergonomic use
5. **Eq/Hash**: All value objects implement equality and hashing

---

## Identity Value Objects

### ContainerId

```rust
/// Unique identifier for a container aggregate.
/// Generated as UUID v4 by default, or user-specified name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContainerId(IdInner);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum IdInner {
    Uuid(uuid::Uuid),
    Name(ContainerName),
}

impl ContainerId {
    /// Generate a new random UUID-based ID.
    pub fn new() -> Self {
        Self(IdInner::Uuid(uuid::Uuid::new_v4()))
    }

    /// Create from a user-specified name.
    pub fn from_name(name: impl Into<ContainerName>) -> Result<Self, InvalidNameError> {
        Ok(Self(IdInner::Name(name.into())))
    }

    /// Parse from string (accepts UUID or valid name).
    pub fn parse(s: &str) -> Result<Self, ParseIdError> {
        if let Ok(uuid) = uuid::Uuid::parse_str(s) {
            return Ok(Self(IdInner::Uuid(uuid)));
        }
        ContainerName::parse(s).map(|n| Self(IdInner::Name(n)))
    }

    /// Short display form (first 12 chars for UUID, full name for named).
    pub fn short(&self) -> String {
        match &self.0 {
            IdInner::Uuid(u) => u.to_string()[..12].to_string(),
            IdInner::Name(n) => n.to_string(),
        }
    }
}

impl Display for ContainerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            IdInner::Uuid(u) => write!(f, "{}", u),
            IdInner::Name(n) => write!(f, "{}", n),
        }
    }
}

impl FromStr for ContainerId {
    type Err = ParseIdError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}
```

### ImageId / ImageDigest

```rust
/// Content-addressable image identifier.
/// Always SHA-256 digest of the OCI manifest.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ImageId(ImageDigest);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ImageDigest(String);

impl ImageDigest {
    /// SHA-256 digest prefix.
    const PREFIX: &'static str = "sha256:";

    /// Create from raw bytes, computing digest.
    pub fn from_bytes(data: &[u8]) -> Self {
        use sha2::{Sha256, Digest};
        let hash = Sha256::digest(data);
        Self(format!("{}{:x}", Self::PREFIX, hash))
    }

    /// Parse from string (must be sha256: followed by 64 hex chars).
    pub fn parse(s: &str) -> Result<Self, InvalidDigestError> {
        if !s.starts_with(Self::PREFIX) {
            return Err(InvalidDigestError::MissingPrefix);
        }
        let hex = &s[Self::PREFIX.len()..];
        if hex.len() != 64 {
            return Err(InvalidDigestError::InvalidLength { expected: 64, got: hex.len() });
        }
        if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(InvalidDigestError::InvalidHex);
        }
        Ok(Self(s.to_lowercase()))
    }

    /// Get the hex portion (without sha256: prefix).
    pub fn hex(&self) -> &str {
        &self.0[Self::PREFIX.len()..]
    }
}

impl Display for ImageDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// Small value object - Copy is appropriate
impl Copy for ImageDigest {}
```

### LayerHash

```rust
/// Blake3 hash for content-addressable layer storage.
/// 256-bit hash stored as 64 hex characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LayerHash([u8; 32]);

impl LayerHash {
    /// Compute hash from data.
    pub fn from_bytes(data: &[u8]) -> Self {
        use blake3::Hasher;
        let mut hasher = Hasher::new();
        hasher.update(data);
        let hash = hasher.finalize();
        Self(*hash.as_bytes())
    }

    /// Parse from hex string.
    pub fn from_hex(hex: &str) -> Result<Self, ParseHashError> {
        if hex.len() != 64 {
            return Err(ParseHashError::InvalidLength);
        }
        let mut bytes = [0u8; 32];
        for i in 0..32 {
            bytes[i] = u8::from_str_radix(&hex[i*2..i*2+2], 16)
                .map_err(|_| ParseHashError::InvalidHex)?;
        }
        Ok(Self(bytes))
    }

    /// Convert to hex string.
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

impl Display for LayerHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}
```

---

## Network Value Objects

### PortMapping

```rust
/// Host-to-container port mapping.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PortMapping {
    pub host_ip: IpAddr,
    pub host_port: u16,
    pub container_port: u16,
    pub protocol: Protocol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
    Sctp,
}

impl PortMapping {
    pub fn new(host_port: u16, container_port: u16, protocol: Protocol) -> Self {
        Self {
            host_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            host_port,
            container_port,
            protocol,
        }
    }

    pub fn with_host_ip(mut self, ip: impl Into<IpAddr>) -> Self {
        self.host_ip = ip.into();
        self
    }

    /// Parse from Docker-compatible string format: "80:8080/tcp" or "127.0.0.1:80:8080/tcp"
    pub fn parse(s: &str) -> Result<Self, ParsePortError> {
        // Implementation handles all Docker port formats
        // ...
    }
}

impl Display for PortMapping {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}->{}/{}",
            self.host_ip, self.host_port, self.container_port,
            self.protocol.to_lowercase()
        )
    }
}
```

### IpCidr

```rust
/// IP address with CIDR notation subnet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IpCidr {
    address: IpAddr,
    prefix_len: u8,
}

impl IpCidr {
    pub fn new(address: IpAddr, prefix_len: u8) -> Result<Self, InvalidCidrError> {
        let max_prefix = match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > max_prefix {
            return Err(InvalidCidrError::PrefixTooLong { max: max_prefix, got: prefix_len });
        }
        Ok(Self { address, prefix_len })
    }

    pub fn network_address(&self) -> IpAddr {
        // Compute network address
    }

    pub fn broadcast_address(&self) -> Option<IpAddr> {
        // IPv4 only
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        // Check if IP is within subnet
    }

    /// Iterate over usable host addresses (excludes network and broadcast for IPv4)
    pub fn iter(&self) -> impl Iterator<Item = IpAddr> {
        // ...
    }
}

impl FromStr for IpCidr {
    type Err = InvalidCidrError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<_> = s.split('/').collect();
        if parts.len() != 2 {
            return Err(InvalidCidrError::InvalidFormat);
        }
        let address: IpAddr = parts[0].parse()?;
        let prefix_len: u8 = parts[1].parse()?;
        Self::new(address, prefix_len)
    }
}
```

---

## Resource Value Objects

### ResourceLimits

```rust
/// Container resource constraints enforced via cgroups v2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ResourceLimits {
    /// Maximum memory in bytes (memory.max in cgroup).
    pub memory: Option<Bytes>,

    /// CPU quota in microseconds per period (cpu.max).
    pub cpu_quota: Option<CpuQuota>,

    /// Maximum number of PIDs (pids.max).
    pub pids: Option<PidLimit>,

    /// IO read bandwidth limit (io.max).
    pub io_read_bps: Option<BytesPerSec>,

    /// IO write bandwidth limit (io.max).
    pub io_write_bps: Option<BytesPerSec>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bytes(u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpuQuota {
    /// Microseconds of CPU time per period.
    pub quota_us: u64,
    /// Period length in microseconds (default 100000 = 100ms).
    pub period_us: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PidLimit(u32);

impl ResourceLimits {
    pub fn builder() -> ResourceLimitsBuilder {
        ResourceLimitsBuilder::default()
    }

    /// Validate limits are within host capabilities.
    pub fn validate(&self, host: &HostResources) -> Result<(), ResourceError> {
        if let Some(mem) = self.memory {
            if mem.0 > host.total_memory {
                return Err(ResourceError::MemoryExceedsHost);
            }
        }
        Ok(())
    }

    /// Convert to cgroup v2 configuration.
    pub fn to_cgroup_config(&self) -> CgroupConfig {
        CgroupConfig {
            memory_max: self.memory.map(|b| b.0),
            cpu_max: self.cpu_quota.map(|q| format!("{} {}", q.quota_us, q.period_us)),
            pids_max: self.pids.map(|p| p.0 as i64),
            // ...
        }
    }
}

// Builder pattern for ergonomic construction
pub struct ResourceLimitsBuilder {
    memory: Option<Bytes>,
    cpu_quota: Option<CpuQuota>,
    pids: Option<PidLimit>,
    // ...
}

impl ResourceLimitsBuilder {
    pub fn memory(mut self, bytes: impl Into<Bytes>) -> Self {
        self.memory = Some(bytes.into());
        self
    }

    pub fn cpu_shares(mut self, shares: f64) -> Self {
        // Convert shares (1.0 = 100% of one CPU) to quota
        self.cpu_quota = Some(CpuQuota {
            quota_us: (shares * 100000.0) as u64,
            period_us: 100000,
        });
        self
    }

    pub fn build(self) -> Result<ResourceLimits, ResourceError> {
        Ok(ResourceLimits {
            memory: self.memory,
            cpu_quota: self.cpu_quota,
            pids: self.pids,
            // ...
        })
    }
}

// Ergonomic Bytes construction
impl Bytes {
    pub const fn kb(n: u64) -> Self { Self(n * 1024) }
    pub const fn mb(n: u64) -> Self { Self(n * 1024 * 1024) }
    pub const fn gb(n: u64) -> Self { Self(n * 1024 * 1024 * 1024) }
}

impl From<u64> for Bytes {
    fn from(n: u64) -> Self { Self(n) }
}

impl Display for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 >= 1024 * 1024 * 1024 {
            write!(f, "{}GB", self.0 / (1024 * 1024 * 1024))
        } else if self.0 >= 1024 * 1024 {
            write!(f, "{}MB", self.0 / (1024 * 1024))
        } else if self.0 >= 1024 {
            write!(f, "{}KB", self.0 / 1024)
        } else {
            write!(f, "{}B", self.0)
        }
    }
}
```

---

## Security Value Objects

### SecurityContext

```rust
/// Linux security configuration for a container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityContext {
    /// Run as this user (UID:GID).
    pub user: Option<UserId>,

    /// Capabilities to retain (all dropped by default).
    pub capabilities: Capabilities,

    /// Seccomp profile for syscall filtering.
    pub seccomp_profile: Option<SeccompProfile>,

    /// AppArmor profile name.
    pub apparmor_profile: Option<String>,

    /// Prevent privilege escalation via setuid/setgid.
    pub no_new_privileges: bool,

    /// Run container in user namespace (rootless).
    pub user_namespace: UserNamespace,

    /// Mount the root filesystem as read-only.
    pub read_only_rootfs: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    /// Capabilities to add (beyond default empty set).
    pub add: HashSet<Capability>,
    /// Capabilities to drop (from added set).
    pub drop: HashSet<Capability>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Capability {
    NetRaw,
    SysAdmin,
    SysChroot,
    Kill,
    // ... all Linux capabilities
}

impl SecurityContext {
    /// Default security context: rootless, all capabilities dropped.
    pub fn default_secure() -> Self {
        Self {
            user: None,
            capabilities: Capabilities::empty(),
            seccomp_profile: Some(SeccompProfile::default()),
            apparmor_profile: None,
            no_new_privileges: true,
            user_namespace: UserNamespace::Private,
            read_only_rootfs: false,
        }
    }

    /// Development profile: more permissive for debugging.
    pub fn development() -> Self {
        Self {
            user: None,
            capabilities: Capabilities::common(),
            seccomp_profile: None,
            apparmor_profile: None,
            no_new_privileges: false,
            user_namespace: UserNamespace::Host,
            read_only_rootfs: false,
        }
    }

    /// Convert to OCI runtime spec.
    pub fn to_oci(&self) -> oci::Linux {
        oci::Linux {
            uid_mappings: self.user_namespace.mappings(),
            gid_mappings: self.user_namespace.mappings(),
            // ...
        }
    }
}
```

### SeccompProfile

```regex
/// Seccomp (secure computing mode) profile for syscall filtering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeccompProfile {
    /// Default action for unmatched syscalls.
    pub default_action: SeccompAction,

    /// Architecture-specific rules.
    pub architectures: Vec<SeccompArch>,

    /// Syscall-specific rules.
    pub syscalls: Vec<SyscallRule>,

    /// Flags for seccomp(2).
    pub flags: SeccompFlags,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SeccompAction {
    KillProcess,
    KillThread,
    Trap,
    Errno(u32),
    Trace(u32),
    Log,
    Allow,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyscallRule {
    pub names: Vec<String>,
    pub action: SeccompAction,
    pub args: Vec<SeccompArg>,
}

impl SeccompProfile {
    /// Default profile blocking dangerous syscalls.
    pub fn default() -> Self {
        Self {
            default_action: SeccompAction::Errno(1), // EPERM
            architectures: vec![SeccompArch::X86_64, SeccompArch::Aarch64],
            syscalls: Self::allowed_syscalls(),
            flags: SeccompFlags::empty(),
        }
    }

    fn allowed_syscalls() -> Vec<SyscallRule> {
        // Default allowlist for common container operations
        vec![
            SyscallRule::allow(&["read", "write", "open", "close", "stat", "fstat", "lstat"]),
            SyscallRule::allow(&["mmap", "mprotect", "munmap", "brk"]),
            // ... many more
        ]
    }
}
```

---

## Intelligence Layer Value Objects

### Prediction

```rust
/// AI-generated resource prediction with confidence score.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Prediction {
    /// Predicted resource needs.
    pub resources: PredictedResources,

    /// Confidence level (0.0 - 1.0).
    pub confidence: f32,

    /// Reasoning for the prediction.
    pub reasoning: String,

    /// Source of the prediction.
    pub source: PredictionSource,

    /// Timestamp of prediction.
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PredictedResources {
    pub memory: Range<Bytes>,
    pub cpu: Range<f32>,
    pub recommended_limits: ResourceLimits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PredictionSource {
    /// WASM neural inference (<1ms).
    WasmInference,
    /// Local LLM inference (10-100ms).
    LocalLlm,
    /// Cloud API call (1-5s).
    CloudApi,
    /// Historical average.
    Historical,
}

impl Prediction {
    /// Create a low-confidence prediction from simple heuristics.
    pub fn heuristic(resources: PredictedResources) -> Self {
        Self {
            resources,
            confidence: 0.3,
            reasoning: "Based on simple heuristics".to_string(),
            source: PredictionSource::Historical,
            timestamp: Timestamp::now(),
        }
    }

    /// Check if prediction is actionable (high enough confidence).
    pub fn is_actionable(&self) -> bool {
        self.confidence >= 0.7
    }
}
```

### Anomaly

```rust
/// Detected container anomaly with remediation suggestion.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Anomaly {
    /// Anomaly identifier.
    pub id: AnomalyId,

    /// Container that exhibited the anomaly.
    pub container_id: ContainerId,

    /// Type of anomaly detected.
    pub anomaly_type: AnomalyType,

    /// Severity level.
    pub severity: Severity,

    /// Human-readable description.
    pub description: String,

    /// Observed metrics that triggered detection.
    pub evidence: HashMap<String, f64>,

    /// Suggested remediation actions.
    pub remediation: Vec<Remediation>,

    /// Timestamp of detection.
    pub detected_at: Timestamp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnomalyType {
    MemoryLeak,
    CpuSpike,
    NetworkAnomaly,
    DiskIOIssue,
    UnexpectedProcess,
    ResourceExhaustion,
    SecurityViolation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Warning,
    Critical,
    Emergency,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Remediation {
    pub action: RemediationAction,
    pub description: String,
    pub automatic: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RemediationAction {
    RestartContainer,
    ScaleOut { replicas: u32 },
    IncreaseMemory { bytes: Bytes },
    KillProcess { pid: Pid },
    Alert { channel: String },
}
```

---

## Value Object Summary

| Value Object | Rust Type | Copy | Key Validation |
|--------------|-----------|------|----------------|
| ContainerId | `enum { Uuid, Name }` | No | Valid UUID or name format |
| ImageDigest | `struct(String)` | Yes | `sha256:` + 64 hex chars |
| LayerHash | `struct([u8; 32])` | Yes | Blake3 256-bit |
| PortMapping | `struct { host, container, protocol }` | No | Port 1-65535 |
| IpCidr | `struct { addr, prefix }` | Yes | Valid prefix for IP version |
| Bytes | `struct(u64)` | Yes | Non-negative |
| ResourceLimits | `struct { memory, cpu, ... }` | No | Within host limits |
| SecurityContext | `struct { user, caps, ... }` | No | Valid capability names |
| Prediction | `struct { resources, confidence, ... }` | No | Confidence 0-1 |
| Anomaly | `struct { type, severity, ... }` | No | Valid enum values |

All value objects implement:
- `Debug`, `Clone`, `PartialEq`, `Eq`
- `Serialize`, `Deserialize` (via serde)
- `Display` for human-readable output
- `FromStr` for parsing from strings
- Validation in constructor returning `Result`
