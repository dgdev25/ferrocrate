use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::fd::{AsRawFd, OwnedFd},
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};

use aya::{
    maps::{Array, HashMap, Map, MapError, PerCpuArray},
    programs::{tc, ProgramError, SchedClassifier, TcAttachType},
    Ebpf, EbpfLoader,
};
use nix::{
    errno::Errno,
    fcntl::{open, openat, AtFlags, OFlag},
    sys::stat::{fchmod, fstat, fstatat, mkdirat, Mode},
    unistd::{fchown, unlinkat, Gid, Uid, UnlinkatFlags},
};

use crate::{
    ebpf::EbpfError,
    ebpf_abi::{
        EndpointKey, EndpointValue, MetaConfig, PolicyKey, PolicyValue, PortKey, PortValue,
        COUNTERS_MAP_NAME, COUNTER_MAX_ENTRIES, ENDPOINTS_MAP_NAME, META_MAP_NAME, META_VALUE_LEN,
        POLICY_MAP_NAME, PORTS_MAP_NAME, PROGRAM_ABI_VERSION,
    },
    ebpf_maps::expected_map_metadata,
};

const BPFFS_ROOT: &str = "/sys/fs/bpf";
const RESERVED_PORTS_PATH: &str = "/proc/sys/net/ipv4/ip_local_reserved_ports";
const FERROCRATE_DIR: &str = "ferrocrate";
const MAPS_DIR: &str = "maps";
const PROGRAMS_DIR: &str = "programs";
const INGRESS_PROGRAM: &str = "ferro_ingress";
const EGRESS_PROGRAM: &str = "ferro_egress";
const ABI_SYMBOL_SUFFIX: &str = "ABI_VERSION";
const OWNED_DIRECTORY_MODE: u32 = 0o700;
const MAP_DEFINITION_SIZE: usize = 28;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MapKind {
    Hash,
    Array,
    PerCpuArray,
    LruHash,
}

impl MapKind {
    fn from_elf(value: u32) -> Result<Self, EbpfError> {
        match value {
            1 => Ok(Self::Hash),
            2 => Ok(Self::Array),
            6 => Ok(Self::PerCpuArray),
            9 => Ok(Self::LruHash),
            other => Err(schema_error("map type", "known BPF map type", other)),
        }
    }

    fn from_aya(value: aya::maps::MapType) -> Result<Self, EbpfError> {
        use aya::maps::MapType;
        match value {
            MapType::Hash => Ok(Self::Hash),
            MapType::Array => Ok(Self::Array),
            MapType::PerCpuArray => Ok(Self::PerCpuArray),
            MapType::LruHash => Ok(Self::LruHash),
            other => Err(schema_error(
                "map type",
                "supported ferro map type",
                format!("{other:?}"),
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MapMetadata {
    pub(crate) name: String,
    pub(crate) kind: MapKind,
    pub(crate) key_size: u32,
    pub(crate) value_size: u32,
    pub(crate) max_entries: u32,
    pub(crate) map_flags: u32,
    pub(crate) pinning: u32,
    pub(crate) map_id: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ObjectMetadata {
    pub(crate) program_abi: u32,
    pub(crate) classifiers: Vec<String>,
    pub(crate) maps: Vec<MapMetadata>,
}

pub(crate) struct KernelPreflight<'a> {
    pub(crate) object: &'a [u8],
    pub(crate) expected_object_sha256: [u8; 32],
    pub(crate) network_id: &'a str,
    pub(crate) interface: &'a str,
    pub(crate) external_ifindex: u32,
}

pub(crate) struct KernelLoadPlan<'a> {
    pub(crate) network_id: &'a str,
    pub(crate) interface: &'a str,
    pub(crate) metadata: [u8; META_VALUE_LEN],
}

pub(crate) trait KernelAdapter {
    fn reserved_ports(&mut self) -> Result<String, EbpfError>;
    fn preflight(&mut self, request: &KernelPreflight<'_>) -> Result<(), EbpfError>;
    fn commit(&mut self, plan: &KernelLoadPlan<'_>) -> Result<(), EbpfError>;
    fn rollback(&mut self) -> Result<(), EbpfError>;
    fn detach(&mut self) -> Result<(), EbpfError>;
    fn install_endpoint(&mut self, key: EndpointKey, value: EndpointValue)
        -> Result<(), EbpfError>;
    fn remove_endpoint(&mut self, key: EndpointKey) -> Result<(), EbpfError>;
    fn set_policy(&mut self, key: PolicyKey, value: PolicyValue) -> Result<(), EbpfError>;
    fn install_port(&mut self, key: PortKey, value: PortValue) -> Result<(), EbpfError>;
    fn remove_port(&mut self, key: PortKey) -> Result<(), EbpfError>;
    fn counters(&mut self) -> Result<[u64; COUNTER_MAX_ENTRIES as usize], EbpfError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdapterState {
    New,
    Preflighted,
    Committed,
    Detached,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidatedRequest {
    network_id: String,
    interface: String,
    external_ifindex: u32,
}

pub(crate) struct AyaKernel {
    bpf: Option<Ebpf>,
    request: Option<ValidatedRequest>,
    layout: Option<PinLayout>,
    ingress_link: Option<tc::SchedClassifierLinkId>,
    egress_link: Option<tc::SchedClassifierLinkId>,
    state: AdapterState,
}

impl Default for AyaKernel {
    fn default() -> Self {
        Self {
            bpf: None,
            request: None,
            layout: None,
            ingress_link: None,
            egress_link: None,
            state: AdapterState::New,
        }
    }
}

impl AyaKernel {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    fn require_state(&self, expected: AdapterState, operation: &str) -> Result<(), EbpfError> {
        if self.state == expected {
            Ok(())
        } else {
            Err(EbpfError::InvalidAdapterState {
                reason: format!("{operation} requires {expected:?}, found {:?}", self.state),
            })
        }
    }

    fn bpf_mut(&mut self) -> Result<&mut Ebpf, EbpfError> {
        self.bpf
            .as_mut()
            .ok_or_else(|| EbpfError::InvalidAdapterState {
                reason: "Aya object is not loaded".to_string(),
            })
    }

    fn ensure_committed(&self) -> Result<(), EbpfError> {
        self.require_state(AdapterState::Committed, "map operation")
    }

    fn cleanup(&mut self) -> Result<(), EbpfError> {
        if self.state == AdapterState::Detached {
            return Ok(());
        }

        let mut failures = Vec::new();
        if let Some(link_id) = self.egress_link.take() {
            if let Err(error) = detach_classifier(self.bpf.as_mut(), EGRESS_PROGRAM, link_id) {
                failures.push(error.to_string());
            }
        }
        if let Some(link_id) = self.ingress_link.take() {
            if let Err(error) = detach_classifier(self.bpf.as_mut(), INGRESS_PROGRAM, link_id) {
                failures.push(error.to_string());
            }
        }

        self.bpf.take();
        if let Some(layout) = self.layout.as_mut() {
            if let Err(error) = layout.cleanup() {
                failures.push(error.to_string());
            }
        }

        if failures.is_empty() {
            self.layout = None;
            self.request = None;
            self.state = AdapterState::Detached;
            Ok(())
        } else {
            Err(EbpfError::Detach {
                reason: failures.join("; "),
            })
        }
    }

    fn insert_hash<const K: usize, const V: usize>(
        &mut self,
        map_name: &'static str,
        key: [u8; K],
        value: [u8; V],
    ) -> Result<(), EbpfError> {
        self.ensure_committed()?;
        let map = self
            .bpf_mut()?
            .map_mut(map_name)
            .ok_or_else(|| missing_map(map_name))?;
        let mut map = HashMap::<_, [u8; K], [u8; V]>::try_from(map)
            .map_err(|error| map_operation(map_name, "open", error))?;
        map.insert(key, value, 0)
            .map_err(|error| map_operation(map_name, "insert", error))
    }

    fn remove_hash<const K: usize, const V: usize>(
        &mut self,
        map_name: &'static str,
        key: [u8; K],
    ) -> Result<(), EbpfError> {
        self.ensure_committed()?;
        let map = self
            .bpf_mut()?
            .map_mut(map_name)
            .ok_or_else(|| missing_map(map_name))?;
        let mut map = HashMap::<_, [u8; K], [u8; V]>::try_from(map)
            .map_err(|error| map_operation(map_name, "open", error))?;
        match map.remove(&key) {
            Ok(()) | Err(MapError::KeyNotFound) => Ok(()),
            Err(error) => Err(map_operation(map_name, "remove", error)),
        }
    }
}

impl Drop for AyaKernel {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

impl KernelAdapter for AyaKernel {
    fn reserved_ports(&mut self) -> Result<String, EbpfError> {
        self.require_state(AdapterState::New, "reserved-port validation")?;
        fs::read_to_string(RESERVED_PORTS_PATH).map_err(|source| EbpfError::ReservedPortsRead {
            reason: source.to_string(),
        })
    }

    fn preflight(&mut self, request: &KernelPreflight<'_>) -> Result<(), EbpfError> {
        self.require_state(AdapterState::New, "preflight")?;

        let actual_hash = sha256(request.object);
        if actual_hash != request.expected_object_sha256 {
            return Err(EbpfError::ObjectHashMismatch {
                expected: request.expected_object_sha256,
                actual: actual_hash,
            });
        }
        let static_metadata = validate_embedded_object(request.object)?;
        validate_environment(
            request.interface,
            request.external_ifindex,
            request.network_id,
        )?;

        // Aya is invoked only after byte-level object and host preflight succeeds.
        let bpf = EbpfLoader::new()
            .load(request.object)
            .map_err(|error| loader_error("Aya object load", error))?;
        let actual_metadata = aya_object_metadata(&bpf, static_metadata.program_abi)?;
        validate_object_metadata(&actual_metadata)?;

        self.bpf = Some(bpf);
        self.request = Some(ValidatedRequest {
            network_id: request.network_id.to_string(),
            interface: request.interface.to_string(),
            external_ifindex: request.external_ifindex,
        });
        self.state = AdapterState::Preflighted;
        Ok(())
    }

    fn commit(&mut self, plan: &KernelLoadPlan<'_>) -> Result<(), EbpfError> {
        self.require_state(AdapterState::Preflighted, "commit")?;
        let request = self
            .request
            .as_ref()
            .ok_or_else(|| EbpfError::InvalidAdapterState {
                reason: "validated preflight request is missing".to_string(),
            })?;
        let metadata = MetaConfig::decode(plan.metadata);
        if request.network_id != plan.network_id
            || request.interface != plan.interface
            || request.external_ifindex != metadata.external_ifindex
            || metadata.abi_version != PROGRAM_ABI_VERSION
            || !metadata.snat_range_reserved()
            || metadata.snat_port_start > metadata.snat_port_end
        {
            return Err(EbpfError::InvalidAdapterState {
                reason:
                    "commit plan does not match validated request and reserved metadata contract"
                        .to_string(),
            });
        }

        let mut layout = PinLayout::create(plan.network_id)?;
        let result = (|| {
            let meta = self
                .bpf_mut()?
                .map_mut(META_MAP_NAME)
                .ok_or_else(|| missing_map(META_MAP_NAME))?;
            let mut meta = Array::<_, [u8; META_VALUE_LEN]>::try_from(meta)
                .map_err(|error| map_operation(META_MAP_NAME, "open", error))?;
            meta.set(0, plan.metadata, 0)
                .map_err(|error| map_operation(META_MAP_NAME, "initialize", error))?;

            layout.pin_maps(self.bpf_mut()?)?;
            layout.pin_programs(self.bpf_mut()?)?;

            match tc::qdisc_add_clsact(plan.interface) {
                Ok(()) => {}
                Err(error) if qdisc_already_exists(&error) => {}
                Err(error) => {
                    return Err(loader_error("add shared clsact qdisc", error));
                }
            }

            let ingress = attach_classifier(
                self.bpf_mut()?,
                INGRESS_PROGRAM,
                plan.interface,
                TcAttachType::Ingress,
            )?;
            self.ingress_link = Some(ingress);
            let egress = attach_classifier(
                self.bpf_mut()?,
                EGRESS_PROGRAM,
                plan.interface,
                TcAttachType::Egress,
            )?;
            self.egress_link = Some(egress);
            Ok(())
        })();

        self.layout = Some(layout);
        if let Err(error) = result {
            let rollback = self.cleanup();
            return match rollback {
                Ok(()) => Err(error),
                Err(rollback) => Err(EbpfError::Rollback {
                    primary: error.to_string(),
                    rollback: rollback.to_string(),
                }),
            };
        }

        self.state = AdapterState::Committed;
        Ok(())
    }

    fn rollback(&mut self) -> Result<(), EbpfError> {
        self.cleanup()
    }

    fn detach(&mut self) -> Result<(), EbpfError> {
        self.cleanup()
    }

    fn install_endpoint(
        &mut self,
        key: EndpointKey,
        value: EndpointValue,
    ) -> Result<(), EbpfError> {
        self.insert_hash(ENDPOINTS_MAP_NAME, key.encode(), value.encode())
    }

    fn remove_endpoint(&mut self, key: EndpointKey) -> Result<(), EbpfError> {
        self.remove_hash::<_, 12>(ENDPOINTS_MAP_NAME, key.encode())
    }

    fn set_policy(&mut self, key: PolicyKey, value: PolicyValue) -> Result<(), EbpfError> {
        self.insert_hash(POLICY_MAP_NAME, key.encode(), value.encode())
    }

    fn install_port(&mut self, key: PortKey, value: PortValue) -> Result<(), EbpfError> {
        self.insert_hash(PORTS_MAP_NAME, key.encode(), value.encode())
    }

    fn remove_port(&mut self, key: PortKey) -> Result<(), EbpfError> {
        self.remove_hash::<_, 8>(PORTS_MAP_NAME, key.encode())
    }

    fn counters(&mut self) -> Result<[u64; COUNTER_MAX_ENTRIES as usize], EbpfError> {
        self.ensure_committed()?;
        let map = self
            .bpf_mut()?
            .map_mut(COUNTERS_MAP_NAME)
            .ok_or_else(|| missing_map(COUNTERS_MAP_NAME))?;
        let map = PerCpuArray::<_, u64>::try_from(map)
            .map_err(|error| map_operation(COUNTERS_MAP_NAME, "open", error))?;
        let mut counters = [0; COUNTER_MAX_ENTRIES as usize];
        for index in 0..COUNTER_MAX_ENTRIES {
            counters[index as usize] = map
                .get(&index, 0)
                .map(|values| values.iter().copied().sum())
                .map_err(|error| map_operation(COUNTERS_MAP_NAME, "read", error))?;
        }
        Ok(counters)
    }
}

fn attach_classifier(
    bpf: &mut Ebpf,
    name: &'static str,
    interface: &str,
    attach_type: TcAttachType,
) -> Result<tc::SchedClassifierLinkId, EbpfError> {
    let program: &mut SchedClassifier = bpf
        .program_mut(name)
        .ok_or_else(|| missing_program(name))?
        .try_into()
        .map_err(|error: ProgramError| EbpfError::ProgramLoad {
            classifier: name.to_string(),
            reason: error.to_string(),
        })?;
    program
        .attach(interface, attach_type)
        .map_err(|error: ProgramError| EbpfError::Attach {
            classifier: name.to_string(),
            reason: error.to_string(),
        })
}

fn detach_classifier(
    bpf: Option<&mut Ebpf>,
    name: &'static str,
    link_id: tc::SchedClassifierLinkId,
) -> Result<(), EbpfError> {
    let Some(bpf) = bpf else {
        return Ok(());
    };
    let Some(program) = bpf.program_mut(name) else {
        return Ok(());
    };
    let program: &mut SchedClassifier = program.try_into().map_err(|error| EbpfError::Detach {
        reason: format!("open classifier {name} for detach: {error}"),
    })?;
    match program.detach(link_id) {
        Ok(()) => Ok(()),
        Err(error) if program_absent(&error) => Ok(()),
        Err(error) => Err(EbpfError::Detach {
            reason: format!("detach classifier {name}: {error}"),
        }),
    }
}

fn program_absent(error: &ProgramError) -> bool {
    matches!(error, ProgramError::NotAttached) || has_errno(error, 2)
}

fn qdisc_already_exists(error: &tc::TcError) -> bool {
    matches!(error, tc::TcError::AlreadyAttached) || has_errno(error, 17)
}

fn has_errno(error: &(dyn std::error::Error + 'static), errno: i32) -> bool {
    let mut current = Some(error);
    while let Some(source) = current {
        if source
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io_error| io_error.raw_os_error() == Some(errno))
        {
            return true;
        }
        current = source.source();
    }
    false
}

pub(crate) fn embedded_object() -> &'static [u8] {
    include_bytes!(env!("FERRO_NET_EBPF_OBJECT"))
}

fn aya_object_metadata(bpf: &Ebpf, program_abi: u32) -> Result<ObjectMetadata, EbpfError> {
    let mut maps = Vec::new();
    for (name, map) in bpf.maps() {
        let name = static_map_name(name)?;
        let data = match map {
            Map::Array(data)
            | Map::HashMap(data)
            | Map::LruHashMap(data)
            | Map::PerCpuArray(data) => data,
            _ => {
                return Err(EbpfError::UnexpectedMap {
                    map: name.to_string(),
                })
            }
        };
        let info = data
            .info()
            .map_err(|error| map_operation(name, "inspect", error))?;
        maps.push(MapMetadata {
            name: name.to_string(),
            kind: MapKind::from_aya(
                info.map_type()
                    .map_err(|error| map_operation(name, "inspect type", error))?,
            )?,
            key_size: info.key_size(),
            value_size: info.value_size(),
            max_entries: info.max_entries(),
            map_flags: info.map_flags(),
            pinning: 0,
            map_id: 0,
        });
    }
    maps.sort_by(|left, right| left.name.cmp(&right.name));

    let mut classifiers = Vec::new();
    for (name, program) in bpf.programs() {
        if matches!(program, aya::programs::Program::SchedClassifier(_)) {
            classifiers.push(name.to_string());
        }
    }
    classifiers.sort();
    Ok(ObjectMetadata {
        program_abi,
        classifiers,
        maps,
    })
}

pub(crate) fn validate_embedded_object(object: &[u8]) -> Result<ObjectMetadata, EbpfError> {
    let elf = ElfFile::parse(object)?;
    let symbols = elf.symbols()?;

    let abi_symbols: Vec<_> = symbols
        .iter()
        .filter(|symbol| {
            symbol.name.ends_with(ABI_SYMBOL_SUFFIX)
                && symbol.binding == 0
                && symbol.symbol_type == 1
        })
        .collect();
    if abi_symbols.len() != 1 {
        return Err(schema_error(
            ABI_SYMBOL_SUFFIX,
            "exactly one ABI symbol",
            abi_symbols.len(),
        ));
    }
    let abi_symbol = abi_symbols[0];
    if abi_symbol.size != 4 {
        return Err(schema_error(ABI_SYMBOL_SUFFIX, 4, abi_symbol.size));
    }
    let abi_section = elf.section(abi_symbol.section_index)?;
    if abi_section.name != format!(".rodata.{}", abi_symbol.name) {
        return Err(schema_error(
            ABI_SYMBOL_SUFFIX,
            format!(".rodata.{}", abi_symbol.name),
            &abi_section.name,
        ));
    }
    let program_abi = read_u32(elf.symbol_bytes(abi_symbol)?, 0)?;
    if program_abi != PROGRAM_ABI_VERSION {
        return Err(EbpfError::AbiMismatch {
            expected: PROGRAM_ABI_VERSION,
            actual: program_abi,
        });
    }

    let expected_programs = BTreeMap::from([
        (EGRESS_PROGRAM.to_string(), "classifier".to_string()),
        (INGRESS_PROGRAM.to_string(), "classifier".to_string()),
    ]);
    let programs: BTreeMap<_, _> = symbols
        .iter()
        .filter(|symbol| symbol.binding == 1 && symbol.symbol_type == 2)
        .filter(|symbol| {
            elf.section(symbol.section_index)
                .is_ok_and(|section| section.name != ".text")
        })
        .map(|symbol| {
            let section = elf.section(symbol.section_index)?;
            Ok((symbol.name.clone(), section.name.clone()))
        })
        .collect::<Result<_, EbpfError>>()?;
    if programs != expected_programs {
        return Err(schema_error(
            "classifiers",
            format!("{expected_programs:?}"),
            format!("{programs:?}"),
        ));
    }

    let mut maps = BTreeMap::new();
    let mut occupied = BTreeSet::new();
    let mut map_section_index = None;
    for symbol in symbols
        .iter()
        .filter(|symbol| symbol.binding == 1 && symbol.symbol_type == 1)
    {
        let section = elf.section(symbol.section_index)?;
        if section.name != "maps" && section.name != ".maps" {
            continue;
        }
        map_section_index = Some(symbol.section_index);
        if symbol.size as usize != MAP_DEFINITION_SIZE {
            return Err(schema_error(&symbol.name, MAP_DEFINITION_SIZE, symbol.size));
        }
        let start = symbol.value as usize;
        let end = start
            .checked_add(MAP_DEFINITION_SIZE)
            .ok_or_else(|| malformed_elf("map definition overflow"))?;
        for offset in start..end {
            if !occupied.insert(offset) {
                return Err(malformed_elf("overlapping map definitions"));
            }
        }
        let bytes = elf.symbol_bytes(symbol)?;
        maps.insert(
            symbol.name.clone(),
            MapMetadata {
                name: symbol.name.clone(),
                kind: MapKind::from_elf(read_u32(bytes, 0)?)?,
                key_size: read_u32(bytes, 4)?,
                value_size: read_u32(bytes, 8)?,
                max_entries: read_u32(bytes, 12)?,
                map_flags: read_u32(bytes, 16)?,
                pinning: read_u32(bytes, 20)?,
                map_id: read_u32(bytes, 24)?,
            },
        );
    }
    let map_section =
        elf.section(map_section_index.ok_or_else(|| malformed_elf("maps section missing"))?)?;
    if map_section.size as usize != maps.len() * MAP_DEFINITION_SIZE
        || occupied.len() != map_section.size as usize
    {
        return Err(schema_error(
            "maps section",
            maps.len() * MAP_DEFINITION_SIZE,
            map_section.size,
        ));
    }

    let metadata = ObjectMetadata {
        program_abi,
        classifiers: programs.keys().cloned().collect(),
        maps: maps.into_values().collect(),
    };
    validate_object_metadata(&metadata)?;
    Ok(metadata)
}

fn validate_object_metadata(actual: &ObjectMetadata) -> Result<(), EbpfError> {
    if actual.program_abi != PROGRAM_ABI_VERSION {
        return Err(EbpfError::AbiMismatch {
            expected: PROGRAM_ABI_VERSION,
            actual: actual.program_abi,
        });
    }
    let expected_programs = vec![EGRESS_PROGRAM.to_string(), INGRESS_PROGRAM.to_string()];
    if actual.classifiers != expected_programs {
        return Err(schema_error(
            "classifiers",
            format!("{expected_programs:?}"),
            format!("{:?}", actual.classifiers),
        ));
    }

    let expected: BTreeMap<_, _> = expected_map_metadata()
        .into_iter()
        .map(|metadata| (metadata.name.clone(), metadata))
        .collect();
    let actual_maps: BTreeMap<_, _> = actual
        .maps
        .iter()
        .map(|metadata| (metadata.name.clone(), metadata))
        .collect();
    if actual_maps.keys().ne(expected.keys()) {
        return Err(schema_error(
            "map names",
            format!("{:?}", expected.keys().collect::<Vec<_>>()),
            format!("{:?}", actual_maps.keys().collect::<Vec<_>>()),
        ));
    }
    for (name, expected_metadata) in expected {
        let actual_metadata = actual_maps[&name];
        if actual_metadata != &expected_metadata {
            return Err(schema_error(
                &name,
                format!("{expected_metadata:?}"),
                format!("{actual_metadata:?}"),
            ));
        }
    }
    Ok(())
}

#[derive(Debug)]
struct ElfSection {
    name: String,
    section_type: u32,
    offset: u64,
    size: u64,
    link: u32,
    entry_size: u64,
}

#[derive(Debug)]
struct ElfSymbol {
    name: String,
    binding: u8,
    symbol_type: u8,
    section_index: usize,
    value: u64,
    size: u64,
}

struct ElfFile<'a> {
    bytes: &'a [u8],
    sections: Vec<ElfSection>,
}

impl<'a> ElfFile<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self, EbpfError> {
        if bytes.len() < 64 || &bytes[..4] != b"\x7fELF" || bytes[4] != 2 || bytes[5] != 1 {
            return Err(malformed_elf("expected a little-endian ELF64 object"));
        }
        if read_u16(bytes, 16)? != 1 || read_u16(bytes, 18)? != 247 {
            return Err(malformed_elf("expected a relocatable BPF ELF object"));
        }
        let section_offset = read_u64(bytes, 40)? as usize;
        let section_entry_size = read_u16(bytes, 58)? as usize;
        let section_count = read_u16(bytes, 60)? as usize;
        let names_index = read_u16(bytes, 62)? as usize;
        if section_entry_size != 64 || section_count == 0 || names_index >= section_count {
            return Err(malformed_elf("invalid ELF section table"));
        }
        let table_end = section_entry_size
            .checked_mul(section_count)
            .and_then(|size| section_offset.checked_add(size))
            .ok_or_else(|| malformed_elf("ELF section table overflow"))?;
        if table_end > bytes.len() {
            return Err(malformed_elf("ELF section table is truncated"));
        }

        let mut raw = Vec::with_capacity(section_count);
        for index in 0..section_count {
            let header = section_offset + index * section_entry_size;
            raw.push((
                read_u32(bytes, header)? as usize,
                read_u32(bytes, header + 4)?,
                read_u64(bytes, header + 24)?,
                read_u64(bytes, header + 32)?,
                read_u32(bytes, header + 40)?,
                read_u64(bytes, header + 56)?,
            ));
        }
        let (_, _, names_offset, names_size, _, _) = raw[names_index];
        let names = checked_slice(bytes, names_offset as usize, names_size as usize)?;
        let sections: Vec<ElfSection> = raw
            .into_iter()
            .map(|(name, section_type, offset, size, link, entry_size)| {
                Ok(ElfSection {
                    name: c_string(names, name)?.to_string(),
                    section_type,
                    offset,
                    size,
                    link,
                    entry_size,
                })
            })
            .collect::<Result<_, EbpfError>>()?;
        for section in &sections {
            checked_slice(bytes, section.offset as usize, section.size as usize)?;
        }
        Ok(Self { bytes, sections })
    }

    fn section(&self, index: usize) -> Result<&ElfSection, EbpfError> {
        self.sections
            .get(index)
            .ok_or_else(|| malformed_elf("symbol section index is out of range"))
    }

    fn symbols(&self) -> Result<Vec<ElfSymbol>, EbpfError> {
        let symbol_sections: Vec<_> = self
            .sections
            .iter()
            .filter(|section| section.section_type == 2)
            .collect();
        if symbol_sections.len() != 1 {
            return Err(malformed_elf("expected exactly one ELF symbol table"));
        }
        let table = symbol_sections[0];
        if table.entry_size != 24 || table.size % table.entry_size != 0 {
            return Err(malformed_elf("invalid ELF64 symbol table"));
        }
        let strings = self.section(table.link as usize)?;
        if strings.section_type != 3 {
            return Err(malformed_elf(
                "symbol table does not reference a string table",
            ));
        }
        let names = checked_slice(self.bytes, strings.offset as usize, strings.size as usize)?;
        let table_bytes = checked_slice(self.bytes, table.offset as usize, table.size as usize)?;
        let mut symbols = Vec::new();
        for entry in table_bytes.chunks_exact(24).skip(1) {
            let name_offset = read_u32(entry, 0)? as usize;
            let info = entry[4];
            let section_index = read_u16(entry, 6)? as usize;
            if section_index == 0 {
                continue;
            }
            symbols.push(ElfSymbol {
                name: c_string(names, name_offset)?.to_string(),
                binding: info >> 4,
                symbol_type: info & 0x0f,
                section_index,
                value: read_u64(entry, 8)?,
                size: read_u64(entry, 16)?,
            });
        }
        Ok(symbols)
    }

    fn symbol_bytes(&self, symbol: &ElfSymbol) -> Result<&'a [u8], EbpfError> {
        let section = self.section(symbol.section_index)?;
        let offset = (section.offset as usize)
            .checked_add(symbol.value as usize)
            .ok_or_else(|| malformed_elf("symbol offset overflow"))?;
        checked_slice(self.bytes, offset, symbol.size as usize)
    }
}

fn checked_slice(bytes: &[u8], offset: usize, size: usize) -> Result<&[u8], EbpfError> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| malformed_elf("ELF range overflow"))?;
    bytes
        .get(offset..end)
        .ok_or_else(|| malformed_elf("ELF range is truncated"))
}

fn c_string(bytes: &[u8], offset: usize) -> Result<&str, EbpfError> {
    let suffix = bytes
        .get(offset..)
        .ok_or_else(|| malformed_elf("string offset out of range"))?;
    let end = suffix
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| malformed_elf("unterminated ELF string"))?;
    std::str::from_utf8(&suffix[..end]).map_err(|_| malformed_elf("ELF string is not UTF-8"))
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, EbpfError> {
    let value: [u8; 2] = checked_slice(bytes, offset, 2)?
        .try_into()
        .expect("checked length");
    Ok(u16::from_le_bytes(value))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, EbpfError> {
    let value: [u8; 4] = checked_slice(bytes, offset, 4)?
        .try_into()
        .expect("checked length");
    Ok(u32::from_le_bytes(value))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, EbpfError> {
    let value: [u8; 8] = checked_slice(bytes, offset, 8)?
        .try_into()
        .expect("checked length");
    Ok(u64::from_le_bytes(value))
}

fn malformed_elf(reason: impl Into<String>) -> EbpfError {
    EbpfError::ObjectFormat {
        reason: reason.into(),
    }
}

fn schema_error(name: &str, expected: impl ToString, actual: impl ToString) -> EbpfError {
    EbpfError::MapSchemaMismatch {
        map: name.to_string(),
        expected: expected.to_string(),
        actual: actual.to_string(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DirectoryPolicy {
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) mode: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct OwnedEntry {
    parent: Arc<OwnedFd>,
    name: String,
    identity: FileIdentity,
}

#[derive(Debug)]
struct OwnedDirectory {
    fd: Arc<OwnedFd>,
    created: Option<OwnedEntry>,
}

#[derive(Debug)]
struct PinLayout {
    _root: Arc<OwnedFd>,
    ferrocrate: OwnedDirectory,
    network: OwnedDirectory,
    maps: OwnedDirectory,
    programs: OwnedDirectory,
    pins: Vec<OwnedEntry>,
}

impl PinLayout {
    fn create(network_id: &str) -> Result<Self, EbpfError> {
        validate_component(network_id)?;
        let root = Arc::new(open_secure_directory(
            Path::new(BPFFS_ROOT),
            DirectoryPolicy {
                uid: 0,
                gid: 0,
                mode: 0,
            },
        )?);
        let policy = DirectoryPolicy {
            uid: 0,
            gid: 0,
            mode: OWNED_DIRECTORY_MODE,
        };
        let ferrocrate = open_or_create_directory(root.clone(), FERROCRATE_DIR, policy)?;
        if child_exists(&ferrocrate.fd, network_id)? {
            return Err(EbpfError::PinPathExists {
                path: format!("{BPFFS_ROOT}/{FERROCRATE_DIR}/{network_id}").into(),
            });
        }
        let network = create_directory(ferrocrate.fd.clone(), network_id, policy)?;
        let maps = match create_directory(network.fd.clone(), MAPS_DIR, policy) {
            Ok(value) => value,
            Err(error) => {
                let _ = remove_owned_directory(network.created.as_ref().expect("created network"));
                return Err(error);
            }
        };
        let programs = match create_directory(network.fd.clone(), PROGRAMS_DIR, policy) {
            Ok(value) => value,
            Err(error) => {
                let _ = remove_owned_directory(maps.created.as_ref().expect("created maps"));
                let _ = remove_owned_directory(network.created.as_ref().expect("created network"));
                return Err(error);
            }
        };
        Ok(Self {
            _root: root,
            ferrocrate,
            network,
            maps,
            programs,
            pins: Vec::new(),
        })
    }

    fn pin_maps(&mut self, bpf: &mut Ebpf) -> Result<(), EbpfError> {
        for expected in expected_map_metadata() {
            let name = static_map_name(&expected.name)?;
            let map = bpf.map_mut(name).ok_or_else(|| missing_map(name))?;
            let target = descriptor_path(&self.maps.fd, name);
            map.pin(&target)
                .map_err(|error| loader_error(&format!("pin map {name}"), error))?;
            self.pins
                .push(capture_owned_entry(self.maps.fd.clone(), name)?);
        }
        Ok(())
    }

    fn pin_programs(&mut self, bpf: &mut Ebpf) -> Result<(), EbpfError> {
        for name in [INGRESS_PROGRAM, EGRESS_PROGRAM] {
            let program: &mut SchedClassifier = bpf
                .program_mut(name)
                .ok_or_else(|| missing_program(name))?
                .try_into()
                .map_err(|error: ProgramError| EbpfError::ProgramLoad {
                    classifier: name.to_string(),
                    reason: error.to_string(),
                })?;
            program
                .load()
                .map_err(|error: ProgramError| EbpfError::ProgramLoad {
                    classifier: name.to_string(),
                    reason: error.to_string(),
                })?;
            let target = descriptor_path(&self.programs.fd, name);
            program
                .pin(&target)
                .map_err(|error| loader_error(&format!("pin program {name}"), error))?;
            self.pins
                .push(capture_owned_entry(self.programs.fd.clone(), name)?);
        }
        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), EbpfError> {
        let mut failures = Vec::new();
        while let Some(pin) = self.pins.pop() {
            if let Err(error) = remove_owned_file(&pin) {
                failures.push(error.to_string());
            }
        }
        for directory in [&self.programs, &self.maps, &self.network] {
            if let Some(entry) = &directory.created {
                if let Err(error) = remove_owned_directory(entry) {
                    failures.push(error.to_string());
                }
            }
        }
        if failures.is_empty() {
            if let Some(entry) = &self.ferrocrate.created {
                match remove_owned_directory(entry) {
                    Ok(()) => {}
                    Err(EbpfError::DirectoryNotEmpty { .. }) => {}
                    Err(error) => failures.push(error.to_string()),
                }
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(EbpfError::Detach {
                reason: failures.join("; "),
            })
        }
    }
}

pub(crate) fn open_secure_directory(
    path: &Path,
    policy: DirectoryPolicy,
) -> Result<OwnedFd, EbpfError> {
    let fd = open(
        path,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| directory_policy(path.display(), error))?;
    verify_directory(&fd, path.display().to_string(), policy, policy.mode == 0)?;
    Ok(fd)
}

pub(crate) fn open_secure_child(
    parent: &OwnedFd,
    name: &str,
    policy: DirectoryPolicy,
) -> Result<OwnedFd, EbpfError> {
    validate_component(name)?;
    let fd = openat(
        parent,
        name,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| directory_policy(name, error))?;
    verify_directory(&fd, name.to_string(), policy, false)?;
    Ok(fd)
}

fn open_or_create_directory(
    parent: Arc<OwnedFd>,
    name: &str,
    policy: DirectoryPolicy,
) -> Result<OwnedDirectory, EbpfError> {
    match open_secure_child(parent.as_ref(), name, policy) {
        Ok(fd) => Ok(OwnedDirectory {
            fd: Arc::new(fd),
            created: None,
        }),
        Err(EbpfError::DirectoryPolicy { reason, .. }) if reason.contains("ENOENT") => {
            create_directory(parent, name, policy)
        }
        Err(error) => Err(error),
    }
}

fn create_directory(
    parent: Arc<OwnedFd>,
    name: &str,
    policy: DirectoryPolicy,
) -> Result<OwnedDirectory, EbpfError> {
    validate_component(name)?;
    mkdirat(parent.as_ref(), name, Mode::from_bits_truncate(policy.mode))
        .map_err(|error| directory_policy(name, error))?;
    let created = capture_owned_entry(parent.clone(), name)?;
    let fd = match open_secure_child(
        parent.as_ref(),
        name,
        DirectoryPolicy {
            uid: policy.uid,
            gid: policy.gid,
            mode: 0,
        },
    ) {
        Ok(fd) => fd,
        Err(error) => {
            let _ = remove_owned_directory(&created);
            return Err(error);
        }
    };
    let opened = fstat(&fd).map_err(|error| directory_policy(name, error))?;
    if (FileIdentity {
        device: opened.st_dev,
        inode: opened.st_ino,
    }) != created.identity
    {
        return Err(EbpfError::OwnershipChanged {
            entry: name.to_string(),
        });
    }
    if let Err(error) = fchown(
        &fd,
        Some(Uid::from_raw(policy.uid)),
        Some(Gid::from_raw(policy.gid)),
    )
    .and_then(|_| fchmod(&fd, Mode::from_bits_truncate(policy.mode)))
    {
        drop(fd);
        let _ = remove_owned_directory(&created);
        return Err(directory_policy(name, error));
    }
    if let Err(error) = verify_directory(&fd, name.to_string(), policy, false) {
        drop(fd);
        let _ = remove_owned_directory(&created);
        return Err(error);
    }
    let fd = Arc::new(fd);
    Ok(OwnedDirectory {
        fd,
        created: Some(created),
    })
}

fn verify_directory(
    fd: &OwnedFd,
    display: String,
    policy: DirectoryPolicy,
    root_policy: bool,
) -> Result<(), EbpfError> {
    let stat = fstat(fd).map_err(|error| directory_policy(&display, error))?;
    if stat.st_uid != policy.uid || stat.st_gid != policy.gid {
        return Err(directory_policy(
            display,
            format!(
                "uid:gid {}:{} is not {}:{}",
                stat.st_uid, stat.st_gid, policy.uid, policy.gid
            ),
        ));
    }
    let mode = stat.st_mode & 0o7777;
    if (root_policy && mode & 0o022 != 0)
        || (!root_policy && policy.mode != 0 && mode != policy.mode)
    {
        return Err(directory_policy(
            display,
            format!("mode {mode:o} violates policy {:o}", policy.mode),
        ));
    }
    Ok(())
}

fn child_exists(parent: &Arc<OwnedFd>, name: &str) -> Result<bool, EbpfError> {
    validate_component(name)?;
    match fstatat(parent.as_ref(), name, AtFlags::AT_SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(true),
        Err(Errno::ENOENT) => Ok(false),
        Err(error) => Err(directory_policy(name, error)),
    }
}

pub(crate) fn capture_owned_entry(
    parent: Arc<OwnedFd>,
    name: &str,
) -> Result<OwnedEntry, EbpfError> {
    validate_component(name)?;
    let stat = fstatat(parent.as_ref(), name, AtFlags::AT_SYMLINK_NOFOLLOW)
        .map_err(|error| directory_policy(name, error))?;
    Ok(OwnedEntry {
        parent,
        name: name.to_string(),
        identity: FileIdentity {
            device: stat.st_dev,
            inode: stat.st_ino,
        },
    })
}

pub(crate) fn remove_owned_file(entry: &OwnedEntry) -> Result<(), EbpfError> {
    remove_owned(entry, UnlinkatFlags::NoRemoveDir)
}

fn remove_owned_directory(entry: &OwnedEntry) -> Result<(), EbpfError> {
    remove_owned(entry, UnlinkatFlags::RemoveDir)
}

fn remove_owned(entry: &OwnedEntry, flag: UnlinkatFlags) -> Result<(), EbpfError> {
    let stat = match fstatat(
        entry.parent.as_ref(),
        entry.name.as_str(),
        AtFlags::AT_SYMLINK_NOFOLLOW,
    ) {
        Ok(stat) => stat,
        Err(Errno::ENOENT) => return Ok(()),
        Err(error) => return Err(directory_policy(&entry.name, error)),
    };
    let current = FileIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
    };
    if current != entry.identity {
        return Err(EbpfError::OwnershipChanged {
            entry: entry.name.clone(),
        });
    }
    match unlinkat(entry.parent.as_ref(), entry.name.as_str(), flag) {
        Ok(()) | Err(Errno::ENOENT) => Ok(()),
        Err(Errno::ENOTEMPTY) | Err(Errno::EEXIST) => Err(EbpfError::DirectoryNotEmpty {
            path: entry.name.clone(),
        }),
        Err(error) => Err(directory_policy(&entry.name, error)),
    }
}

fn descriptor_path(parent: &Arc<OwnedFd>, name: &str) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}/{}", parent.as_raw_fd(), name))
}

fn validate_component(value: &str) -> Result<(), EbpfError> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || value.contains('/')
        || value.as_bytes().contains(&0)
    {
        return Err(EbpfError::InvalidPinPath { path: value.into() });
    }
    Ok(())
}

fn directory_policy(path: impl ToString, reason: impl ToString) -> EbpfError {
    EbpfError::DirectoryPolicy {
        path: path.to_string(),
        reason: reason.to_string(),
    }
}

fn validate_environment(
    interface: &str,
    external_ifindex: u32,
    network_id: &str,
) -> Result<(), EbpfError> {
    validate_component(network_id)?;
    validate_component(interface)?;
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")
        .map_err(|error| loader_error("read mountinfo", error))?;
    if !mountinfo
        .lines()
        .any(|line| line.contains(" /sys/fs/bpf ") && line.contains(" - bpf "))
    {
        return Err(EbpfError::BpffsUnavailable {
            reason: "bpffs is not mounted at /sys/fs/bpf".to_string(),
        });
    }
    let root = open_secure_directory(
        Path::new(BPFFS_ROOT),
        DirectoryPolicy {
            uid: 0,
            gid: 0,
            mode: 0,
        },
    )?;
    match open_secure_child(
        &root,
        FERROCRATE_DIR,
        DirectoryPolicy {
            uid: 0,
            gid: 0,
            mode: OWNED_DIRECTORY_MODE,
        },
    ) {
        Ok(ferrocrate) => {
            if child_exists(&Arc::new(ferrocrate), network_id)? {
                return Err(EbpfError::PinPathExists {
                    path: format!("{BPFFS_ROOT}/{FERROCRATE_DIR}/{network_id}").into(),
                });
            }
        }
        Err(EbpfError::DirectoryPolicy { reason, .. }) if reason.contains("ENOENT") => {}
        Err(error) => return Err(error),
    }

    let ifindex_path = Path::new("/sys/class/net").join(interface).join("ifindex");
    let actual_ifindex: u32 = fs::read_to_string(&ifindex_path)
        .map_err(|error| loader_error("read interface ifindex", error))?
        .trim()
        .parse()
        .map_err(|error| loader_error("parse interface ifindex", error))?;
    if actual_ifindex != external_ifindex {
        return Err(EbpfError::InterfaceMismatch {
            interface: interface.to_string(),
            expected: external_ifindex,
            actual: actual_ifindex,
        });
    }

    let tc = Command::new("tc")
        .arg("-V")
        .output()
        .map_err(|error| loader_error("execute tc -V", error))?;
    if !tc.status.success() {
        return Err(EbpfError::TcUnavailable {
            interface: interface.to_string(),
            reason: "tc -V failed".to_string(),
        });
    }
    let qdisc = Command::new("tc")
        .args(["qdisc", "show", "dev", interface])
        .output()
        .map_err(|error| EbpfError::TcUnavailable {
            interface: interface.to_string(),
            reason: error.to_string(),
        })?;
    if !qdisc.status.success() {
        return Err(EbpfError::TcUnavailable {
            interface: interface.to_string(),
            reason: String::from_utf8_lossy(&qdisc.stderr).trim().to_string(),
        });
    }
    let status =
        fs::read_to_string("/proc/self/status").map_err(|error| EbpfError::TcUnavailable {
            interface: interface.to_string(),
            reason: error.to_string(),
        })?;
    let effective = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:\t"))
        .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
        .unwrap_or_default();
    let cap_net_admin = effective & (1 << 12) != 0;
    let cap_sys_admin = effective & (1 << 21) != 0;
    let cap_bpf = effective & (1 << 39) != 0;
    if !cap_net_admin || (!cap_bpf && !cap_sys_admin) {
        return Err(EbpfError::TcUnavailable {
            interface: interface.to_string(),
            reason: "CAP_NET_ADMIN and CAP_BPF (or CAP_SYS_ADMIN) are required".to_string(),
        });
    }
    Ok(())
}

fn map_operation(map: &'static str, operation: &'static str, error: MapError) -> EbpfError {
    let capacity = match &error {
        MapError::SyscallError(syscall) => {
            matches!(syscall.io_error.raw_os_error(), Some(7 | 28))
        }
        _ => false,
    };
    if capacity {
        EbpfError::MapCapacity { map }
    } else {
        EbpfError::MapOperation {
            map,
            operation,
            reason: error.to_string(),
        }
    }
}

fn missing_map(name: &'static str) -> EbpfError {
    EbpfError::MissingMap { map: name }
}

fn missing_program(name: &'static str) -> EbpfError {
    EbpfError::MissingClassifier { classifier: name }
}

fn loader_error(operation: &str, error: impl std::fmt::Display) -> EbpfError {
    EbpfError::ObjectLoad {
        reason: format!("{operation}: {error}"),
    }
}

fn static_map_name(name: &str) -> Result<&'static str, EbpfError> {
    match name {
        crate::ebpf_abi::ENDPOINTS_MAP_NAME => Ok(crate::ebpf_abi::ENDPOINTS_MAP_NAME),
        crate::ebpf_abi::PORTS_MAP_NAME => Ok(crate::ebpf_abi::PORTS_MAP_NAME),
        crate::ebpf_abi::CONNTRACK_MAP_NAME => Ok(crate::ebpf_abi::CONNTRACK_MAP_NAME),
        crate::ebpf_abi::POLICY_MAP_NAME => Ok(crate::ebpf_abi::POLICY_MAP_NAME),
        crate::ebpf_abi::COUNTERS_MAP_NAME => Ok(crate::ebpf_abi::COUNTERS_MAP_NAME),
        crate::ebpf_abi::META_MAP_NAME => Ok(crate::ebpf_abi::META_MAP_NAME),
        other => Err(EbpfError::UnexpectedMap {
            map: other.to_string(),
        }),
    }
}
pub(crate) fn sha256(input: &[u8]) -> [u8; 32] {
    const INITIAL: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const ROUND: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let bit_length = (input.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity(input.len() + 72);
    padded.extend_from_slice(input);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_length.to_be_bytes());

    let mut state = INITIAL;
    for chunk in padded.chunks_exact(64) {
        let mut words = [0_u32; 64];
        for (index, word) in words.iter_mut().take(16).enumerate() {
            let offset = index * 4;
            *word = u32::from_be_bytes(chunk[offset..offset + 4].try_into().unwrap());
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ ((!e) & g);
            let temporary1 = h
                .wrapping_add(sum1)
                .wrapping_add(choice)
                .wrapping_add(ROUND[index])
                .wrapping_add(words[index]);
            let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temporary2 = sum0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temporary1);
            d = c;
            c = b;
            b = a;
            a = temporary1.wrapping_add(temporary2);
        }
        for (value, addition) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *value = value.wrapping_add(addition);
        }
    }

    let mut digest = [0; 32];
    for (index, value) in state.into_iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&value.to_be_bytes());
    }
    digest
}

#[cfg(test)]
mod review_tests {
    use std::{
        fs, io,
        os::unix::fs::{symlink, MetadataExt, PermissionsExt},
        sync::Arc,
    };

    use super::*;

    #[test]
    fn embedded_object_has_exact_static_abi_programs_and_maps() {
        let metadata = validate_embedded_object(embedded_object()).unwrap();
        assert_eq!(metadata.program_abi, PROGRAM_ABI_VERSION);
        assert_eq!(
            metadata.classifiers,
            vec![EGRESS_PROGRAM.to_string(), INGRESS_PROGRAM.to_string()]
        );

        let mut actual = metadata.maps;
        actual.sort_by(|left, right| left.name.cmp(&right.name));
        let mut expected = expected_map_metadata();
        expected.sort_by(|left, right| left.name.cmp(&right.name));
        assert_eq!(actual, expected);
    }

    #[test]
    fn altered_legacy_map_capacity_is_rejected_by_static_validation() {
        let mut object = embedded_object().to_vec();
        let max_entries_offset = {
            let elf = ElfFile::parse(&object).unwrap();
            let symbol = elf
                .symbols()
                .unwrap()
                .into_iter()
                .find(|symbol| symbol.name == crate::ebpf_abi::ENDPOINTS_MAP_NAME)
                .unwrap();
            elf.section(symbol.section_index).unwrap().offset as usize + symbol.value as usize + 12
        };
        object[max_entries_offset..max_entries_offset + 4]
            .copy_from_slice(&(crate::ebpf_abi::ENDPOINT_MAX_ENTRIES + 1).to_le_bytes());

        assert!(matches!(
            validate_embedded_object(&object),
            Err(EbpfError::MapSchemaMismatch { map, .. })
                if map == crate::ebpf_abi::ENDPOINTS_MAP_NAME
        ));
    }

    #[test]
    fn aya_capacity_errnos_are_classified_as_map_capacity() {
        for errno in [7, 28] {
            let error = MapError::SyscallError(aya::sys::SyscallError {
                call: "bpf_map_update_elem",
                io_error: io::Error::from_raw_os_error(errno),
            });
            assert!(matches!(
                map_operation(ENDPOINTS_MAP_NAME, "insert", error),
                EbpfError::MapCapacity {
                    map: ENDPOINTS_MAP_NAME
                }
            ));
        }
    }

    #[test]
    fn secure_directory_open_rejects_symlinks_and_insecure_modes() {
        let temporary = tempfile::tempdir().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let metadata = fs::metadata(temporary.path()).unwrap();
        let policy = DirectoryPolicy {
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: 0o700,
        };
        let root = open_secure_directory(temporary.path(), policy).unwrap();

        fs::create_dir(temporary.path().join("outside")).unwrap();
        symlink("outside", temporary.path().join("linked")).unwrap();
        assert!(matches!(
            open_secure_child(&root, "linked", policy),
            Err(EbpfError::DirectoryPolicy { .. })
        ));

        fs::create_dir(temporary.path().join("insecure")).unwrap();
        fs::set_permissions(
            temporary.path().join("insecure"),
            fs::Permissions::from_mode(0o777),
        )
        .unwrap();
        assert!(matches!(
            open_secure_child(&root, "insecure", policy),
            Err(EbpfError::DirectoryPolicy { .. })
        ));
    }

    #[test]
    fn cleanup_refuses_to_delete_a_replaced_pin() {
        let temporary = tempfile::tempdir().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let metadata = fs::metadata(temporary.path()).unwrap();
        let root = Arc::new(
            open_secure_directory(
                temporary.path(),
                DirectoryPolicy {
                    uid: metadata.uid(),
                    gid: metadata.gid(),
                    mode: 0o700,
                },
            )
            .unwrap(),
        );
        let pin = temporary.path().join("pin");
        fs::write(&pin, b"owned").unwrap();
        let owned = capture_owned_entry(root, "pin").unwrap();
        fs::remove_file(&pin).unwrap();
        fs::write(&pin, b"replacement").unwrap();

        assert!(matches!(
            remove_owned_file(&owned),
            Err(EbpfError::OwnershipChanged { .. })
        ));
        assert_eq!(fs::read(&pin).unwrap(), b"replacement");
    }
}
