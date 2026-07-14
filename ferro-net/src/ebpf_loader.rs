use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use aya::maps::{Array, HashMap as AyaHashMap, Map, MapData, MapError, PerCpuArray};
use aya::programs::{tc, Program, SchedClassifier, TcAttachType};
use aya::{Ebpf, EbpfLoader};

use crate::ebpf::{
    EbpfError, BPFFS_ROOT, EGRESS_CLASSIFIER, FERRO_NETWORK_ROOT, INGRESS_CLASSIFIER,
};
use crate::ebpf_abi::{
    CONNTRACK_MAP_NAME, COUNTERS_MAP_NAME, COUNTER_MAX_ENTRIES, ENDPOINTS_MAP_NAME,
    ENDPOINT_KEY_LEN, ENDPOINT_VALUE_LEN, META_MAP_NAME, META_VALUE_LEN, POLICY_KEY_LEN,
    POLICY_MAP_NAME, POLICY_VALUE_LEN, PORTS_MAP_NAME, PORT_KEY_LEN, PORT_VALUE_LEN,
};
use crate::ebpf_maps::expected_map_metadata;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapKind {
    Hash,
    LruHash,
    Array,
    PerCpuArray,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapMetadata {
    pub name: String,
    pub kind: MapKind,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectMetadata {
    pub program_abi: u32,
    pub maps: Vec<MapMetadata>,
    pub classifiers: Vec<String>,
}

#[derive(Debug)]
pub struct KernelPreflight<'a> {
    pub object: &'a [u8],
    pub interface: &'a str,
    pub external_ifindex: u32,
    pub pin_path: &'a Path,
}

#[derive(Debug)]
pub struct KernelLoadPlan<'a> {
    pub interface: &'a str,
    pub pin_path: &'a Path,
    pub metadata: [u8; META_VALUE_LEN],
}

pub trait KernelAdapter: Send {
    fn reserved_ports(&mut self) -> Result<String, EbpfError>;
    fn preflight(
        &mut self,
        request: &KernelPreflight<'_>,
    ) -> Result<ObjectMetadata, EbpfError>;
    fn commit(&mut self, plan: &KernelLoadPlan<'_>) -> Result<(), EbpfError>;
    fn map_insert(
        &mut self,
        map: &'static str,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), EbpfError>;
    fn map_remove(&mut self, map: &'static str, key: &[u8]) -> Result<(), EbpfError>;
    fn counters(&mut self) -> Result<[u64; COUNTER_MAX_ENTRIES as usize], EbpfError>;
    fn rollback(&mut self) -> Result<(), EbpfError>;
    fn detach(&mut self) -> Result<(), EbpfError>;
}

pub struct AyaKernel {
    bpf: Option<Ebpf>,
    interface: Option<String>,
    pin_files: Vec<PathBuf>,
    owned_directories: Vec<PathBuf>,
    network_pin_path: Option<PathBuf>,
    qdisc_owned: bool,
}

impl AyaKernel {
    pub fn new() -> Self {
        Self {
            bpf: None,
            interface: None,
            pin_files: Vec::new(),
            owned_directories: Vec::new(),
            network_pin_path: None,
            qdisc_owned: false,
        }
    }

    fn validate_environment(&self, request: &KernelPreflight<'_>) -> Result<(), EbpfError> {
        validate_bpffs_mount()?;
        validate_pin_path(request.pin_path)?;
        validate_interface(request.interface, request.external_ifindex)?;
        validate_tc(request.interface)
    }

    fn create_pin_layout(&mut self, pin_path: &Path) -> Result<(), EbpfError> {
        let ferro = Path::new(BPFFS_ROOT).join("ferro");
        let networks = ferro.join("networks");
        for (path, allow_existing) in [
            (ferro, true),
            (networks, true),
            (pin_path.to_path_buf(), false),
            (pin_path.join("maps"), false),
            (pin_path.join("programs"), false),
        ] {
            match fs::create_dir(&path) {
                Ok(()) => {
                    if path == pin_path {
                        self.network_pin_path = Some(path.clone());
                    }
                    self.owned_directories.push(path);
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists && allow_existing => {
                    let metadata = fs::symlink_metadata(&path).map_err(|source| EbpfError::Pin {
                        item: path.display().to_string(),
                        reason: source.to_string(),
                    })?;
                    if !metadata.is_dir() || metadata.file_type().is_symlink() {
                        return Err(EbpfError::InvalidPinPath { path });
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    return Err(EbpfError::PinPathExists { path });
                }
                Err(error) => {
                    return Err(EbpfError::Pin {
                        item: path.display().to_string(),
                        reason: error.to_string(),
                    });
                }
            }
        }
        Ok(())
    }

    fn initialize_metadata(&mut self, metadata: [u8; META_VALUE_LEN]) -> Result<(), EbpfError> {
        let map = self
            .bpf
            .as_mut()
            .and_then(|bpf| bpf.map_mut(META_MAP_NAME))
            .ok_or(EbpfError::MissingMap { map: META_MAP_NAME })?;
        let mut map = Array::<_, [u8; META_VALUE_LEN]>::try_from(map)
            .map_err(|error| map_operation("initialize", META_MAP_NAME, error))?;
        map.set(0, metadata, 0)
            .map_err(|error| map_operation("initialize", META_MAP_NAME, error))
    }

    fn pin_maps(&mut self, pin_path: &Path) -> Result<(), EbpfError> {
        for expected in expected_map_metadata() {
            let path = pin_path.join("maps").join(&expected.name);
            self.bpf
                .as_ref()
                .and_then(|bpf| bpf.map(&expected.name))
                .ok_or(EbpfError::MissingMap {
                    map: static_map_name(&expected.name),
                })?
                .pin(&path)
                .map_err(|error| EbpfError::Pin {
                    item: expected.name.clone(),
                    reason: error.to_string(),
                })?;
            self.pin_files.push(path);
        }
        Ok(())
    }

    fn load_and_pin_classifier(&mut self, name: &'static str, path: PathBuf) -> Result<(), EbpfError> {
        let program = self
            .bpf
            .as_mut()
            .and_then(|bpf| bpf.program_mut(name))
            .ok_or(EbpfError::MissingClassifier { classifier: name })?;
        let classifier: &mut SchedClassifier = program.try_into().map_err(|error: aya::programs::ProgramError| {
            EbpfError::ProgramLoad {
                classifier: name.to_string(),
                reason: error.to_string(),
            }
        })?;
        classifier.load().map_err(|error| EbpfError::ProgramLoad {
            classifier: name.to_string(),
            reason: error.to_string(),
        })?;
        program.pin(&path).map_err(|error| EbpfError::Pin {
            item: name.to_string(),
            reason: error.to_string(),
        })?;
        self.pin_files.push(path);
        Ok(())
    }

    fn attach_classifier(
        &mut self,
        name: &'static str,
        interface: &str,
        attach_type: TcAttachType,
    ) -> Result<(), EbpfError> {
        let program = self
            .bpf
            .as_mut()
            .and_then(|bpf| bpf.program_mut(name))
            .ok_or(EbpfError::MissingClassifier { classifier: name })?;
        let classifier: &mut SchedClassifier = program.try_into().map_err(|error: aya::programs::ProgramError| {
            EbpfError::ProgramLoad {
                classifier: name.to_string(),
                reason: error.to_string(),
            }
        })?;
        classifier
            .attach(interface, attach_type)
            .map(|_| ())
            .map_err(|error| EbpfError::Attach {
                classifier: name.to_string(),
                reason: error.to_string(),
            })
    }

    fn cleanup(&mut self) -> Result<(), EbpfError> {
        drop(self.bpf.take());
        let mut first_error = None;

        if self.qdisc_owned {
            if let Some(interface) = self.interface.as_deref() {
                match Command::new("tc")
                    .args(["qdisc", "del", "dev", interface, "clsact"])
                    .output()
                {
                    Ok(output) if output.status.success() => self.qdisc_owned = false,
                    Ok(output) => {
                        first_error = Some(EbpfError::Detach {
                            reason: String::from_utf8_lossy(&output.stderr).trim().to_string(),
                        });
                    }
                    Err(error) => {
                        first_error = Some(EbpfError::Detach {
                            reason: error.to_string(),
                        });
                    }
                }
            }
        }

        let mut remaining_files = Vec::new();
        for path in std::mem::take(&mut self.pin_files).into_iter().rev() {
            if let Err(error) = fs::remove_file(&path) {
                if error.kind() != io::ErrorKind::NotFound {
                    if first_error.is_none() {
                        first_error = Some(EbpfError::Detach {
                            reason: format!("could not remove {}: {error}", path.display()),
                        });
                    }
                    remaining_files.push(path);
                }
            }
        }
        remaining_files.reverse();
        self.pin_files = remaining_files;

        let mut remaining_directories = Vec::new();
        for path in std::mem::take(&mut self.owned_directories)
            .into_iter()
            .rev()
        {
            if let Err(error) = fs::remove_dir(&path) {
                if error.kind() == io::ErrorKind::DirectoryNotEmpty
                    && self
                        .network_pin_path
                        .as_deref()
                        .is_some_and(|network| path.starts_with(network))
                {
                    if first_error.is_none() {
                        first_error = Some(EbpfError::Detach {
                            reason: format!("owned path remains non-empty: {}", path.display()),
                        });
                    }
                    remaining_directories.push(path);
                } else if !matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::DirectoryNotEmpty
                ) {
                    if first_error.is_none() {
                        first_error = Some(EbpfError::Detach {
                            reason: format!("could not remove {}: {error}", path.display()),
                        });
                    }
                    remaining_directories.push(path);
                }
            }
        }
        remaining_directories.reverse();
        self.owned_directories = remaining_directories;
        if self.pin_files.is_empty()
            && self
                .owned_directories
                .iter()
                .all(|path| {
                    self.network_pin_path
                        .as_deref()
                        .is_none_or(|network| !path.starts_with(network))
                })
        {
            self.network_pin_path = None;
        }

        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn insert_hash<const K: usize, const V: usize>(
        &mut self,
        map_name: &'static str,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), EbpfError> {
        let key: [u8; K] = fixed_bytes(key, map_name, "insert key")?;
        let value: [u8; V] = fixed_bytes(value, map_name, "insert value")?;
        let map = self
            .bpf
            .as_mut()
            .and_then(|bpf| bpf.map_mut(map_name))
            .ok_or(EbpfError::MissingMap { map: map_name })?;
        let mut map = AyaHashMap::<_, [u8; K], [u8; V]>::try_from(map)
            .map_err(|error| map_operation("open", map_name, error))?;
        map.insert(key, value, 0)
            .map_err(|error| map_operation("insert into", map_name, error))
    }

    fn remove_hash<const K: usize, const V: usize>(
        &mut self,
        map_name: &'static str,
        key: &[u8],
    ) -> Result<(), EbpfError> {
        let key: [u8; K] = fixed_bytes(key, map_name, "remove key")?;
        let map = self
            .bpf
            .as_mut()
            .and_then(|bpf| bpf.map_mut(map_name))
            .ok_or(EbpfError::MissingMap { map: map_name })?;
        let mut map = AyaHashMap::<_, [u8; K], [u8; V]>::try_from(map)
            .map_err(|error| map_operation("open", map_name, error))?;
        match map.remove(&key) {
            Ok(()) => Ok(()),
            Err(error) if has_errno(&error, 2) => Ok(()),
            Err(error) => Err(map_operation("remove from", map_name, error)),
        }
    }
}

impl Default for AyaKernel {
    fn default() -> Self {
        Self::new()
    }
}

impl KernelAdapter for AyaKernel {
    fn reserved_ports(&mut self) -> Result<String, EbpfError> {
        fs::read_to_string("/proc/sys/net/ipv4/ip_local_reserved_ports").map_err(|error| {
            EbpfError::ReservedPortsRead {
                reason: error.to_string(),
            }
        })
    }

    fn preflight(
        &mut self,
        request: &KernelPreflight<'_>,
    ) -> Result<ObjectMetadata, EbpfError> {
        self.validate_environment(request)?;
        let program_abi = object_abi(request.object)?;
        let bpf = EbpfLoader::new()
            .load(request.object)
            .map_err(|error| EbpfError::ObjectLoad {
                reason: error.to_string(),
            })?;
        let metadata = aya_object_metadata(&bpf, program_abi)?;
        self.bpf = Some(bpf);
        self.interface = Some(request.interface.to_string());
        Ok(metadata)
    }

    fn commit(&mut self, plan: &KernelLoadPlan<'_>) -> Result<(), EbpfError> {
        self.create_pin_layout(plan.pin_path)?;
        self.initialize_metadata(plan.metadata)?;
        self.pin_maps(plan.pin_path)?;
        self.load_and_pin_classifier(
            INGRESS_CLASSIFIER,
            plan.pin_path.join("programs").join(INGRESS_CLASSIFIER),
        )?;
        self.load_and_pin_classifier(
            EGRESS_CLASSIFIER,
            plan.pin_path.join("programs").join(EGRESS_CLASSIFIER),
        )?;
        match tc::qdisc_add_clsact(plan.interface) {
            Ok(()) => self.qdisc_owned = true,
            Err(tc::TcError::AlreadyAttached) => self.qdisc_owned = false,
            Err(error) => {
                return Err(EbpfError::TcUnavailable {
                    interface: plan.interface.to_string(),
                    reason: error.to_string(),
                });
            }
        }
        self.attach_classifier(INGRESS_CLASSIFIER, plan.interface, TcAttachType::Ingress)?;
        self.attach_classifier(EGRESS_CLASSIFIER, plan.interface, TcAttachType::Egress)
    }

    fn map_insert(
        &mut self,
        map: &'static str,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), EbpfError> {
        match map {
            ENDPOINTS_MAP_NAME => {
                self.insert_hash::<ENDPOINT_KEY_LEN, ENDPOINT_VALUE_LEN>(map, key, value)
            }
            PORTS_MAP_NAME => self.insert_hash::<PORT_KEY_LEN, PORT_VALUE_LEN>(map, key, value),
            POLICY_MAP_NAME => {
                self.insert_hash::<POLICY_KEY_LEN, POLICY_VALUE_LEN>(map, key, value)
            }
            _ => Err(EbpfError::MapOperation {
                operation: "insert into",
                map,
                reason: "map is not mutable through the public API".to_string(),
            }),
        }
    }

    fn map_remove(&mut self, map: &'static str, key: &[u8]) -> Result<(), EbpfError> {
        match map {
            ENDPOINTS_MAP_NAME => {
                self.remove_hash::<ENDPOINT_KEY_LEN, ENDPOINT_VALUE_LEN>(map, key)
            }
            PORTS_MAP_NAME => self.remove_hash::<PORT_KEY_LEN, PORT_VALUE_LEN>(map, key),
            _ => Err(EbpfError::MapOperation {
                operation: "remove from",
                map,
                reason: "map is not removable through the public API".to_string(),
            }),
        }
    }

    fn counters(&mut self) -> Result<[u64; COUNTER_MAX_ENTRIES as usize], EbpfError> {
        let map = self
            .bpf
            .as_ref()
            .and_then(|bpf| bpf.map(COUNTERS_MAP_NAME))
            .ok_or(EbpfError::MissingMap {
                map: COUNTERS_MAP_NAME,
            })?;
        let map = PerCpuArray::<_, u64>::try_from(map).map_err(|error| EbpfError::Metrics {
            reason: error.to_string(),
        })?;
        let mut counters = [0; COUNTER_MAX_ENTRIES as usize];
        for (index, total) in counters.iter_mut().enumerate() {
            let values = map
                .get(&(index as u32), 0)
                .map_err(|error| EbpfError::Metrics {
                    reason: format!("counter {index}: {error}"),
                })?;
            *total = values
                .iter()
                .copied()
                .fold(0_u64, u64::wrapping_add);
        }
        Ok(counters)
    }

    fn rollback(&mut self) -> Result<(), EbpfError> {
        self.cleanup()
    }

    fn detach(&mut self) -> Result<(), EbpfError> {
        self.cleanup()
    }
}

pub(crate) fn embedded_object() -> &'static [u8] {
    aya::include_bytes_aligned!(env!("FERRO_NET_EBPF_OBJECT"))
}

fn aya_object_metadata(bpf: &Ebpf, program_abi: u32) -> Result<ObjectMetadata, EbpfError> {
    let mut maps = Vec::new();
    for (name, map) in bpf.maps() {
        let (kind, data) = inspected_map(map).ok_or_else(|| EbpfError::UnexpectedMap {
            map: name.to_string(),
        })?;
        let info = data.info().map_err(|error| EbpfError::ObjectLoad {
            reason: format!("could not inspect map `{name}`: {error}"),
        })?;
        maps.push(MapMetadata {
            name: name.to_string(),
            kind,
            key_size: info.key_size(),
            value_size: info.value_size(),
            max_entries: info.max_entries(),
        });
    }
    let mut classifiers = Vec::new();
    for (name, program) in bpf.programs() {
        if matches!(program, Program::SchedClassifier(_)) {
            classifiers.push(name.to_string());
        } else {
            return Err(EbpfError::UnexpectedClassifier {
                classifier: name.to_string(),
            });
        }
    }
    Ok(ObjectMetadata {
        program_abi,
        maps,
        classifiers,
    })
}

pub(crate) fn object_abi(object: &[u8]) -> Result<u32, EbpfError> {
    const ELF_HEADER_LEN: usize = 64;
    const SHT_SYMTAB: u32 = 2;
    const SYMBOL_LEN: usize = 24;

    if object.len() < ELF_HEADER_LEN
        || object.get(..4) != Some(b"\x7fELF")
        || object[4] != 2
        || object[5] != 1
    {
        return Err(invalid_elf("expected a little-endian ELF64 object"));
    }
    let section_offset = usize_from_u64(read_u64(object, 40)?, "section table offset")?;
    let section_entry_size = usize::from(read_u16(object, 58)?);
    let section_count = usize::from(read_u16(object, 60)?);
    if section_entry_size < 64 || section_count == 0 {
        return Err(invalid_elf("invalid section table dimensions"));
    }
    checked_region(
        object,
        section_offset,
        section_entry_size
            .checked_mul(section_count)
            .ok_or_else(|| invalid_elf("section table length overflow"))?,
    )?;

    for section_index in 0..section_count {
        let section = section_offset + section_index * section_entry_size;
        if read_u32(object, section + 4)? != SHT_SYMTAB {
            continue;
        }
        let symbols_offset = usize_from_u64(read_u64(object, section + 24)?, "symbol offset")?;
        let symbols_size = usize_from_u64(read_u64(object, section + 32)?, "symbol size")?;
        let string_section_index = read_u32(object, section + 40)? as usize;
        let symbol_entry_size = usize_from_u64(read_u64(object, section + 56)?, "symbol entry")?;
        if symbol_entry_size < SYMBOL_LEN || string_section_index >= section_count {
            return Err(invalid_elf("invalid symbol table dimensions"));
        }
        checked_region(object, symbols_offset, symbols_size)?;

        let strings_section = section_offset + string_section_index * section_entry_size;
        let strings_offset =
            usize_from_u64(read_u64(object, strings_section + 24)?, "string offset")?;
        let strings_size =
            usize_from_u64(read_u64(object, strings_section + 32)?, "string size")?;
        let strings = checked_region(object, strings_offset, strings_size)?;

        for symbol in (symbols_offset..symbols_offset + symbols_size).step_by(symbol_entry_size) {
            if symbol + SYMBOL_LEN > symbols_offset + symbols_size {
                break;
            }
            let name_offset = read_u32(object, symbol)? as usize;
            let Some(name) = elf_string(strings, name_offset) else {
                return Err(invalid_elf("invalid symbol name offset"));
            };
            if name != "ABI_VERSION" && !name.ends_with("ABI_VERSION") {
                continue;
            }
            let value_offset = usize_from_u64(read_u64(object, symbol + 8)?, "symbol value")?;
            let value_size = usize_from_u64(read_u64(object, symbol + 16)?, "symbol size")?;
            let value_section_index = usize::from(read_u16(object, symbol + 6)?);
            if value_size != size_of::<u32>() || value_section_index >= section_count {
                return Err(invalid_elf("ABI_VERSION has an invalid definition"));
            }
            let value_section = section_offset + value_section_index * section_entry_size;
            let value_section_offset = usize_from_u64(
                read_u64(object, value_section + 24)?,
                "ABI section offset",
            )?;
            let absolute_offset = value_section_offset
                .checked_add(value_offset)
                .ok_or_else(|| invalid_elf("ABI value offset overflow"))?;
            return read_u32(object, absolute_offset);
        }
    }
    Err(invalid_elf("ABI_VERSION symbol is missing"))
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, EbpfError> {
    let value = checked_region(bytes, offset, 2)?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, EbpfError> {
    let value = checked_region(bytes, offset, 4)?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, EbpfError> {
    let value = checked_region(bytes, offset, 8)?;
    Ok(u64::from_le_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ]))
}

fn checked_region(bytes: &[u8], offset: usize, length: usize) -> Result<&[u8], EbpfError> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| invalid_elf("ELF offset overflow"))?;
    bytes
        .get(offset..end)
        .ok_or_else(|| invalid_elf("ELF region is out of bounds"))
}

fn usize_from_u64(value: u64, field: &str) -> Result<usize, EbpfError> {
    usize::try_from(value).map_err(|_| invalid_elf(&format!("{field} does not fit in usize")))
}

fn elf_string(strings: &[u8], offset: usize) -> Option<&str> {
    let bytes = strings.get(offset..)?;
    let end = bytes.iter().position(|byte| *byte == 0)?;
    std::str::from_utf8(&bytes[..end]).ok()
}

fn invalid_elf(reason: &str) -> EbpfError {
    EbpfError::ObjectLoad {
        reason: reason.to_string(),
    }
}

fn inspected_map(map: &Map) -> Option<(MapKind, &MapData)> {
    match map {
        Map::HashMap(data) => Some((MapKind::Hash, data)),
        Map::LruHashMap(data) => Some((MapKind::LruHash, data)),
        Map::Array(data) => Some((MapKind::Array, data)),
        Map::PerCpuArray(data) => Some((MapKind::PerCpuArray, data)),
        _ => None,
    }
}

fn validate_bpffs_mount() -> Result<(), EbpfError> {
    let mountinfo = fs::read_to_string("/proc/self/mountinfo").map_err(|error| {
        EbpfError::BpffsUnavailable {
            reason: error.to_string(),
        }
    })?;
    let mounted = mountinfo.lines().any(|line| {
        let Some((mount, filesystem)) = line.split_once(" - ") else {
            return false;
        };
        let fields: Vec<_> = mount.split_whitespace().collect();
        fields.get(4) == Some(&BPFFS_ROOT)
            && filesystem.split_whitespace().next() == Some("bpf")
    });
    if mounted {
        Ok(())
    } else {
        Err(EbpfError::BpffsUnavailable {
            reason: format!("no bpf filesystem mounted at {BPFFS_ROOT}"),
        })
    }
}

fn validate_pin_path(pin_path: &Path) -> Result<(), EbpfError> {
    let ownership_root = Path::new(FERRO_NETWORK_ROOT);
    if pin_path.parent() != Some(ownership_root) {
        return Err(EbpfError::InvalidPinPath {
            path: pin_path.to_path_buf(),
        });
    }
    for path in [
        Path::new(BPFFS_ROOT),
        Path::new(BPFFS_ROOT).join("ferro").as_path(),
        ownership_root,
    ] {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => {
                return Err(EbpfError::InvalidPinPath {
                    path: path.to_path_buf(),
                });
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(EbpfError::BpffsUnavailable {
                    reason: format!("could not inspect {}: {error}", path.display()),
                });
            }
        }
    }
    match fs::symlink_metadata(pin_path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(EbpfError::PinPathExists {
            path: pin_path.to_path_buf(),
        }),
        Err(error) => Err(EbpfError::BpffsUnavailable {
            reason: format!("could not inspect {}: {error}", pin_path.display()),
        }),
    }
}

fn validate_interface(interface: &str, expected: u32) -> Result<(), EbpfError> {
    let value = fs::read_to_string(Path::new("/sys/class/net").join(interface).join("ifindex"))
        .map_err(|error| EbpfError::InterfaceMismatch {
            interface: interface.to_string(),
            expected,
            actual: error.raw_os_error().unwrap_or_default() as u32,
        })?;
    let actual = value
        .trim()
        .parse::<u32>()
        .map_err(|_| EbpfError::InterfaceMismatch {
            interface: interface.to_string(),
            expected,
            actual: 0,
        })?;
    if actual == expected {
        Ok(())
    } else {
        Err(EbpfError::InterfaceMismatch {
            interface: interface.to_string(),
            expected,
            actual,
        })
    }
}

fn validate_tc(interface: &str) -> Result<(), EbpfError> {
    let output = Command::new("tc")
        .args(["qdisc", "show", "dev", interface])
        .output()
        .map_err(|error| EbpfError::TcUnavailable {
            interface: interface.to_string(),
            reason: error.to_string(),
        })?;
    if !output.status.success() {
        return Err(EbpfError::TcUnavailable {
            interface: interface.to_string(),
            reason: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }

    let status = fs::read_to_string("/proc/self/status").map_err(|error| {
        EbpfError::TcUnavailable {
            interface: interface.to_string(),
            reason: error.to_string(),
        }
    })?;
    let effective = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:\t"))
        .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
        .unwrap_or_default();
    let cap_net_admin = effective & (1 << 12) != 0;
    let cap_sys_admin = effective & (1 << 21) != 0;
    let cap_bpf = effective & (1 << 39) != 0;
    if cap_net_admin && (cap_bpf || cap_sys_admin) {
        Ok(())
    } else {
        Err(EbpfError::TcUnavailable {
            interface: interface.to_string(),
            reason: "CAP_NET_ADMIN and CAP_BPF (or CAP_SYS_ADMIN) are required".to_string(),
        })
    }
}

fn fixed_bytes<const N: usize>(
    bytes: &[u8],
    map: &'static str,
    operation: &'static str,
) -> Result<[u8; N], EbpfError> {
    bytes.try_into().map_err(|_| EbpfError::MapOperation {
        operation,
        map,
        reason: format!("expected {N} bytes, found {}", bytes.len()),
    })
}

fn map_operation(operation: &'static str, map: &'static str, error: MapError) -> EbpfError {
    if has_errno(&error, 28) {
        EbpfError::MapCapacity { map }
    } else {
        EbpfError::MapOperation {
            operation,
            map,
            reason: error.to_string(),
        }
    }
}

fn has_errno(error: &(dyn std::error::Error + 'static), errno: i32) -> bool {
    let mut current = Some(error);
    while let Some(source) = current {
        if source
            .downcast_ref::<io::Error>()
            .is_some_and(|io_error| io_error.raw_os_error() == Some(errno))
        {
            return true;
        }
        current = source.source();
    }
    false
}

fn static_map_name(name: &str) -> &'static str {
    match name {
        ENDPOINTS_MAP_NAME => ENDPOINTS_MAP_NAME,
        PORTS_MAP_NAME => PORTS_MAP_NAME,
        CONNTRACK_MAP_NAME => CONNTRACK_MAP_NAME,
        POLICY_MAP_NAME => POLICY_MAP_NAME,
        COUNTERS_MAP_NAME => COUNTERS_MAP_NAME,
        _ => META_MAP_NAME,
    }
}

pub(crate) fn sha256(input: &[u8]) -> [u8; 32] {
    const INITIAL: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
        0x1f83d9ab, 0x5be0cd19,
    ];
    const ROUND: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
        0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
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
