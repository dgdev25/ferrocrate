use super::JournalError;
use std::{
    collections::VecDeque,
    fs::{File, OpenOptions},
    io::{Read, Seek},
    path::Path,
};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

pub(super) const READER_MAGIC: &[u8; 8] = b"FWREAD03";
pub(super) const READER_FILE: &str = "witness.readonly-v2";
pub(super) const READER_SEGMENT_PREFIX: &str = "witness.readonly-v2.segment-";
const HEADER_BYTES: u64 = 24;
const MAX_MIRROR_BYTES: u64 = 16 * 1024 * 1024 * 1024;

/// A no-create, no-lock, bounded reader over an atomically published witness
/// snapshot. Opening this type never initializes sled trees, reserve metadata,
/// directories, or writer state.
pub struct WitnessReader {
    file: File,
    pending: VecDeque<(File, u64)>,
    journal_id: [u8; 16],
    end_offset: u64,
    last_sequence: u64,
    last_hash: [u8; 32],
    failed: bool,
}

impl WitnessReader {
    pub fn open_read_only(
        root: impl AsRef<Path>,
        expected: [u8; 16],
    ) -> Result<Self, JournalError> {
        let path = root.as_ref().join(READER_FILE);
        if root.as_ref().join("witness.reader-stale").exists() {
            return Err(JournalError::ReaderStale);
        }
        let mut paths = Vec::new();
        for entry in std::fs::read_dir(root.as_ref())? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some(range) = name.strip_prefix(READER_SEGMENT_PREFIX) {
                let (first, last) = range.split_once('-').ok_or(JournalError::Corrupt)?;
                paths.push((
                    first.parse::<u64>().map_err(|_| JournalError::Corrupt)?,
                    last.parse::<u64>().map_err(|_| JournalError::Corrupt)?,
                    entry.path(),
                ));
            }
        }
        paths.sort_by_key(|part| part.0);
        paths.push((u64::MAX, u64::MAX, path));
        let mut opened = VecDeque::new();
        for (_, _, path) in paths {
            let (file, length) = open_part(&path, expected)?;
            opened.push_back((file, length));
        }
        let (file, end_offset) = opened.pop_front().ok_or(JournalError::Corrupt)?;
        Ok(Self {
            file,
            pending: opened,
            journal_id: expected,
            end_offset,
            last_sequence: 0,
            last_hash: [0; 32],
            failed: false,
        })
    }

    pub const fn journal_id(&self) -> [u8; 16] {
        self.journal_id
    }

    pub fn next_record(&mut self) -> Result<Option<Vec<u8>>, JournalError> {
        while self.file.stream_position()? == self.end_offset {
            let Some((file, end)) = self.pending.pop_front() else {
                return Ok(None);
            };
            self.file = file;
            self.end_offset = end;
        }
        let position = self.file.stream_position()?;
        if position == self.end_offset {
            return Ok(None);
        }
        if position > self.end_offset || self.end_offset - position < 12 {
            return Err(JournalError::Corrupt);
        }
        let mut header = [0_u8; 12];
        self.file.read_exact(&mut header)?;
        let sequence =
            u64::from_be_bytes(header[..8].try_into().map_err(|_| JournalError::Corrupt)?);
        let length =
            u32::from_be_bytes(header[8..].try_into().map_err(|_| JournalError::Corrupt)?) as usize;
        if sequence != self.last_sequence.saturating_add(1)
            || length == 0
            || length > super::MAX_RECORD_BYTES
            || self.file.stream_position()?.saturating_add(length as u64) > self.end_offset
        {
            return Err(JournalError::Corrupt);
        }
        let mut bytes = vec![0; length];
        self.file.read_exact(&mut bytes)?;
        let decoded = super::decode_record(&bytes).map_err(|_| JournalError::Corrupt)?;
        if decoded.journal_id() != &self.journal_id
            || decoded.sequence() != sequence
            || decoded.previous_hash() != self.last_hash
        {
            return Err(JournalError::Corrupt);
        }
        self.last_sequence = sequence;
        self.last_hash = decoded.record_hash();
        Ok(Some(bytes))
    }

    pub fn records(&mut self) -> WitnessRecords<'_> {
        WitnessRecords(self)
    }

    pub fn finish(mut self) -> Result<(), JournalError> {
        if self.failed
            || self.file.stream_position()? != self.end_offset
            || !self.pending.is_empty()
        {
            Err(JournalError::Corrupt)
        } else {
            Ok(())
        }
    }
}

fn open_part(path: &Path, expected: [u8; 16]) -> Result<(File, u64), JournalError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
    let mut file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() < HEADER_BYTES || metadata.len() > MAX_MIRROR_BYTES {
        return Err(JournalError::Corrupt);
    }
    #[cfg(unix)]
    if metadata.nlink() != 1 {
        return Err(JournalError::Corrupt);
    }
    let mut header = [0_u8; HEADER_BYTES as usize];
    file.read_exact(&mut header)?;
    if &header[..8] != READER_MAGIC || header[8..24] != expected {
        return Err(JournalError::JournalMismatch);
    }
    Ok((file, metadata.len()))
}

pub struct WitnessRecords<'a>(&'a mut WitnessReader);

impl Iterator for WitnessRecords<'_> {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.0.next_record() {
            Ok(value) => value,
            Err(_) => {
                self.0.failed = true;
                None
            }
        }
    }
}
