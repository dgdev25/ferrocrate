use super::JournalError;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    path::Path,
};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

pub(super) const READER_MAGIC: &[u8; 8] = b"FWREAD02";
pub(super) const READER_FILE: &str = "witness.readonly-v2";
const HEADER_BYTES: u64 = 32;
const MAX_SNAPSHOT_BYTES: u64 = 128 * 1024 * 1024;

/// A no-create, no-lock, bounded reader over an atomically published witness
/// snapshot. Opening this type never initializes sled trees, reserve metadata,
/// directories, or writer state.
pub struct WitnessReader {
    file: File,
    journal_id: [u8; 16],
    remaining: u64,
    last_sequence: u64,
    failed: bool,
}

impl WitnessReader {
    pub fn open_read_only(
        root: impl AsRef<Path>,
        expected: [u8; 16],
    ) -> Result<Self, JournalError> {
        let path = root.as_ref().join(READER_FILE);
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
        let mut file = options.open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.len() < HEADER_BYTES
            || metadata.len() > MAX_SNAPSHOT_BYTES
        {
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
        let remaining = u64::from_be_bytes(
            header[24..32]
                .try_into()
                .map_err(|_| JournalError::Corrupt)?,
        );
        if remaining > 1_000_000 {
            return Err(JournalError::Corrupt);
        }
        Ok(Self {
            file,
            journal_id: expected,
            remaining,
            last_sequence: 0,
            failed: false,
        })
    }

    pub const fn journal_id(&self) -> [u8; 16] {
        self.journal_id
    }

    pub fn next_record(&mut self) -> Result<Option<Vec<u8>>, JournalError> {
        if self.remaining == 0 {
            return Ok(None);
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
        {
            return Err(JournalError::Corrupt);
        }
        let mut bytes = vec![0; length];
        self.file.read_exact(&mut bytes)?;
        self.last_sequence = sequence;
        self.remaining -= 1;
        if self.remaining == 0 {
            let end = self.file.stream_position()?;
            if end != self.file.seek(SeekFrom::End(0))? {
                return Err(JournalError::Corrupt);
            }
        }
        Ok(Some(bytes))
    }

    pub fn records(&mut self) -> WitnessRecords<'_> {
        WitnessRecords(self)
    }

    pub fn finish(self) -> Result<(), JournalError> {
        if self.failed || self.remaining != 0 {
            Err(JournalError::Corrupt)
        } else {
            Ok(())
        }
    }
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
