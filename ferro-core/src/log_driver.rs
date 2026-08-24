use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogStream {
    Stdout,
    Stderr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    pub stream: LogStream,
    pub timestamp_nanos: u128,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerLogContext {
    pub container_id: String,
    pub log_dir: PathBuf,
    pub append: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogReadback {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogRotation {
    pub max_size: u64,
    pub max_files: u32,
}

pub trait ContainerLogWriter: Send {
    fn write(&mut self, entry: &LogEntry) -> io::Result<()>;
    fn flush(&mut self) -> io::Result<()>;
    fn close(&mut self) -> io::Result<()>;
}

pub trait LogDriver: Send + Sync {
    fn name(&self) -> &str;
    fn supports_read(&self) -> bool;
    fn open(&self, context: &ContainerLogContext) -> io::Result<Box<dyn ContainerLogWriter>>;

    fn read(&self, _context: &ContainerLogContext) -> io::Result<LogReadback> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("configured logging driver {} does not support reading", self.name()),
        ))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct JsonFileLogDriver {
    rotation: Option<LogRotation>,
}

impl JsonFileLogDriver {
    pub fn new(rotation: Option<LogRotation>) -> Self {
        Self { rotation }
    }
}

impl LogDriver for JsonFileLogDriver {
    fn name(&self) -> &str {
        "json-file"
    }

    fn supports_read(&self) -> bool {
        true
    }

    fn open(&self, context: &ContainerLogContext) -> io::Result<Box<dyn ContainerLogWriter>> {
        fs::create_dir_all(&context.log_dir)?;
        Ok(Box::new(JsonFileLogWriter {
            stdout: JsonFileStream::open(
                context.log_dir.join("stdout.log"),
                context.append,
                self.rotation,
            )?,
            stderr: JsonFileStream::open(
                context.log_dir.join("stderr.log"),
                context.append,
                self.rotation,
            )?,
            closed: false,
        }))
    }

    fn read(&self, context: &ContainerLogContext) -> io::Result<LogReadback> {
        Ok(LogReadback {
            stdout: read_rotated(&context.log_dir.join("stdout.log"))?,
            stderr: read_rotated(&context.log_dir.join("stderr.log"))?,
        })
    }
}

struct JsonFileLogWriter {
    stdout: JsonFileStream,
    stderr: JsonFileStream,
    closed: bool,
}

impl ContainerLogWriter for JsonFileLogWriter {
    fn write(&mut self, entry: &LogEntry) -> io::Result<()> {
        if self.closed {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "log writer is closed"));
        }
        match entry.stream {
            LogStream::Stdout => self.stdout.write(entry),
            LogStream::Stderr => self.stderr.write(entry),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stdout.flush()?;
        self.stderr.flush()
    }

    fn close(&mut self) -> io::Result<()> {
        if !self.closed {
            self.flush()?;
            self.closed = true;
        }
        Ok(())
    }
}

struct JsonFileStream {
    path: PathBuf,
    log: File,
    journal: File,
    offset: u64,
    rotation: Option<LogRotation>,
}

impl JsonFileStream {
    fn open(path: PathBuf, append: bool, rotation: Option<LogRotation>) -> io::Result<Self> {
        let log = open_log_file(&path, append)?;
        let journal = open_log_file(&journal_path(&path), append)?;
        let offset = log.metadata()?.len();
        Ok(Self { path, log, journal, offset, rotation })
    }

    fn write(&mut self, entry: &LogEntry) -> io::Result<()> {
        if entry.bytes.is_empty() {
            return Ok(());
        }
        if let Some(rotation) = self.rotation {
            let current = self.log.metadata()?.len();
            if current > 0 && current.saturating_add(entry.bytes.len() as u64) > rotation.max_size {
                self.flush()?;
                rotate_pair(&self.path, rotation.max_files)?;
                self.log = open_log_file(&self.path, true)?;
                self.journal = open_log_file(&journal_path(&self.path), true)?;
                self.offset = 0;
            }
        }
        self.log.write_all(&entry.bytes)?;
        writeln!(self.journal, "{} {}", self.offset, entry.timestamp_nanos)?;
        self.offset += entry.bytes.len() as u64;
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.log.flush()?;
        self.journal.flush()?;
        self.log.sync_data()?;
        self.journal.sync_data()
    }
}

fn open_log_file(path: &Path, append: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).write(true);
    if append {
        options.append(true);
    } else {
        options.truncate(true);
    }
    options.open(path)
}

fn journal_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".ts");
    path.with_file_name(name)
}

fn rotated_path(path: &Path, index: u32) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{index}"));
    path.with_file_name(name)
}

fn rotate_pair(path: &Path, max_files: u32) -> io::Result<()> {
    if max_files < 2 {
        return Ok(());
    }
    let oldest = max_files - 1;
    let _ = fs::remove_file(rotated_path(path, oldest));
    let _ = fs::remove_file(journal_path(&rotated_path(path, oldest)));
    for index in (1..oldest).rev() {
        let source = rotated_path(path, index);
        if source.exists() {
            fs::rename(&source, rotated_path(path, index + 1))?;
        }
        let source_journal = journal_path(&source);
        if source_journal.exists() {
            fs::rename(source_journal, journal_path(&rotated_path(path, index + 1)))?;
        }
    }
    if path.exists() {
        fs::rename(path, rotated_path(path, 1))?;
    }
    let journal = journal_path(path);
    if journal.exists() {
        fs::rename(journal, journal_path(&rotated_path(path, 1)))?;
    }
    Ok(())
}

fn read_rotated(path: &Path) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    for index in (1..=64).rev() {
        let rotated = rotated_path(path, index);
        if rotated.exists() {
            output.extend(fs::read(rotated)?);
        }
    }
    if path.exists() {
        output.extend(fs::read(path)?);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::{
        ContainerLogContext, JsonFileLogDriver, LogDriver, LogEntry, LogStream,
    };

    #[test]
    fn json_file_driver_runs_container_lifecycle_and_reads_streams() {
        let temp = tempfile::tempdir().expect("tempdir");
        let context = ContainerLogContext {
            container_id: "container-123".into(),
            log_dir: temp.path().to_path_buf(),
            append: false,
        };
        let driver = JsonFileLogDriver::new(None);
        assert_eq!(driver.name(), "json-file");
        assert!(driver.supports_read());

        let mut writer = driver.open(&context).expect("open");
        writer
            .write(&LogEntry {
                stream: LogStream::Stdout,
                timestamp_nanos: 10,
                bytes: b"hello\n".to_vec(),
            })
            .expect("write stdout");
        writer
            .write(&LogEntry {
                stream: LogStream::Stderr,
                timestamp_nanos: 20,
                bytes: b"warning\n".to_vec(),
            })
            .expect("write stderr");
        writer.flush().expect("flush");
        writer.close().expect("close");

        let readback = driver.read(&context).expect("readback");
        assert_eq!(readback.stdout, b"hello\n");
        assert_eq!(readback.stderr, b"warning\n");
        assert_eq!(
            std::fs::read_to_string(temp.path().join("stdout.log.ts")).unwrap(),
            "0 10\n"
        );
        assert_eq!(
            std::fs::read_to_string(temp.path().join("stderr.log.ts")).unwrap(),
            "0 20\n"
        );
    }

    #[test]
    fn json_file_driver_rotates_log_and_timestamp_journal_as_a_pair() {
        let temp = tempfile::tempdir().expect("tempdir");
        let context = ContainerLogContext {
            container_id: "container-rotate".into(),
            log_dir: temp.path().to_path_buf(),
            append: false,
        };
        let driver = JsonFileLogDriver::new(Some(super::LogRotation {
            max_size: 5,
            max_files: 2,
        }));
        let mut writer = driver.open(&context).expect("open");
        for (timestamp_nanos, bytes) in [(10, b"one\n".as_slice()), (20, b"two\n".as_slice())] {
            writer
                .write(&LogEntry {
                    stream: LogStream::Stdout,
                    timestamp_nanos,
                    bytes: bytes.to_vec(),
                })
                .expect("write");
        }
        writer.close().expect("close");

        assert_eq!(
            std::fs::read(temp.path().join("stdout.log.1")).unwrap(),
            b"one\n"
        );
        assert_eq!(
            std::fs::read_to_string(temp.path().join("stdout.log.1.ts")).unwrap(),
            "0 10\n"
        );
        assert_eq!(std::fs::read(temp.path().join("stdout.log")).unwrap(), b"two\n");
        assert_eq!(
            std::fs::read_to_string(temp.path().join("stdout.log.ts")).unwrap(),
            "0 20\n"
        );
    }
}
