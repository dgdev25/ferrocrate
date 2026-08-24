use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use base64::Engine as _;
use ed25519_dalek::VerifyingKey;
use serde::Serialize;

use crate::plugin_contract::{PluginKind, PluginManifest};
use crate::plugin_runtime::execute_plugin;

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
            format!(
                "configured logging driver {} does not support reading",
                self.name()
            ),
        ))
    }
}

#[cfg(feature = "journald")]
#[derive(Debug, Clone)]
pub struct JournaldLogDriver {
    socket_path: PathBuf,
}

#[cfg(feature = "journald")]
impl JournaldLogDriver {
    pub fn system() -> Self {
        Self::new("/run/systemd/journal/socket")
    }

    pub fn new(socket_path: impl AsRef<Path>) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_path_buf(),
        }
    }
}

#[cfg(feature = "journald")]
impl LogDriver for JournaldLogDriver {
    fn name(&self) -> &str {
        "journald"
    }

    fn supports_read(&self) -> bool {
        false
    }

    fn open(&self, context: &ContainerLogContext) -> io::Result<Box<dyn ContainerLogWriter>> {
        use std::os::unix::net::UnixDatagram;
        let socket = UnixDatagram::unbound()?;
        socket.connect(&self.socket_path)?;
        Ok(Box::new(JournaldLogWriter {
            socket,
            container_id: safe_identity(&context.container_id),
            closed: false,
        }))
    }
}

#[cfg(feature = "journald")]
struct JournaldLogWriter {
    socket: std::os::unix::net::UnixDatagram,
    container_id: String,
    closed: bool,
}

#[cfg(feature = "journald")]
impl ContainerLogWriter for JournaldLogWriter {
    fn write(&mut self, entry: &LogEntry) -> io::Result<()> {
        if self.closed {
            return Err(closed_writer_error());
        }
        let message = trim_line_end(&entry.bytes);
        let priority = match entry.stream {
            LogStream::Stdout => 6,
            LogStream::Stderr => 3,
        };
        let stream = stream_name(entry.stream);
        let mut payload = format!(
            "CONTAINER_ID={}\nCONTAINER_NAME={}\nSYSLOG_IDENTIFIER=ferrocrate\nPRIORITY={priority}\nFERROCRATE_STREAM={stream}\nFERROCRATE_TIMESTAMP_NANOS={}\n",
            self.container_id, self.container_id, entry.timestamp_nanos
        )
        .into_bytes();
        if message.contains(&b'\n') {
            payload.extend_from_slice(b"MESSAGE\n");
            payload.extend_from_slice(&(message.len() as u64).to_le_bytes());
            payload.extend_from_slice(message);
            payload.push(b'\n');
        } else {
            payload.extend_from_slice(b"MESSAGE=");
            payload.extend_from_slice(message);
            payload.push(b'\n');
        }
        self.socket.send(&payload).map(|_| ())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn close(&mut self) -> io::Result<()> {
        self.closed = true;
        Ok(())
    }
}

#[cfg(feature = "syslog")]
#[derive(Debug, Clone)]
pub struct SyslogLogDriver {
    socket_path: PathBuf,
}

#[cfg(feature = "syslog")]
impl SyslogLogDriver {
    pub fn system() -> Self {
        Self::new("/dev/log")
    }

    pub fn new(socket_path: impl AsRef<Path>) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_path_buf(),
        }
    }
}

#[cfg(feature = "syslog")]
impl LogDriver for SyslogLogDriver {
    fn name(&self) -> &str {
        "syslog"
    }

    fn supports_read(&self) -> bool {
        false
    }

    fn open(&self, context: &ContainerLogContext) -> io::Result<Box<dyn ContainerLogWriter>> {
        use std::os::unix::net::UnixDatagram;
        let socket = UnixDatagram::unbound()?;
        socket.connect(&self.socket_path)?;
        Ok(Box::new(SyslogLogWriter {
            socket,
            container_id: safe_identity(&context.container_id),
            closed: false,
        }))
    }
}

#[cfg(feature = "syslog")]
struct SyslogLogWriter {
    socket: std::os::unix::net::UnixDatagram,
    container_id: String,
    closed: bool,
}

#[cfg(feature = "syslog")]
impl ContainerLogWriter for SyslogLogWriter {
    fn write(&mut self, entry: &LogEntry) -> io::Result<()> {
        if self.closed {
            return Err(closed_writer_error());
        }
        let priority = match entry.stream {
            LogStream::Stdout => 14,
            LogStream::Stderr => 11,
        };
        let message =
            String::from_utf8_lossy(trim_line_end(&entry.bytes)).replace(['\r', '\n'], " ");
        let payload = format!(
            "<{priority}>1 - ferrocrate {} {} - {message}",
            self.container_id,
            stream_name(entry.stream)
        );
        self.socket.send(payload.as_bytes()).map(|_| ())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn close(&mut self) -> io::Result<()> {
        self.closed = true;
        Ok(())
    }
}

#[derive(Clone)]
pub struct ExternalLogDriver {
    manifest: PluginManifest,
    trust_root: VerifyingKey,
}

impl ExternalLogDriver {
    pub fn new(manifest: PluginManifest, trust_root: VerifyingKey) -> io::Result<Self> {
        if manifest.kind != PluginKind::LogDriver {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "plugin manifest is not a log driver",
            ));
        }
        if !manifest
            .permissions
            .iter()
            .any(|permission| permission == "write_logs")
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "log driver plugin must declare write_logs",
            ));
        }
        Ok(Self {
            manifest,
            trust_root,
        })
    }

    fn call(&self, envelope: &ExternalLogEnvelope) -> io::Result<()> {
        let input = serde_json::to_vec(envelope)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let result = execute_plugin(
            &self.manifest,
            &self.trust_root,
            "write_logs",
            &["log-driver".to_string()],
            &input,
        )
        .map_err(io::Error::other)?;
        if result.exit_code != 0 || result.timed_out {
            return Err(io::Error::other(format!(
                "log driver plugin exited with status {}: {}",
                result.exit_code,
                String::from_utf8_lossy(&result.stderr)
            )));
        }
        Ok(())
    }
}

impl LogDriver for ExternalLogDriver {
    fn name(&self) -> &str {
        &self.manifest.name
    }

    fn supports_read(&self) -> bool {
        false
    }

    fn open(&self, context: &ContainerLogContext) -> io::Result<Box<dyn ContainerLogWriter>> {
        let writer = ExternalLogWriter {
            driver: self.clone(),
            container_id: context.container_id.clone(),
            closed: false,
        };
        writer.call("open", None)?;
        Ok(Box::new(writer))
    }
}

struct ExternalLogWriter {
    driver: ExternalLogDriver,
    container_id: String,
    closed: bool,
}

impl ExternalLogWriter {
    fn call(&self, operation: &str, entry: Option<&LogEntry>) -> io::Result<()> {
        self.driver.call(&ExternalLogEnvelope {
            operation,
            container_id: &self.container_id,
            stream: entry.map(|entry| stream_name(entry.stream)),
            timestamp_nanos: entry.map(|entry| entry.timestamp_nanos),
            data_base64: entry
                .map(|entry| base64::engine::general_purpose::STANDARD.encode(&entry.bytes)),
        })
    }
}

impl ContainerLogWriter for ExternalLogWriter {
    fn write(&mut self, entry: &LogEntry) -> io::Result<()> {
        if self.closed {
            return Err(closed_writer_error());
        }
        self.call("write", Some(entry))
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.closed {
            return Err(closed_writer_error());
        }
        self.call("flush", None)
    }

    fn close(&mut self) -> io::Result<()> {
        if !self.closed {
            self.call("close", None)?;
            self.closed = true;
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct ExternalLogEnvelope<'a> {
    operation: &'a str,
    container_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    stream: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp_nanos: Option<u128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_base64: Option<String>,
}

fn stream_name(stream: LogStream) -> &'static str {
    match stream {
        LogStream::Stdout => "stdout",
        LogStream::Stderr => "stderr",
    }
}

#[cfg(any(feature = "journald", feature = "syslog"))]
fn trim_line_end(mut bytes: &[u8]) -> &[u8] {
    while bytes
        .last()
        .is_some_and(|byte| *byte == b'\n' || *byte == b'\r')
    {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

#[cfg(any(feature = "journald", feature = "syslog"))]
fn safe_identity(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn closed_writer_error() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "log writer is closed")
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
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "log writer is closed",
            ));
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
        Ok(Self {
            path,
            log,
            journal,
            offset,
            rotation,
        })
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
    use super::{ContainerLogContext, JsonFileLogDriver, LogDriver, LogEntry, LogStream};

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
        assert_eq!(
            std::fs::read(temp.path().join("stdout.log")).unwrap(),
            b"two\n"
        );
        assert_eq!(
            std::fs::read_to_string(temp.path().join("stdout.log.ts")).unwrap(),
            "0 20\n"
        );
    }

    #[cfg(feature = "journald")]
    #[test]
    fn journald_driver_emits_container_id_and_message() {
        use super::JournaldLogDriver;
        use std::os::unix::net::UnixDatagram;

        let temp = tempfile::tempdir().expect("tempdir");
        let socket_path = temp.path().join("journal.sock");
        let receiver = UnixDatagram::bind(&socket_path).expect("bind journal receiver");
        receiver
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .expect("timeout");
        let context = ContainerLogContext {
            container_id: "journal-container".into(),
            log_dir: temp.path().join("logs"),
            append: false,
        };
        let driver = JournaldLogDriver::new(&socket_path);
        let mut writer = driver.open(&context).expect("open");
        writer
            .write(&LogEntry {
                stream: LogStream::Stdout,
                timestamp_nanos: 42,
                bytes: b"journal hello\n".to_vec(),
            })
            .expect("write");
        writer.close().expect("close");

        let mut buffer = [0_u8; 4096];
        let count = receiver.recv(&mut buffer).expect("journal datagram");
        let entry = String::from_utf8_lossy(&buffer[..count]);
        assert!(entry.contains("CONTAINER_ID=journal-container"), "{entry}");
        assert!(entry.contains("MESSAGE=journal hello"), "{entry}");
        assert!(!driver.supports_read());
    }

    #[cfg(feature = "syslog")]
    #[test]
    fn syslog_driver_emits_rfc5424_container_identity() {
        use super::SyslogLogDriver;
        use std::os::unix::net::UnixDatagram;

        let temp = tempfile::tempdir().expect("tempdir");
        let socket_path = temp.path().join("syslog.sock");
        let receiver = UnixDatagram::bind(&socket_path).expect("bind syslog receiver");
        receiver
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .expect("timeout");
        let context = ContainerLogContext {
            container_id: "syslog-container".into(),
            log_dir: temp.path().join("logs"),
            append: false,
        };
        let driver = SyslogLogDriver::new(&socket_path);
        let mut writer = driver.open(&context).expect("open");
        writer
            .write(&LogEntry {
                stream: LogStream::Stderr,
                timestamp_nanos: 42,
                bytes: b"syslog warning\n".to_vec(),
            })
            .expect("write");
        writer.close().expect("close");

        let mut buffer = [0_u8; 4096];
        let count = receiver.recv(&mut buffer).expect("syslog datagram");
        let entry = String::from_utf8_lossy(&buffer[..count]);
        assert!(entry.starts_with("<11>1 "), "{entry}");
        assert!(
            entry.contains(" ferrocrate syslog-container stderr - "),
            "{entry}"
        );
        assert!(entry.ends_with("syslog warning"), "{entry}");
        assert!(!driver.supports_read());
    }

    #[test]
    fn published_manifest_fixture_plugin_receives_lifecycle_and_write() {
        use super::ExternalLogDriver;
        use crate::plugin_contract::parse_plugin_manifest;
        use ed25519_dalek::{Signer, SigningKey};
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().expect("tempdir");
        let capture = temp.path().join("capture.jsonl");
        let entrypoint = temp.path().join("fixture-log-driver.sh");
        std::fs::write(
            &entrypoint,
            include_bytes!("../../tests/fixtures/plugins/log-driver-recorder.sh"),
        )
        .expect("fixture entrypoint");
        std::fs::set_permissions(&entrypoint, std::fs::Permissions::from_mode(0o700))
            .expect("executable fixture");
        {
            let _guard = crate::test_support::acquire_env_lock();
            unsafe { std::env::set_var("FERROCRATE_LOG_DRIVER_CAPTURE", &capture) };
        }

        let mut manifest = parse_plugin_manifest(include_bytes!(
            "../../tests/fixtures/plugins/log-driver-v1.json"
        ))
        .expect("published manifest fixture");
        manifest.entrypoint = entrypoint.display().to_string();
        manifest.signature.clear();
        let key = SigningKey::from_bytes(&[17_u8; 32]);
        let unsigned = serde_json::to_vec(&manifest).expect("canonical manifest");
        manifest.signature = format!("ed25519:{}", hex::encode(key.sign(&unsigned).to_bytes()));

        let context = ContainerLogContext {
            container_id: "plugin-container".into(),
            log_dir: temp.path().join("logs"),
            append: false,
        };
        let driver = ExternalLogDriver::new(manifest, key.verifying_key()).expect("driver");
        let mut writer = driver.open(&context).expect("open");
        writer
            .write(&LogEntry {
                stream: LogStream::Stdout,
                timestamp_nanos: 99,
                bytes: b"plugin hello\n".to_vec(),
            })
            .expect("write");
        writer.flush().expect("flush");
        writer.close().expect("close");
        {
            let _guard = crate::test_support::acquire_env_lock();
            unsafe { std::env::remove_var("FERROCRATE_LOG_DRIVER_CAPTURE") };
        }

        let records = std::fs::read_to_string(capture).expect("plugin capture");
        let operations = records
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("envelope"))
            .map(|record| record["operation"].as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        assert_eq!(operations, ["open", "write", "flush", "close"]);
        assert!(records.contains("plugin-container"), "{records}");
        assert!(records.contains("cGx1Z2luIGhlbGxvCg=="), "{records}");
    }

    #[test]
    fn shared_capture_opens_once_writes_both_streams_and_closes_once() {
        use super::{capture_stream, ContainerLogWriter, LogCapture};
        use std::sync::{Arc, Mutex};

        #[derive(Clone)]
        struct RecordingWriter(Arc<Mutex<Vec<String>>>);
        impl ContainerLogWriter for RecordingWriter {
            fn write(&mut self, entry: &LogEntry) -> std::io::Result<()> {
                self.0.lock().unwrap().push(format!(
                    "write:{}:{}",
                    super::stream_name(entry.stream),
                    String::from_utf8_lossy(&entry.bytes)
                ));
                Ok(())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.0.lock().unwrap().push("flush".into());
                Ok(())
            }
            fn close(&mut self) -> std::io::Result<()> {
                self.0.lock().unwrap().push("close".into());
                Ok(())
            }
        }

        let calls = Arc::new(Mutex::new(Vec::new()));
        let capture = LogCapture::new(Box::new(RecordingWriter(Arc::clone(&calls))), 2);
        capture_stream(b"out\n".as_slice(), capture.clone(), LogStream::Stdout);
        assert!(!calls.lock().unwrap().contains(&"close".to_string()));
        capture_stream(b"err\n".as_slice(), capture, LogStream::Stderr);

        let calls = calls.lock().unwrap();
        assert!(calls.iter().any(|call| call == "write:stdout:out\n"));
        assert!(calls.iter().any(|call| call == "write:stderr:err\n"));
        assert_eq!(calls.iter().filter(|call| call.as_str() == "close").count(), 1);
    }
}
