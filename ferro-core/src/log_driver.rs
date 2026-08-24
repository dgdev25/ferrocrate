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
