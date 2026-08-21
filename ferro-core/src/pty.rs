//! Small, ownership-safe primitives for a supervised kernel PTY.
//!
//! The runtime deliberately keeps PTY allocation separate from the Docker
//! request parser. Callers must allocate only after durable authorization and
//! reservation, then retain the master for attach/log draining while handing
//! the slave to the child process.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::{ffi::CStr, os::raw::c_char};

use nix::pty::{openpty, Winsize};

const MAX_DIMENSION: u16 = 65_535;

#[derive(Debug)]
pub struct PtyPair {
    master: OwnedFd,
    slave: OwnedFd,
}

impl PtyPair {
    /// Allocate a PTY pair with a validated initial window size.
    pub fn new(rows: u16, cols: u16) -> io::Result<Self> {
        validate_dimension(rows, "rows")?;
        validate_dimension(cols, "cols")?;
        let size = Winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let pair = openpty(Some(&size), None).map_err(io::Error::from)?;
        Ok(Self {
            master: pair.master,
            slave: pair.slave,
        })
    }

    pub fn master(&self) -> &OwnedFd {
        &self.master
    }

    pub fn into_master(self) -> OwnedFd {
        self.master
    }

    pub fn into_slave(self) -> OwnedFd {
        self.slave
    }

    pub fn into_parts(self) -> (OwnedFd, OwnedFd) {
        (self.master, self.slave)
    }

    /// Return the kernel device path for the slave side while it is live.
    /// Callers may persist this path for a later Docker resize request.
    pub fn slave_name(&self) -> io::Result<PathBuf> {
        // SAFETY: the master descriptor is owned by this live PTY pair and
        // libc writes a NUL-terminated path into its static buffer.
        let name = unsafe { nix::libc::ttyname(self.master.as_raw_fd()) };
        if name.is_null() {
            return Err(io::Error::last_os_error());
        }
        let name = unsafe { CStr::from_ptr(name as *const c_char) };
        Ok(PathBuf::from(name.to_string_lossy().into_owned()))
    }

    /// Update the live terminal size through the PTY master.
    pub fn set_size(&self, rows: u16, cols: u16) -> io::Result<()> {
        validate_dimension(rows, "rows")?;
        validate_dimension(cols, "cols")?;
        let size = Winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        Self::set_size_fd(self.master.as_raw_fd(), &size)
    }

    /// Resize a PTY from a persisted slave device path.
    pub fn set_size_path(path: &Path, rows: u16, cols: u16) -> io::Result<()> {
        validate_dimension(rows, "rows")?;
        validate_dimension(cols, "cols")?;
        let size = Winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let fd = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;
        Self::set_size_fd(fd.as_raw_fd(), &size)
    }

    fn set_size_fd(fd: std::os::fd::RawFd, size: &Winsize) -> io::Result<()> {
        // SAFETY: `fd` is a live PTY descriptor and `size` points to a
        // properly initialized winsize structure for the ioctl duration.
        let result = unsafe { nix::libc::ioctl(fd, nix::libc::TIOCSWINSZ, size as *const Winsize) };
        if result == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

/// Make a spawned process a session leader with the PTY slave as its
/// controlling terminal. Merely wiring stdin/stdout/stderr to a PTY is not
/// sufficient for interactive programs: job-control signals, `tcgetpgrp`,
/// and terminal-generated interrupts require a controlling session.
///
/// The caller must install the slave descriptor as the command's stdin before
/// spawning. `pre_exec` runs after Rust has forked and duplicated those
/// descriptors, so descriptor 0 is valid in the child.
pub fn configure_command(command: &mut Command) -> io::Result<()> {
    // SAFETY: the closure only invokes async-signal-safe libc operations in
    // the post-fork child, and `slave_fd` is owned by the command's stdio.
    unsafe {
        command.pre_exec(move || {
            if nix::libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            if nix::libc::ioctl(
                nix::libc::STDIN_FILENO,
                nix::libc::TIOCSCTTY,
                0 as nix::libc::c_int,
            ) == -1
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(())
}

fn validate_dimension(value: u16, field: &str) -> io::Result<()> {
    // `MAX_DIMENSION` is `u16::MAX`, so a `u16` can never exceed it; only
    // zero is rejectable.
    if value == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{field} must be between 1 and {MAX_DIMENSION}"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;

    use super::PtyPair;

    #[test]
    fn rejects_zero_window_dimensions_before_allocation() {
        assert!(PtyPair::new(0, 80).is_err());
        assert!(PtyPair::new(24, 0).is_err());
    }

    #[test]
    fn allocates_and_resizes_a_kernel_pty() {
        let pair = PtyPair::new(24, 80).expect("allocate PTY");
        pair.set_size(40, 120).expect("resize PTY");
        let path = pair.slave_name().expect("slave device path");
        PtyPair::set_size_path(&path, 50, 140).expect("resize slave device");
        assert!(pair.master().as_raw_fd() >= 0);
    }

    #[test]
    fn child_output_crosses_the_slave_to_master_boundary() {
        use std::io::Read;
        use std::process::{Command, Stdio};

        let pair = PtyPair::new(24, 80).expect("allocate PTY");
        let (master, slave) = pair.into_parts();
        let mut child = Command::new("/bin/sh")
            .args(["-c", "printf ready"])
            .stdin(Stdio::null())
            .stdout(Stdio::from(slave))
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn PTY child");
        let mut output = Vec::new();
        let mut master = std::fs::File::from(master);
        let mut buffer = [0_u8; 64];
        loop {
            match master.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => output.extend_from_slice(&buffer[..count]),
                // Linux reports EIO when the PTY slave closes. That is the
                // terminal EOF condition, not a failed child write.
                Err(error) if error.raw_os_error() == Some(nix::libc::EIO) => break,
                Err(error) => panic!("read PTY master: {error}"),
            }
        }
        assert!(child.wait().expect("wait PTY child").success());
        assert!(
            String::from_utf8_lossy(&output).contains("ready"),
            "PTY output={output:?}"
        );
    }

    #[test]
    fn child_can_use_pty_as_controlling_terminal() {
        use std::io::Read;
        use std::process::{Command, Stdio};

        let pair = PtyPair::new(24, 80).expect("allocate PTY");
        let (master, slave) = pair.into_parts();
        let slave_for_stdin = slave.try_clone().expect("clone PTY slave");
        let mut command = Command::new("/usr/bin/timeout");
        command
            .args(["2", "/bin/sh", "-c", "test -t 0 && test -t 1 && stty size"])
            .stdin(Stdio::from(slave_for_stdin))
            .stdout(Stdio::from(slave.try_clone().expect("clone PTY slave")))
            .stderr(Stdio::from(slave));
        super::configure_command(&mut command).expect("configure controlling terminal");
        let mut child = command.spawn().expect("spawn PTY child");
        let mut output = Vec::new();
        let mut master = std::fs::File::from(master);
        let flags = unsafe { nix::libc::fcntl(master.as_raw_fd(), nix::libc::F_GETFL) };
        assert!(flags >= 0, "get PTY flags failed");
        assert_eq!(
            unsafe {
                nix::libc::fcntl(
                    master.as_raw_fd(),
                    nix::libc::F_SETFL,
                    flags | nix::libc::O_NONBLOCK,
                )
            },
            0,
            "set PTY nonblocking failed"
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let status = loop {
            let mut buffer = [0_u8; 128];
            match master.read(&mut buffer) {
                Ok(count) => output.extend_from_slice(&buffer[..count]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) if error.raw_os_error() == Some(nix::libc::EIO) => {}
                Err(error) => panic!("read PTY master: {error}"),
            }
            if let Some(status) = child.try_wait().expect("poll PTY child") {
                break status;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "PTY child did not exit"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert!(
            status.success(),
            "PTY child status={status:?} output={output:?}"
        );
        assert!(
            String::from_utf8_lossy(&output).contains("24 80"),
            "PTY output={output:?}"
        );
    }
}
