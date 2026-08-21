//! Small, ownership-safe primitives for a supervised kernel PTY.
//!
//! The runtime deliberately keeps PTY allocation separate from the Docker
//! request parser. Callers must allocate only after durable authorization and
//! reservation, then retain the master for attach/log draining while handing
//! the slave to the child process.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
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

fn validate_dimension(value: u16, field: &str) -> io::Result<()> {
    if value == 0 || value > MAX_DIMENSION {
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
}
