use crate::{
    protocol::{response_frame, MAX_FRAME_BYTES},
    server::NetdServer,
};
use nix::sys::socket::{getsockopt, recvmsg, sockopt::PeerCredentials, ControlMessageOwned};
use std::{
    io::Write,
    os::{fd::AsRawFd, unix::net::UnixListener},
    path::{Path, PathBuf},
};

/// Accepts and serves exactly one production-authenticated netd request.
/// Peer UID, pidfd, executable and start time are validated before any body bytes are read.
pub fn serve_authenticated_one(
    listener: &UnixListener,
    server: &mut NetdServer,
    expected_uid: u32,
    expected_executable: &Path,
    now: u64,
) -> Result<(), String> {
    let (mut stream, _) = listener.accept().map_err(|error| error.to_string())?;
    let credentials = getsockopt(&stream, PeerCredentials).map_err(|error| error.to_string())?;
    if credentials.uid() != expected_uid {
        return Err("unexpected Unix peer UID".into());
    }
    let peer = authenticate_peer_process(credentials.pid(), expected_executable)?;
    let mut prefix = [0_u8; 4];
    receive_no_descriptors(&stream, &mut prefix)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length > MAX_FRAME_BYTES {
        return Err("frame exceeds 1 MiB".into());
    }
    let mut body = vec![0_u8; length];
    receive_no_descriptors(&stream, &mut body)?;
    if !peer.still_valid() {
        return Err("peer identity changed while reading request".into());
    }
    let mut frame = prefix.to_vec();
    frame.extend(body);
    let response = server.handle_peer(credentials.uid(), &frame, now);
    stream
        .write_all(&response_frame(&response).map_err(|error| error.to_string())?)
        .map_err(|error| error.to_string())
}

fn receive_no_descriptors(
    stream: &std::os::unix::net::UnixStream,
    bytes: &mut [u8],
) -> Result<(), String> {
    let mut offset = 0;
    while offset < bytes.len() {
        let mut iov = [std::io::IoSliceMut::new(&mut bytes[offset..])];
        let mut cmsg = nix::cmsg_space!([std::os::fd::RawFd; 1]);
        let message = recvmsg::<()>(
            stream.as_raw_fd(),
            &mut iov,
            Some(&mut cmsg),
            nix::sys::socket::MsgFlags::empty(),
        )
        .map_err(|error| error.to_string())?;
        if message.bytes == 0
            || message
                .cmsgs()
                .map_err(|error| error.to_string())?
                .any(|item| matches!(item, ControlMessageOwned::ScmRights(_)))
        {
            return Err("invalid framed request or descriptor injection".into());
        }
        offset += message.bytes;
    }
    Ok(())
}

struct AuthenticatedPeer {
    _pidfd: std::os::fd::OwnedFd,
    pid: i32,
    executable: PathBuf,
    start_time: String,
}

impl AuthenticatedPeer {
    fn still_valid(&self) -> bool {
        read_peer_identity(self.pid)
            .is_ok_and(|(exe, start)| exe == self.executable && start == self.start_time)
    }
}

fn authenticate_peer_process(pid: i32, expected: &Path) -> Result<AuthenticatedPeer, String> {
    let pinned_pid = rustix::process::Pid::from_raw(pid).ok_or("invalid peer PID")?;
    let pidfd = rustix::process::pidfd_open(pinned_pid, rustix::process::PidfdFlags::empty())
        .map_err(|_| "pidfd_open failed")?;
    let (actual, start_time) = read_peer_identity(pid)?;
    if actual != expected {
        return Err("unexpected peer executable".into());
    }
    Ok(AuthenticatedPeer {
        _pidfd: pidfd,
        pid,
        executable: actual,
        start_time,
    })
}

fn read_peer_identity(pid: i32) -> Result<(PathBuf, String), String> {
    let executable = std::fs::read_link(format!("/proc/{pid}/exe")).map_err(|e| e.to_string())?;
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|e| e.to_string())?;
    let start_time = stat
        .rsplit(')')
        .next()
        .and_then(|value| value.split_whitespace().nth(19))
        .ok_or("invalid proc stat")?
        .to_owned();
    Ok((executable, start_time))
}

#[cfg(test)]
mod tests {
    use super::{authenticate_peer_process, receive_no_descriptors};

    #[test]
    fn pins_peer_executable_and_rejects_descriptors() {
        use std::os::fd::AsRawFd;
        let pid = std::process::id() as i32;
        let executable = std::fs::read_link(format!("/proc/{pid}/exe")).unwrap();
        assert!(authenticate_peer_process(pid, &executable).is_ok());
        assert!(authenticate_peer_process(pid, std::path::Path::new("/wrong")).is_err());
        let (receiver, sender) = std::os::unix::net::UnixStream::pair().unwrap();
        let file = std::fs::File::open("/dev/null").unwrap();
        let bytes = 4_u32.to_be_bytes();
        let iov = [std::io::IoSlice::new(&bytes)];
        let rights = [file.as_raw_fd()];
        nix::sys::socket::sendmsg::<()>(
            sender.as_raw_fd(),
            &iov,
            &[nix::sys::socket::ControlMessage::ScmRights(&rights)],
            nix::sys::socket::MsgFlags::empty(),
            None,
        )
        .unwrap();
        assert!(receive_no_descriptors(&receiver, &mut [0; 4]).is_err());
    }
}
