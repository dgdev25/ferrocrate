use crate::{
    protocol::{response_frame, MAX_FRAME_BYTES},
    server::NetdServer,
};
use nix::sys::socket::{
    getsockopt, recvmsg, sockopt::PeerCredentials, ControlMessageOwned, MsgFlags,
};
use std::{
    collections::VecDeque,
    io::Write,
    os::{fd::AsRawFd, unix::net::UnixListener},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultPoint {
    Effect,
    StatePersist,
}

#[derive(Clone, Default)]
pub struct FaultHandle(std::sync::Arc<std::sync::Mutex<VecDeque<FaultPoint>>>);
impl FaultHandle {
    pub fn fail_once(&self, point: FaultPoint) {
        self.0.lock().expect("fault lock").push_back(point);
    }
    pub(crate) fn take(&self, point: FaultPoint) -> bool {
        let mut faults = self.0.lock().expect("fault lock");
        if faults.front() == Some(&point) {
            faults.pop_front();
            true
        } else {
            false
        }
    }
}

/// Serves exactly one bounded request. UID is checked before any request bytes are read.
pub fn serve_one(
    listener: &UnixListener,
    server: &mut NetdServer,
    expected_uid: u32,
    now: u64,
) -> Result<(), String> {
    let (mut stream, _) = listener.accept().map_err(|e| e.to_string())?;
    let credentials = getsockopt(&stream, PeerCredentials).map_err(|e| e.to_string())?;
    if credentials.uid() != expected_uid {
        return Err("unexpected Unix peer UID".into());
    }
    let mut prefix = [0_u8; 4];
    receive_no_fds(&stream, &mut prefix)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length > MAX_FRAME_BYTES {
        return Err("frame exceeds 1 MiB".into());
    }
    let mut body = vec![0; length];
    receive_no_fds(&stream, &mut body)?;
    let mut frame = prefix.to_vec();
    frame.extend(body);
    let response = server.handle_peer(expected_uid, &frame, now);
    stream
        .write_all(&response_frame(&response).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())
}

fn receive_no_fds(stream: &std::os::unix::net::UnixStream, bytes: &mut [u8]) -> Result<(), String> {
    let mut offset = 0;
    while offset < bytes.len() {
        let mut iov = [std::io::IoSliceMut::new(&mut bytes[offset..])];
        let mut cmsg = nix::cmsg_space!([std::os::fd::RawFd; 1]);
        let message = recvmsg::<()>(
            stream.as_raw_fd(),
            &mut iov,
            Some(&mut cmsg),
            MsgFlags::empty(),
        )
        .map_err(|e| e.to_string())?;
        if message.bytes == 0
            || message
                .cmsgs()
                .map_err(|e| e.to_string())?
                .any(|v| matches!(v, ControlMessageOwned::ScmRights(_)))
        {
            return Err("invalid framed request".into());
        }
        offset += message.bytes;
    }
    Ok(())
}
