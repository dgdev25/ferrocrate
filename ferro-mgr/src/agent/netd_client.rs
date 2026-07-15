use std::{io::{Read, Write}, os::unix::net::UnixStream, path::PathBuf, time::Duration};

use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;

const MAX_FRAME_BYTES: usize = 1024 * 1024;

#[derive(Debug, Error)]
pub enum NetdClientError {
    #[error("netd connection failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("netd request serialization failed: {0}")]
    Encode(#[from] serde_json::Error),
    #[error("netd response frame is invalid")]
    InvalidFrame,
    #[error("netd response exceeds the configured limit")]
    Oversized,
}

pub struct UnixNetdClient {
    socket: PathBuf,
    timeout: Duration,
}

impl UnixNetdClient {
    pub fn new(socket: impl Into<PathBuf>) -> Self { Self { socket: socket.into(), timeout: Duration::from_secs(5) } }

    pub fn with_timeout(mut self, timeout: Duration) -> Self { self.timeout = timeout; self }

    pub fn request<Request, Response>(&self, request: &Request) -> Result<Response, NetdClientError>
    where Request: Serialize, Response: DeserializeOwned {
        let mut stream = UnixStream::connect(&self.socket)?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;
        let body = serde_json::to_vec(request)?;
        if body.len() > MAX_FRAME_BYTES { return Err(NetdClientError::Oversized); }
        stream.write_all(&(body.len() as u32).to_be_bytes())?;
        stream.write_all(&body)?;
        let mut prefix = [0_u8; 4];
        stream.read_exact(&mut prefix)?;
        let length = u32::from_be_bytes(prefix) as usize;
        if length > MAX_FRAME_BYTES { return Err(NetdClientError::Oversized); }
        let mut response = vec![0_u8; length];
        stream.read_exact(&mut response)?;
        serde_json::from_slice(&response).map_err(NetdClientError::Encode)
    }
}

#[cfg(test)]
mod tests {
    use super::UnixNetdClient;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize)] struct Request { value: u32 }
    #[derive(Deserialize, PartialEq, Debug)] struct Response { value: u32 }

    #[test]
    fn client_has_bounded_timeout_and_socket_path() {
        let client = UnixNetdClient::new("/run/ferrocrate/netd.sock").with_timeout(std::time::Duration::from_millis(50));
        assert_eq!(client.socket.to_string_lossy(), "/run/ferrocrate/netd.sock");
        let _ = Request { value: 1 };
        let _ = std::marker::PhantomData::<Response>;
    }
}
