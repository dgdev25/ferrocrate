use std::{collections::BTreeMap, sync::Mutex};

use serde::{Deserialize, Serialize};
use rustls::pki_types::{pem::PemObject, CertificateDer};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FleetRole {
    View,
    Operate,
}

impl FleetRole {
    pub fn can_operate(self) -> bool {
        matches!(self, Self::Operate)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserIdentity {
    pub principal: String,
    pub role: FleetRole,
}

#[derive(Debug, Clone)]
struct Session {
    identity: BrowserIdentity,
    expires_at: i64,
}

#[derive(Default)]
pub struct SessionStore {
    sessions: Mutex<BTreeMap<[u8; 32], Session>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mint(
        &self,
        identity: BrowserIdentity,
        now_unix: i64,
        ttl_seconds: i64,
    ) -> Result<String, String> {
        if identity.principal.trim().is_empty() || ttl_seconds <= 0 || ttl_seconds > 900 {
            return Err("fleet session identity or lifetime is invalid".into());
        }
        let mut secret = [0_u8; 32];
        getrandom::fill(&mut secret)
            .map_err(|error| format!("failed to generate fleet session: {error}"))?;
        let token = hex(&secret);
        let digest = Sha256::digest(token.as_bytes()).into();
        self.sessions
            .lock()
            .map_err(|_| "fleet session lock poisoned".to_string())?
            .insert(
                digest,
                Session {
                    identity,
                    expires_at: now_unix.saturating_add(ttl_seconds),
                },
            );
        Ok(token)
    }

    pub fn authenticate(&self, token: &str, now_unix: i64) -> Option<BrowserIdentity> {
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let mut sessions = self.sessions.lock().ok()?;
        sessions.retain(|_, session| session.expires_at > now_unix);
        sessions.get(&digest).map(|session| session.identity.clone())
    }
}

pub fn certificate_principal(pem: &[u8]) -> Result<String, String> {
    let mut reader = std::io::Cursor::new(pem);
    let certificate = CertificateDer::pem_reader_iter(&mut reader)
        .next()
        .transpose()
        .map_err(|error| format!("failed to parse operator certificate: {error}"))?
        .ok_or_else(|| "operator certificate PEM is empty".to_string())?;
    let digest = Sha256::digest(certificate.as_ref());
    Ok(format!("mtls:{}", hex(&digest[..16])))
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}
