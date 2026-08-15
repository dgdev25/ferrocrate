use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SinkRequest {
    pub version: u8,
    #[serde(default)]
    pub query_head: bool,
    pub journal_id: [u8; 16],
    pub expected_sequence: u64,
    pub expected_head: [u8; 32],
    pub emergency_nonce: String,
    pub operation_id: [u8; 16],
    pub record: Vec<u8>,
    pub record_hash: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SinkReceipt {
    pub version: u8,
    pub journal_id: [u8; 16],
    pub sequence: u64,
    pub emergency_nonce: String,
    pub operation_id: [u8; 16],
    pub record_hash: [u8; 32],
    pub head: [u8; 32],
    pub signature: Vec<u8>,
}

impl SinkRequest {
    pub fn validate(&self) -> Result<(), String> {
        if self.query_head {
            return if self.version == 1 && self.record.is_empty() {
                Ok(())
            } else {
                Err("invalid emergency sink head query".into())
            };
        }
        if self.version != 1 || self.emergency_nonce.is_empty() || self.emergency_nonce.len() > 128
        {
            return Err("invalid emergency sink request metadata".into());
        }
        if self.record.len() > MAX_FRAME_BYTES / 2
            || Sha256::digest(&self.record).as_slice() != self.record_hash
        {
            return Err("emergency sink record hash mismatch".into());
        }
        Ok(())
    }
}

impl SinkReceipt {
    fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        serde_json::to_vec(&unsigned).map_err(|e| e.to_string())
    }

    pub fn sign(&mut self, key: &SigningKey) -> Result<(), String> {
        self.signature = key.sign(&self.signing_bytes()?).to_bytes().to_vec();
        Ok(())
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<(), String> {
        let signature: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| "invalid sink receipt signature")?;
        key.verify(&self.signing_bytes()?, &Signature::from_bytes(&signature))
            .map_err(|_| "invalid sink receipt signature".into())
    }
}

pub fn write_frame(mut output: impl Write, value: &impl Serialize) -> Result<(), String> {
    let body = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    if body.len() > MAX_FRAME_BYTES {
        return Err("emergency sink frame too large".into());
    }
    output
        .write_all(&(body.len() as u32).to_be_bytes())
        .and_then(|_| output.write_all(&body))
        .map_err(|e| e.to_string())
}

pub fn read_frame<T: for<'de> Deserialize<'de>>(mut input: impl Read) -> Result<T, String> {
    let mut prefix = [0; 4];
    input.read_exact(&mut prefix).map_err(|e| e.to_string())?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length > MAX_FRAME_BYTES {
        return Err("emergency sink frame too large".into());
    }
    let mut body = vec![0; length];
    input.read_exact(&mut body).map_err(|e| e.to_string())?;
    serde_json::from_slice(&body).map_err(|e| e.to_string())
}
