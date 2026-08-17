//! Signed provenance envelopes for AI model artifacts.
//!
//! The envelope binds the model family, version, and exact artifact digest to
//! an Ed25519 signer. It is deliberately independent of key storage and remote
//! anchoring so callers can apply their own trust-root and revocation policy.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModelProvenance {
    pub model_type: String,
    pub version: u32,
    pub artifact_sha256: String,
    pub signer_key_id: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProvenanceError {
    #[error("model provenance fields are invalid: {0}")]
    InvalidFields(String),
    #[error("model provenance signature is invalid")]
    InvalidSignature,
}

impl ModelProvenance {
    pub fn sign(
        model_type: impl Into<String>,
        version: u32,
        artifact_sha256: impl Into<String>,
        signer_key_id: impl Into<String>,
        key: &SigningKey,
    ) -> Result<Self, ProvenanceError> {
        let unsigned = Self {
            model_type: model_type.into(),
            version,
            artifact_sha256: artifact_sha256.into(),
            signer_key_id: signer_key_id.into(),
            signature: vec![0; 64],
        };
        unsigned.validate_fields()?;
        let signature = key.sign(&unsigned.payload());
        Ok(Self {
            signature: signature.to_bytes().to_vec(),
            ..unsigned
        })
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<(), ProvenanceError> {
        self.validate_fields()?;
        let signature = Signature::from_slice(&self.signature)
            .map_err(|_| ProvenanceError::InvalidSignature)?;
        key.verify(&self.payload(), &signature)
            .map_err(|_| ProvenanceError::InvalidSignature)
    }

    fn validate_fields(&self) -> Result<(), ProvenanceError> {
        if self.model_type.is_empty() || self.model_type.len() > 128 {
            return Err(ProvenanceError::InvalidFields(
                "model_type must be 1..=128 bytes".into(),
            ));
        }
        if self.signer_key_id.is_empty() || self.signer_key_id.len() > 128 {
            return Err(ProvenanceError::InvalidFields(
                "signer_key_id must be 1..=128 bytes".into(),
            ));
        }
        if self.artifact_sha256.len() != 64
            || !self
                .artifact_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(ProvenanceError::InvalidFields(
                "artifact_sha256 must be a 64-character hexadecimal digest".into(),
            ));
        }
        Ok(())
    }

    fn payload(&self) -> Vec<u8> {
        // Length-prefixing prevents ambiguous concatenation across fields.
        let mut payload = b"ferrocrate-ai-model-provenance-v1\0".to_vec();
        for field in [
            self.model_type.as_bytes(),
            &self.version.to_be_bytes(),
            self.artifact_sha256.as_bytes(),
            self.signer_key_id.as_bytes(),
        ] {
            let length = (field.len() as u64).to_be_bytes();
            payload.extend_from_slice(&length);
            payload.extend_from_slice(field);
        }
        payload
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signs_and_verifies_digest_bound_provenance() {
        let signing = SigningKey::from_bytes(&[7; 32]);
        let provenance = ModelProvenance::sign(
            "resource-predictor",
            4,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "training-key-1",
            &signing,
        )
        .expect("provenance");
        provenance.verify(&signing.verifying_key()).expect("verify");
    }

    #[test]
    fn tampering_or_wrong_key_fails_closed() {
        let signing = SigningKey::from_bytes(&[8; 32]);
        let wrong = SigningKey::from_bytes(&[9; 32]);
        let mut provenance = ModelProvenance::sign(
            "anomaly-detector",
            2,
            "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
            "training-key-2",
            &signing,
        )
        .expect("provenance");
        assert_eq!(
            provenance.verify(&wrong.verifying_key()),
            Err(ProvenanceError::InvalidSignature)
        );
        provenance.version = 3;
        assert_eq!(
            provenance.verify(&signing.verifying_key()),
            Err(ProvenanceError::InvalidSignature)
        );
    }

    #[test]
    fn rejects_malformed_digest_before_signature_work() {
        let signing = SigningKey::from_bytes(&[10; 32]);
        let error = ModelProvenance::sign("model", 1, "not-a-digest", "key", &signing)
            .expect_err("malformed digest");
        assert!(matches!(error, ProvenanceError::InvalidFields(_)));
    }
}
