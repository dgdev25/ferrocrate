use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Feature {
    Desktop,
    AiAdvanced,
    AiCloud,
    Fleet,
    Compliance,
    PrioritySupport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Plan {
    Free,
    Pro,
    Enterprise,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entitlement {
    pub plan: Plan,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub issued_at: Option<u64>,
    #[serde(default)]
    pub expires_at: Option<u64>,
    #[serde(default)]
    pub features: HashSet<Feature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedEntitlement {
    payload: String,
    signature: String,
}

#[derive(Debug, Error)]
pub enum EntitlementError {
    #[error("entitlement file missing: {0}")]
    MissingFile(String),
    #[error("invalid entitlement json: {0}")]
    InvalidEnvelope(String),
    #[error("invalid entitlement payload: {0}")]
    InvalidPayload(String),
    #[error("invalid entitlement signature format")]
    InvalidSignature,
    #[error("entitlement signature verification failed")]
    SignatureVerificationFailed,
    #[error("FERROCRATE_ENTITLEMENT_PUBKEY is required to verify entitlements")]
    MissingPublicKey,
    #[error("invalid FERROCRATE_ENTITLEMENT_PUBKEY: expected base64 ed25519 public key")]
    InvalidPublicKey,
    #[error("entitlement expired")]
    Expired,
    #[error("feature `{feature}` requires paid entitlement (current plan: {plan})")]
    NotEntitled {
        feature: &'static str,
        plan: &'static str,
    },
}

impl Plan {
    pub fn as_str(self) -> &'static str {
        match self {
            Plan::Free => "free",
            Plan::Pro => "pro",
            Plan::Enterprise => "enterprise",
        }
    }
}

impl Feature {
    pub fn as_str(self) -> &'static str {
        match self {
            Feature::Desktop => "desktop",
            Feature::AiAdvanced => "ai_advanced",
            Feature::AiCloud => "ai_cloud",
            Feature::Fleet => "fleet",
            Feature::Compliance => "compliance",
            Feature::PrioritySupport => "priority_support",
        }
    }
}

impl Entitlement {
    pub fn free() -> Self {
        Self {
            plan: Plan::Free,
            subject: None,
            issued_at: None,
            expires_at: None,
            features: HashSet::new(),
        }
    }

    pub fn is_expired(&self) -> bool {
        let Some(expires_at) = self.expires_at else {
            return false;
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_secs())
            .unwrap_or(0);
        now >= expires_at
    }

    pub fn allows(&self, feature: Feature) -> bool {
        if self.features.contains(&feature) {
            return true;
        }
        match self.plan {
            Plan::Free => false,
            Plan::Pro => matches!(feature, Feature::Desktop | Feature::AiAdvanced),
            Plan::Enterprise => true,
        }
    }
}

pub fn default_entitlement_path() -> PathBuf {
    if let Ok(path) = std::env::var("FERROCRATE_ENTITLEMENT_FILE") {
        return PathBuf::from(path);
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home)
            .join(".ferrocrate")
            .join("entitlement.lic");
    }
    PathBuf::from(".ferrocrate").join("entitlement.lic")
}

pub fn load_entitlement_from_env() -> Result<Option<Entitlement>, EntitlementError> {
    let path = default_entitlement_path();
    if !path.exists() {
        return Ok(None);
    }
    let payload = std::fs::read_to_string(&path)
        .map_err(|_| EntitlementError::MissingFile(path.display().to_string()))?;
    let entitlement = verify_signed_entitlement(&payload)?;
    if entitlement.is_expired() {
        return Err(EntitlementError::Expired);
    }
    Ok(Some(entitlement))
}

pub fn require_feature(feature: Feature) -> Result<Entitlement, EntitlementError> {
    let entitlement = load_entitlement_from_env()?.unwrap_or_else(Entitlement::free);
    if entitlement.is_expired() {
        return Err(EntitlementError::Expired);
    }
    if entitlement.allows(feature) {
        return Ok(entitlement);
    }
    Err(EntitlementError::NotEntitled {
        feature: feature.as_str(),
        plan: entitlement.plan.as_str(),
    })
}

fn verify_signed_entitlement(raw: &str) -> Result<Entitlement, EntitlementError> {
    let envelope = serde_json::from_str::<SignedEntitlement>(raw)
        .map_err(|err| EntitlementError::InvalidEnvelope(err.to_string()))?;
    let pubkey = entitlement_public_key()?;
    let payload_bytes = decode_b64(&envelope.payload)
        .map_err(|err| EntitlementError::InvalidPayload(err.to_string()))?;
    let signature_bytes =
        decode_b64(&envelope.signature).map_err(|_| EntitlementError::InvalidSignature)?;
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|_| EntitlementError::InvalidSignature)?;
    pubkey
        .verify(&payload_bytes, &signature)
        .map_err(|_| EntitlementError::SignatureVerificationFailed)?;
    serde_json::from_slice::<Entitlement>(&payload_bytes)
        .map_err(|err| EntitlementError::InvalidPayload(err.to_string()))
}

fn entitlement_public_key() -> Result<VerifyingKey, EntitlementError> {
    let raw = std::env::var("FERROCRATE_ENTITLEMENT_PUBKEY")
        .map_err(|_| EntitlementError::MissingPublicKey)?;
    let bytes = decode_b64(raw.trim()).map_err(|_| EntitlementError::InvalidPublicKey)?;
    let key_bytes: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| EntitlementError::InvalidPublicKey)?;
    VerifyingKey::from_bytes(&key_bytes).map_err(|_| EntitlementError::InvalidPublicKey)
}

fn decode_b64(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD
        .decode(input)
        .or_else(|_| STANDARD.decode(input))
}

#[cfg(test)]
mod tests {
    use super::{require_feature, Entitlement, Feature, Plan};
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    use std::fs;
    use std::sync::{Mutex, OnceLock};
    use tempfile::TempDir;

    struct ScopedEnv {
        key: &'static str,
        original: Option<String>,
    }

    fn entitlement_env_guard() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    impl ScopedEnv {
        fn set(key: &'static str, value: &str) -> Self {
            let original = std::env::var(key).ok();
            unsafe {
                std::env::set_var(key, value);
            }
            Self { key, original }
        }
    }

    impl Drop for ScopedEnv {
        fn drop(&mut self) {
            if let Some(value) = &self.original {
                unsafe {
                    std::env::set_var(self.key, value);
                }
            } else {
                unsafe {
                    std::env::remove_var(self.key);
                }
            }
        }
    }

    #[test]
    fn free_plan_has_no_paid_features() {
        let entitlement = Entitlement::free();
        assert!(!entitlement.allows(Feature::Desktop));
        assert!(!entitlement.allows(Feature::AiAdvanced));
    }

    #[test]
    fn pro_plan_enables_desktop_and_ai_advanced() {
        let entitlement = Entitlement {
            plan: Plan::Pro,
            subject: Some("test".to_string()),
            issued_at: None,
            expires_at: None,
            features: Default::default(),
        };
        assert!(entitlement.allows(Feature::Desktop));
        assert!(entitlement.allows(Feature::AiAdvanced));
        assert!(!entitlement.allows(Feature::Fleet));
    }

    #[test]
    fn enterprise_plan_enables_all_features() {
        let entitlement = Entitlement {
            plan: Plan::Enterprise,
            subject: Some("test".to_string()),
            issued_at: None,
            expires_at: None,
            features: Default::default(),
        };
        assert!(entitlement.allows(Feature::Desktop));
        assert!(entitlement.allows(Feature::AiCloud));
        assert!(entitlement.allows(Feature::Compliance));
    }

    #[test]
    fn require_feature_fails_closed_without_entitlement() {
        let _guard = entitlement_env_guard();
        let temp = TempDir::new().expect("temp dir");
        let missing = temp.path().join("missing.lic");
        let _path = ScopedEnv::set(
            "FERROCRATE_ENTITLEMENT_FILE",
            missing.to_str().expect("utf8 path"),
        );
        let _pubkey = ScopedEnv::set(
            "FERROCRATE_ENTITLEMENT_PUBKEY",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        );
        let err = require_feature(Feature::Desktop).expect_err("desktop should be gated");
        assert!(err.to_string().contains("requires paid entitlement"));
    }

    #[test]
    fn signed_entitlement_allows_paid_feature() {
        let _guard = entitlement_env_guard();
        let temp = TempDir::new().expect("temp dir");
        let entitlement_path = temp.path().join("entitlement.lic");
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let verify_key = signing_key.verifying_key();
        let pubkey_b64 = BASE64_STANDARD.encode(verify_key.to_bytes());

        let payload = serde_json::to_vec(&Entitlement {
            plan: Plan::Pro,
            subject: Some("acme".to_string()),
            issued_at: Some(1_760_000_000),
            expires_at: None,
            features: [Feature::Desktop, Feature::AiAdvanced]
                .into_iter()
                .collect(),
        })
        .expect("payload json");
        let signature = signing_key.sign(&payload);
        let envelope = serde_json::json!({
            "payload": BASE64_STANDARD.encode(&payload),
            "signature": BASE64_STANDARD.encode(signature.to_bytes()),
        });
        fs::write(
            &entitlement_path,
            serde_json::to_string(&envelope).expect("envelope json"),
        )
        .expect("write entitlement");

        let _path = ScopedEnv::set(
            "FERROCRATE_ENTITLEMENT_FILE",
            entitlement_path.to_str().expect("utf8 path"),
        );
        let _pubkey = ScopedEnv::set("FERROCRATE_ENTITLEMENT_PUBKEY", &pubkey_b64);
        let loaded = require_feature(Feature::Desktop).expect("desktop should be allowed");
        assert_eq!(loaded.plan, Plan::Pro);
    }
}
