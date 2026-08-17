use crate::seccomp::{guest_seccomp_profile, SeccompProfile};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AiRuntimeError {
    #[error("token budget exceeded: used {used}, budget {budget}")]
    TokenBudgetExceeded { used: u64, budget: u64 },
    #[error("coherence gate failed: {gate}: {reason}")]
    CoherenceGateFailed { gate: String, reason: String },
    #[error("seccomp error: {0}")]
    Seccomp(#[from] crate::seccomp::SeccompError),
}

/// Authority level for an AI agent container.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Authority {
    /// Restricted: guest seccomp profile, no network syscalls.
    Guest,
    /// Default seccomp profile, standard container isolation.
    #[default]
    User,
    /// Unconfined: no additional seccomp restrictions beyond the default.
    Admin,
}

/// Configuration parsed from the `[ai_runtime]` section of a ferrofile.toml.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiRuntimeConfig {
    #[serde(default)]
    pub authority: Authority,
    /// Maximum number of LLM API tokens the container may consume.
    /// 0 means unlimited.
    #[serde(default)]
    pub token_budget: u64,
    /// Maximum memory in megabytes for the AI model. 0 means unlimited.
    #[serde(default)]
    pub memory_budget_mb: u64,
    /// Pre-run coherence gate assertions. Supported values:
    /// - `"model_loaded"`: requires `FERRO_MODEL_PATH` env var to be set
    /// - `"vector_store_healthy"`: requires `FERRO_VECTOR_STORE_PATH` env var to be set
    #[serde(default)]
    pub coherence_gates: Vec<String>,
}

/// Metered token counter for enforcing `token_budget`.
#[derive(Debug, Clone)]
pub struct TokenBudgetCounter {
    used: Arc<AtomicU64>,
    budget: u64,
}

impl TokenBudgetCounter {
    /// Creates a counter with the given budget. A budget of 0 is unlimited.
    pub fn new(budget: u64) -> Self {
        Self {
            used: Arc::new(AtomicU64::new(0)),
            budget,
        }
    }

    /// Record `count` tokens used. Returns an error if the budget is exceeded.
    pub fn record(&self, count: u64) -> Result<(), AiRuntimeError> {
        if self.budget == 0 {
            return Ok(());
        }
        let mut current = self.used.load(Ordering::Acquire);
        loop {
            let Some(next) = current.checked_add(count) else {
                return Err(AiRuntimeError::TokenBudgetExceeded {
                    used: u64::MAX,
                    budget: self.budget,
                });
            };
            if next > self.budget {
                return Err(AiRuntimeError::TokenBudgetExceeded {
                    used: next,
                    budget: self.budget,
                });
            }
            match self.used.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(observed) => current = observed,
            }
        }
    }

    /// Returns current usage.
    pub fn used(&self) -> u64 {
        self.used.load(Ordering::SeqCst)
    }
}

/// Checks coherence gate assertions against the container's environment variables.
///
/// Supported gates:
/// - `"model_loaded"` — requires `FERRO_MODEL_PATH` in `env`
/// - `"vector_store_healthy"` — requires `FERRO_VECTOR_STORE_PATH` in `env`
pub fn check_coherence_gates(gates: &[String], env: &[String]) -> Result<(), AiRuntimeError> {
    for gate in gates {
        match gate.as_str() {
            "model_loaded" => {
                let present = env.iter().any(|e| e.starts_with("FERRO_MODEL_PATH="));
                if !present {
                    return Err(AiRuntimeError::CoherenceGateFailed {
                        gate: gate.clone(),
                        reason: "FERRO_MODEL_PATH not set".to_string(),
                    });
                }
            }
            "vector_store_healthy" => {
                let present = env
                    .iter()
                    .any(|e| e.starts_with("FERRO_VECTOR_STORE_PATH="));
                if !present {
                    return Err(AiRuntimeError::CoherenceGateFailed {
                        gate: gate.clone(),
                        reason: "FERRO_VECTOR_STORE_PATH not set".to_string(),
                    });
                }
            }
            _ => {
                // Unknown gates are ignored to allow forward-compatibility.
            }
        }
    }
    Ok(())
}

/// Returns additional environment variables to inject into an AI container.
///
/// Always injects `FERRO_AUTHORITY`. Injects `FERRO_TOKEN_BUDGET` if > 0,
/// and `FERRO_MEMORY_BUDGET_MB` if > 0.
pub fn ai_runtime_env(config: &AiRuntimeConfig) -> Vec<String> {
    let authority = match config.authority {
        Authority::Guest => "guest",
        Authority::User => "user",
        Authority::Admin => "admin",
    };
    let mut out = vec![format!("FERRO_AUTHORITY={authority}")];
    if config.token_budget > 0 {
        out.push(format!("FERRO_TOKEN_BUDGET={}", config.token_budget));
    }
    if config.memory_budget_mb > 0 {
        out.push(format!(
            "FERRO_MEMORY_BUDGET_MB={}",
            config.memory_budget_mb
        ));
    }
    out
}

/// Returns the seccomp profile to apply for the given authority level.
///
/// - `Guest` → restricted guest profile (blocks network syscalls)
/// - `User` → `None` (caller uses the default profile)
/// - `Admin` → `None` (caller uses the default profile)
pub fn seccomp_profile_for_authority(
    authority: &Authority,
) -> Result<Option<SeccompProfile>, AiRuntimeError> {
    match authority {
        Authority::Guest => {
            let profile = guest_seccomp_profile()?;
            Ok(Some(profile))
        }
        Authority::User | Authority::Admin => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_budget_unlimited() {
        let counter = TokenBudgetCounter::new(0);
        assert!(counter.record(1_000_000).is_ok());
    }

    #[test]
    fn token_budget_enforced() {
        let counter = TokenBudgetCounter::new(100);
        assert!(counter.record(50).is_ok());
        assert!(counter.record(50).is_ok());
        let err = counter.record(1).unwrap_err();
        assert!(matches!(err, AiRuntimeError::TokenBudgetExceeded { .. }));
    }

    #[test]
    fn token_budget_never_overshoots_under_concurrent_reservations() {
        let counter = Arc::new(TokenBudgetCounter::new(100));
        let mut workers = Vec::new();
        for _ in 0..8 {
            let counter = Arc::clone(&counter);
            workers.push(std::thread::spawn(move || counter.record(15).is_ok()));
        }
        let accepted = workers
            .into_iter()
            .map(|worker| worker.join().expect("worker should finish"))
            .filter(|accepted| *accepted)
            .count();
        assert_eq!(accepted, 6);
        assert_eq!(counter.used(), 90);
        assert!(counter.record(11).is_err());
        assert_eq!(counter.used(), 90);
    }

    #[test]
    fn coherence_gate_model_loaded_passes() {
        let env = vec!["FERRO_MODEL_PATH=/models/llama.gguf".to_string()];
        assert!(check_coherence_gates(&["model_loaded".to_string()], &env).is_ok());
    }

    #[test]
    fn coherence_gate_model_loaded_fails() {
        let env = vec![];
        let err = check_coherence_gates(&["model_loaded".to_string()], &env).unwrap_err();
        assert!(matches!(err, AiRuntimeError::CoherenceGateFailed { .. }));
    }

    #[test]
    fn coherence_gate_vector_store_passes() {
        let env = vec!["FERRO_VECTOR_STORE_PATH=/data/store".to_string()];
        assert!(check_coherence_gates(&["vector_store_healthy".to_string()], &env).is_ok());
    }

    #[test]
    fn coherence_gate_unknown_ignored() {
        let env = vec![];
        assert!(check_coherence_gates(&["future_gate_v99".to_string()], &env).is_ok());
    }

    #[test]
    fn ai_runtime_env_guest_with_budget() {
        let config = AiRuntimeConfig {
            authority: Authority::Guest,
            token_budget: 5000,
            memory_budget_mb: 512,
            coherence_gates: vec![],
        };
        let env = ai_runtime_env(&config);
        assert!(env.contains(&"FERRO_AUTHORITY=guest".to_string()));
        assert!(env.contains(&"FERRO_TOKEN_BUDGET=5000".to_string()));
        assert!(env.contains(&"FERRO_MEMORY_BUDGET_MB=512".to_string()));
    }

    #[test]
    fn ai_runtime_env_omits_zero_budget() {
        let config = AiRuntimeConfig {
            authority: Authority::User,
            token_budget: 0,
            memory_budget_mb: 0,
            coherence_gates: vec![],
        };
        let env = ai_runtime_env(&config);
        assert!(env.contains(&"FERRO_AUTHORITY=user".to_string()));
        assert!(!env.iter().any(|e| e.starts_with("FERRO_TOKEN_BUDGET")));
        assert!(!env.iter().any(|e| e.starts_with("FERRO_MEMORY_BUDGET_MB")));
    }
}
