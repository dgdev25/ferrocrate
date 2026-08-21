#[cfg(target_os = "linux")]
use crate::seccomp::{guest_seccomp_profile, SeccompProfile};
#[cfg(not(target_os = "linux"))]
#[derive(Debug, Clone)]
pub struct SeccompProfile;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AiRuntimeError {
    #[error("token budget exceeded: used {used}, budget {budget}")]
    TokenBudgetExceeded { used: u64, budget: u64 },
    #[error("memory budget exceeded: used {used} bytes, budget {budget} bytes")]
    MemoryBudgetExceeded { used: u64, budget: u64 },
    #[error("coherence gate failed: {gate}: {reason}")]
    CoherenceGateFailed { gate: String, reason: String },
    #[cfg(target_os = "linux")]
    #[error("seccomp error: {0}")]
    Seccomp(#[from] crate::seccomp::SeccompError),
    #[error("model backend failed: {0}")]
    ModelBackend(String),
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

impl Authority {
    /// Total order over authority levels: `Guest` (0) grants the least
    /// authority and `Admin` (2) the most. Callers use the rank to prove that
    /// granting more authority never weakens the seccomp profile.
    pub fn rank(&self) -> u8 {
        match self {
            Authority::Guest => 0,
            Authority::User => 1,
            Authority::Admin => 2,
        }
    }
}

/// The set of syscalls a profile permits.
///
/// An allow-by-default profile (`defaultAction == SCMP_ACT_ALLOW`) permits
/// every syscall except its explicitly denied names, which is represented as
/// `All` paired with the explicit deny list. A deny-by-default profile permits
/// only its explicitly allowed names.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
enum AllowedSyscalls {
    All,
    Explicit(std::collections::BTreeSet<String>),
}

#[cfg(target_os = "linux")]
fn denied_names(profile: &SeccompProfile) -> std::collections::BTreeSet<String> {
    profile
        .syscalls
        .iter()
        .filter(|rule| rule.action != "SCMP_ACT_ALLOW")
        .flat_map(|rule| rule.names.iter().cloned())
        .collect()
}

#[cfg(target_os = "linux")]
fn allowed_syscalls(profile: &SeccompProfile) -> AllowedSyscalls {
    let explicit = profile
        .syscalls
        .iter()
        .filter(|rule| rule.action == "SCMP_ACT_ALLOW")
        .flat_map(|rule| rule.names.iter().cloned())
        .collect();
    if profile.default_action == "SCMP_ACT_ALLOW" {
        AllowedSyscalls::All
    } else {
        AllowedSyscalls::Explicit(explicit)
    }
}

/// Returns true when `strict` permits at most the syscalls `relaxed` permits.
///
/// Every syscall allowed by `strict` must also be allowed by `relaxed`. Two
/// allow-by-default profiles compare through their deny lists: `strict` must
/// deny every name `relaxed` denies.
#[cfg(target_os = "linux")]
pub fn profile_is_at_least_as_strict(
    strict: &SeccompProfile,
    relaxed: &SeccompProfile,
) -> bool {
    match (allowed_syscalls(strict), allowed_syscalls(relaxed)) {
        (AllowedSyscalls::All, AllowedSyscalls::All) => {
            denied_names(relaxed).is_subset(&denied_names(strict))
        }
        // An allow-by-default profile can never be at most a
        // deny-by-default profile's smaller explicit set.
        (AllowedSyscalls::All, AllowedSyscalls::Explicit(_)) => false,
        (AllowedSyscalls::Explicit(names), AllowedSyscalls::All) => {
            names.is_disjoint(&denied_names(relaxed))
        }
        (AllowedSyscalls::Explicit(names), AllowedSyscalls::Explicit(other)) => {
            names.is_subset(&other)
        }
    }
}

/// Returns the profile the authority mapping grants for comparison purposes:
/// `Guest` maps to the restricted guest profile, `User` and `Admin` map to the
/// standard default profile. Used to check that the authority-to-seccomp
/// mapping is monotone: a higher authority must never produce a weaker
/// profile.
#[cfg(target_os = "linux")]
fn comparison_profile_for_authority(
    authority: &Authority,
) -> Result<SeccompProfile, AiRuntimeError> {
    match authority {
        Authority::Guest => Ok(crate::seccomp::guest_seccomp_profile()?),
        Authority::User | Authority::Admin => Ok(crate::seccomp::default_seccomp_profile()?),
    }
}

/// Checks the authority-to-seccomp mapping invariant: for every pair of
/// authority levels where `lower.rank() <= higher.rank()`, the profile granted
/// to `lower` is at least as strict as the profile granted to `higher`.
/// Returns an error naming the violating pair when the invariant breaks.
#[cfg(target_os = "linux")]
pub fn authority_seccomp_mapping_is_monotone() -> Result<(), AiRuntimeError> {
    let levels = [Authority::Guest, Authority::User, Authority::Admin];
    for lower in &levels {
        for higher in &levels {
            if lower.rank() > higher.rank() {
                continue;
            }
            let lower_profile = comparison_profile_for_authority(lower)?;
            let higher_profile = comparison_profile_for_authority(higher)?;
            if !profile_is_at_least_as_strict(&lower_profile, &higher_profile) {
                return Err(AiRuntimeError::ModelBackend(format!(
                    "authority-to-seccomp mapping is not monotone: {lower:?} (rank {}) grants a weaker profile than {higher:?} (rank {})",
                    lower.rank(),
                    higher.rank()
                )));
            }
        }
    }
    Ok(())
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

    /// Releases a prior charge (for example after a rollback). Concurrent
    /// reservations by other threads are preserved; the counter never
    /// underflows.
    pub fn release(&self, count: u64) {
        let mut current = self.used.load(Ordering::Acquire);
        loop {
            let next = current.saturating_sub(count);
            match self.used.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(observed) => current = observed,
            }
        }
    }
}

/// Metered memory counter for enforcing `memory_budget_mb` against model
/// state. Same fail-closed semantics as `TokenBudgetCounter`: a budget of 0 is
/// unlimited, an over-budget charge is rejected without moving the counter,
/// and overflow fails closed.
#[derive(Debug, Clone)]
pub struct MemoryBudgetCounter {
    used: Arc<AtomicU64>,
    budget: u64,
}

impl MemoryBudgetCounter {
    /// Creates a counter with the given budget in bytes. A budget of 0 is
    /// unlimited.
    pub fn new(budget: u64) -> Self {
        Self {
            used: Arc::new(AtomicU64::new(0)),
            budget,
        }
    }

    /// Charges `bytes` of model-state memory. Returns an error without
    /// changing usage when the budget would be exceeded.
    pub fn record(&self, bytes: u64) -> Result<(), AiRuntimeError> {
        if self.budget == 0 {
            return Ok(());
        }
        let mut current = self.used.load(Ordering::Acquire);
        loop {
            let Some(next) = current.checked_add(bytes) else {
                return Err(AiRuntimeError::MemoryBudgetExceeded {
                    used: u64::MAX,
                    budget: self.budget,
                });
            };
            if next > self.budget {
                return Err(AiRuntimeError::MemoryBudgetExceeded {
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

    /// Returns current usage in bytes.
    pub fn used(&self) -> u64 {
        self.used.load(Ordering::SeqCst)
    }

    /// Releases a prior charge when model state is released. The counter never
    /// underflows.
    pub fn release(&self, bytes: u64) {
        let mut current = self.used.load(Ordering::Acquire);
        loop {
            let next = current.saturating_sub(bytes);
            match self.used.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(observed) => current = observed,
            }
        }
    }
}

/// Per-container cognitive budget pairing the token budget with a memory
/// budget for model state. Charging both is transactional: when the memory
/// budget rejects the charge, the already-applied token charge is rolled back
/// so both counters stay exact.
#[derive(Debug, Clone)]
pub struct CognitiveBudgets {
    pub tokens: TokenBudgetCounter,
    pub memory: MemoryBudgetCounter,
}

impl CognitiveBudgets {
    /// Creates budgets from the raw `AiRuntimeConfig` fields. A zero budget is
    /// unlimited (matching the config semantics).
    pub fn from_config(config: &AiRuntimeConfig) -> Self {
        Self::new(config.token_budget, config.memory_budget_mb.saturating_mul(1024 * 1024))
    }

    /// Creates budgets from raw values. `token_budget` is a token count and
    /// `memory_budget_bytes` a byte count; zero means unlimited.
    pub fn new(token_budget: u64, memory_budget_bytes: u64) -> Self {
        Self {
            tokens: TokenBudgetCounter::new(token_budget),
            memory: MemoryBudgetCounter::new(memory_budget_bytes),
        }
    }

    /// Charges token and model-state memory usage together, fail-closed. If
    /// the memory budget rejects the charge, the token charge is rolled back.
    pub fn record_usage(&self, tokens: u64, memory_bytes: u64) -> Result<(), AiRuntimeError> {
        self.tokens.record(tokens)?;
        if let Err(error) = self.memory.record(memory_bytes) {
            self.tokens.release(tokens);
            return Err(error);
        }
        Ok(())
    }

    /// Releases model-state memory without touching token accounting.
    pub fn release_memory(&self, memory_bytes: u64) {
        self.memory.release(memory_bytes);
    }

    /// Current token usage.
    pub fn used_tokens(&self) -> u64 {
        self.tokens.used()
    }

    /// Current model-state memory usage in bytes.
    pub fn used_memory_bytes(&self) -> u64 {
        self.memory.used()
    }
}

/// Local adapter that enforces a token budget around a model backend.
///
/// The backend remains caller-supplied so the core runtime never makes an
/// implicit network call or embeds provider credentials. Backends return the
/// generated text and the provider-reported completion-token count; prompt
/// tokens are supplied by the caller using the provider's tokenizer. Prompt
/// usage is charged before invocation and completion usage is charged before
/// the response is released, so an over-budget response is fail-closed.
#[derive(Debug, Clone)]
pub struct MeteredModelProxy {
    counter: TokenBudgetCounter,
}

impl MeteredModelProxy {
    pub fn new(token_budget: u64) -> Self {
        Self {
            counter: TokenBudgetCounter::new(token_budget),
        }
    }

    pub fn used_tokens(&self) -> u64 {
        self.counter.used()
    }

    pub fn invoke<F>(
        &self,
        prompt: &str,
        prompt_tokens: u64,
        backend: F,
    ) -> Result<String, AiRuntimeError>
    where
        F: FnOnce(&str) -> Result<(String, u64), String>,
    {
        self.counter.record(prompt_tokens)?;
        let (response, completion_tokens) =
            backend(prompt).map_err(AiRuntimeError::ModelBackend)?;
        self.counter.record(completion_tokens)?;
        Ok(response)
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
                let present = env_value_is_nonempty(env, "FERRO_MODEL_PATH");
                if !present {
                    return Err(AiRuntimeError::CoherenceGateFailed {
                        gate: gate.clone(),
                        reason: "FERRO_MODEL_PATH not set".to_string(),
                    });
                }
            }
            "vector_store_healthy" => {
                let present = env_value_is_nonempty(env, "FERRO_VECTOR_STORE_PATH");
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

fn env_value_is_nonempty(env: &[String], key: &str) -> bool {
    env.iter().any(|entry| {
        entry
            .strip_prefix(key)
            .and_then(|value| value.strip_prefix('='))
            .is_some_and(|value| !value.trim().is_empty())
    })
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
    #[cfg(not(target_os = "linux"))]
    if matches!(authority, Authority::Guest) {
        return Err(AiRuntimeError::ModelBackend(
            "guest seccomp profiles are unsupported on this platform".to_string(),
        ));
    }
    match authority {
        Authority::Guest => {
            #[cfg(target_os = "linux")]
            {
                let profile = guest_seccomp_profile()?;
                Ok(Some(profile))
            }
            #[cfg(not(target_os = "linux"))]
            {
                unreachable!("non-Linux guest authority returned above")
            }
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
    fn metered_proxy_accounts_prompt_and_completion_before_release() {
        let proxy = MeteredModelProxy::new(10);
        let response = proxy
            .invoke("hello", 4, |prompt| Ok((format!("{prompt} world"), 5)))
            .expect("within budget");
        assert_eq!(response, "hello world");
        assert_eq!(proxy.used_tokens(), 9);
    }

    #[test]
    fn metered_proxy_rejects_completion_that_exceeds_budget() {
        let proxy = MeteredModelProxy::new(5);
        let error = proxy
            .invoke("hello", 4, |_| Ok(("response".to_string(), 2)))
            .unwrap_err();
        assert!(matches!(error, AiRuntimeError::TokenBudgetExceeded { .. }));
        assert_eq!(proxy.used_tokens(), 4);
    }

    #[test]
    fn metered_proxy_charges_prompt_but_never_hides_backend_failure() {
        let proxy = MeteredModelProxy::new(10);
        let error = proxy
            .invoke("hello", 3, |_| Err("provider unavailable".to_string()))
            .unwrap_err();
        assert!(
            matches!(error, AiRuntimeError::ModelBackend(message) if message == "provider unavailable")
        );
        assert_eq!(proxy.used_tokens(), 3);
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
    fn coherence_gate_model_loaded_rejects_empty_path() {
        let env = vec!["FERRO_MODEL_PATH=  ".to_string()];
        let err = check_coherence_gates(&["model_loaded".to_string()], &env).unwrap_err();
        assert!(matches!(err, AiRuntimeError::CoherenceGateFailed { .. }));
    }

    #[test]
    fn coherence_gate_vector_store_passes() {
        let env = vec!["FERRO_VECTOR_STORE_PATH=/data/store".to_string()];
        assert!(check_coherence_gates(&["vector_store_healthy".to_string()], &env).is_ok());
    }

    #[test]
    fn coherence_gate_vector_store_rejects_empty_path() {
        let env = vec!["FERRO_VECTOR_STORE_PATH=".to_string()];
        let err = check_coherence_gates(&["vector_store_healthy".to_string()], &env).unwrap_err();
        assert!(matches!(err, AiRuntimeError::CoherenceGateFailed { .. }));
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

    #[test]
    fn memory_budget_unlimited() {
        let counter = MemoryBudgetCounter::new(0);
        assert!(counter.record(u64::MAX).is_ok());
    }

    #[test]
    fn memory_budget_enforced_fail_closed() {
        let counter = MemoryBudgetCounter::new(1024);
        assert!(counter.record(512).is_ok());
        let err = counter.record(513).unwrap_err();
        assert!(matches!(err, AiRuntimeError::MemoryBudgetExceeded { .. }));
        // Fail-closed: the rejected charge must not move the counter.
        assert_eq!(counter.used(), 512);
    }

    #[test]
    fn memory_budget_rejects_overflow() {
        let counter = MemoryBudgetCounter::new(u64::MAX);
        // A charge equal to the maximum budget still fits...
        assert!(counter.record(u64::MAX).is_ok());
        // ...but any further byte overflows the counter and fails closed.
        let err = counter.record(1).unwrap_err();
        assert!(matches!(err, AiRuntimeError::MemoryBudgetExceeded { .. }));
        assert_eq!(counter.used(), u64::MAX);
    }

    #[test]
    fn memory_budget_never_overshoots_under_concurrent_charges() {
        let counter = std::sync::Arc::new(MemoryBudgetCounter::new(100));
        let mut workers = Vec::new();
        for _ in 0..8 {
            let counter = counter.clone();
            workers.push(std::thread::spawn(move || counter.record(15).is_ok()));
        }
        let accepted = workers
            .into_iter()
            .map(|worker| worker.join().expect("worker should finish"))
            .filter(|accepted| *accepted)
            .count();
        assert_eq!(accepted, 6);
        assert_eq!(counter.used(), 90);
    }

    #[test]
    fn memory_budget_release_never_underflows() {
        let counter = MemoryBudgetCounter::new(100);
        counter.record(50).expect("charge");
        counter.release(80);
        assert_eq!(counter.used(), 0);
    }

    #[test]
    fn cognitive_budgets_reject_memory_and_roll_back_tokens() {
        let budgets = CognitiveBudgets::new(1000, 1024);
        assert!(budgets.record_usage(100, 512).is_ok());
        let err = budgets.record_usage(100, 600).unwrap_err();
        assert!(matches!(err, AiRuntimeError::MemoryBudgetExceeded { .. }));
        // The token charge of the rejected call is rolled back exactly.
        assert_eq!(budgets.used_tokens(), 100);
        assert_eq!(budgets.used_memory_bytes(), 512);
    }

    #[test]
    fn cognitive_budgets_token_exhaustion_keeps_memory_unchanged() {
        let budgets = CognitiveBudgets::new(100, 1024);
        budgets.record_usage(100, 512).expect("first charge");
        let err = budgets.record_usage(1, 512).unwrap_err();
        assert!(matches!(err, AiRuntimeError::TokenBudgetExceeded { .. }));
        assert_eq!(budgets.used_tokens(), 100);
        assert_eq!(budgets.used_memory_bytes(), 512);
    }

    #[test]
    fn cognitive_budgets_from_config_converts_mb_to_bytes() {
        let config = AiRuntimeConfig {
            authority: Authority::User,
            token_budget: 5000,
            memory_budget_mb: 2,
            coherence_gates: vec![],
        };
        let budgets = CognitiveBudgets::from_config(&config);
        // A charge equal to the full 2 MB budget fits; one byte more fails closed.
        assert!(budgets.record_usage(0, 2 * 1024 * 1024).is_ok());
        assert!(budgets.record_usage(0, 1).is_err());
        budgets.release_memory(2 * 1024 * 1024);
        assert_eq!(budgets.used_memory_bytes(), 0);
    }

    #[test]
    fn authority_rank_orders_guest_below_user_below_admin() {
        assert!(Authority::Guest.rank() < Authority::User.rank());
        assert!(Authority::User.rank() < Authority::Admin.rank());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn authority_to_seccomp_mapping_is_monotone() {
        authority_seccomp_mapping_is_monotone()
            .expect("higher authority must never produce a weaker seccomp profile");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn guest_profile_is_stricter_than_default_profile() {
        let guest = crate::seccomp::guest_seccomp_profile().expect("guest profile");
        let default = crate::seccomp::default_seccomp_profile().expect("default profile");
        assert!(profile_is_at_least_as_strict(&guest, &default));
        // The asymmetry is real: the default profile allows strictly more,
        // for example network syscalls the guest profile denies.
        assert!(!profile_is_at_least_as_strict(&default, &guest));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn profile_strictness_comparison_covers_allow_by_default_pairs() {
        use crate::seccomp::{parse_seccomp_profile, SyscallRule};
        let base = parse_seccomp_profile(
            r#"{"defaultAction":"SCMP_ACT_ALLOW","architectures":["SCMP_ARCH_X86_64"],"syscalls":[]}"#,
        )
        .expect("base profile");
        let denies_more = SeccompProfile {
            syscalls: vec![SyscallRule {
                names: vec!["reboot".to_string(), "bpf".to_string()],
                action: "SCMP_ACT_ERRNO".to_string(),
                errno_ret: None,
                args: None,
            }],
            ..base.clone()
        };
        let denies_less = SeccompProfile {
            syscalls: vec![SyscallRule {
                names: vec!["bpf".to_string()],
                action: "SCMP_ACT_ERRNO".to_string(),
                errno_ret: None,
                args: None,
            }],
            ..base.clone()
        };
        // An allow-by-default profile is stricter when it denies a superset.
        assert!(profile_is_at_least_as_strict(&denies_more, &denies_less));
        assert!(!profile_is_at_least_as_strict(&denies_less, &denies_more));
        assert!(profile_is_at_least_as_strict(&denies_more, &denies_more));
        // The deny-by-default guest profile is never at most an allow-by-default
        // profile's complement comparison in the weak direction.
        let guest = crate::seccomp::guest_seccomp_profile().expect("guest profile");
        assert!(!profile_is_at_least_as_strict(&base, &guest));
    }
}
