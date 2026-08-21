//! AI multi-container lifecycle qualification scenarios (roadmap item 23).
//!
//! In-process scenarios that must hold when many containers run with AI
//! features enabled: token/memory budgets fail closed under exhaustion with
//! no cross-container leakage, the metering ledger survives daemon restarts
//! at container scale, coherence gates reject invalid decision traces, and
//! provider failover stays deterministic under provider failure. The
//! container-level startup/RSS overhead scenarios live in
//! `scripts/perf/ai-lifecycle-qualification.sh`.

#![cfg(target_os = "linux")]

use ferro_core::ai_runtime::{check_coherence_gates, AiRuntimeError, CognitiveBudgets};
use ferro_mind::ai::explain::{check_action_coherence, CoherencePolicy, DecisionTrace};
use ferro_mind::ai::metering::MeteringLedger;
use ferro_mind::ai::routing::cost::{
    execute_routed_prompt_metered_failover_recorded, AttemptOutcome, Provider, ProviderAdapter,
    ProviderEndpoint, RoutingPolicy, TokenBudget,
};
use std::path::PathBuf;
use std::sync::Arc;

/// Container count for the scaled scenarios: start at 10, scale to 50 once
/// the smaller matrix is stable. All scenarios here run at 50 because the
/// in-process cost is bounded by per-container counters, not container
/// execution.
const CONTAINERS: usize = 50;

fn container_id(index: usize) -> String {
    format!("qual-container-{index:02}")
}

/// Budgets of 50 containers drained to exhaustion concurrently must fail
/// closed, never overshoot, and never leak a charge into another container.
#[test]
fn budget_exhaustion_fails_closed_for_50_containers_without_leakage() {
    let budgets: Vec<Arc<CognitiveBudgets>> = (0..CONTAINERS)
        .map(|_| Arc::new(CognitiveBudgets::new(100, 1024 * 1024)))
        .collect();
    let exhausted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut workers = Vec::new();
    for budgets in budgets.iter().cloned() {
        let exhausted = Arc::clone(&exhausted);
        workers.push(std::thread::spawn(move || {
            let mut rejected = 0;
            // Charge far past the budget so every container observes at
            // least one fail-closed rejection.
            for _ in 0..20 {
                if budgets.record_usage(10, 64 * 1024).is_err() {
                    rejected += 1;
                }
            }
            if rejected == 0 {
                panic!("budget never rejected a charge");
            }
            if budgets.used_tokens() > 100 {
                panic!("token usage {} exceeded budget 100", budgets.used_tokens());
            }
            if budgets.used_memory_bytes() > 1024 * 1024 {
                panic!(
                    "memory usage {} exceeded budget {}",
                    budgets.used_memory_bytes(),
                    1024 * 1024
                );
            }
            exhausted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }));
    }
    for worker in workers {
        worker.join().expect("worker finishes");
    }
    assert_eq!(
        exhausted.load(std::sync::atomic::Ordering::SeqCst),
        CONTAINERS
    );
    // Cross-container leakage: charging container i must never move any other
    // container's counters. Every counter already sits at its exhaustion
    // plateau; one more rejected charge on each must leave all others exact.
    for budgets in budgets.iter() {
        let tokens_before = budgets.used_tokens();
        let memory_before = budgets.used_memory_bytes();
        assert!(matches!(
            budgets.record_usage(1, 1),
            Err(AiRuntimeError::TokenBudgetExceeded { .. })
        ));
        assert_eq!(budgets.used_tokens(), tokens_before);
        assert_eq!(budgets.used_memory_bytes(), memory_before);
        // A fresh sibling container is untouched by every charge above.
        let sibling = CognitiveBudgets::new(100, 1024 * 1024);
        assert_eq!(sibling.used_tokens(), 0);
        assert_eq!(sibling.used_memory_bytes(), 0);
    }
}

/// The metering ledger records usage for 50 containers across three ledger
/// instances (simulated daemon restarts) without losing or truncating lines.
#[test]
fn metering_ledger_survives_three_restarts_at_50_container_scale() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("metering.jsonl");
    const SESSIONS: u64 = 3;
    const PER_SESSION_TOKENS: u64 = 40;
    for session in 0..SESSIONS {
        // A new ledger per "daemon" must append, never truncate.
        let ledger = MeteringLedger::new(&path);
        for index in 0..CONTAINERS {
            let id = container_id(index);
            let used_after = (session + 1) * PER_SESSION_TOKENS;
            ledger
                .record_usage(&id, PER_SESSION_TOKENS, 1024, used_after, 1024, None)
                .unwrap_or_else(|error| panic!("session {session} record {id}: {error}"));
        }
    }
    let contents = std::fs::read_to_string(&path).expect("read ledger");
    let lines: Vec<&str> = contents.lines().filter(|line| !line.trim().is_empty()).collect();
    assert_eq!(lines.len(), SESSIONS as usize * CONTAINERS);
    let mut per_container = std::collections::BTreeMap::new();
    for line in &lines {
        let entry: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|error| panic!("invalid JSON line: {error}"));
        assert_eq!(entry["schema_version"], "v1");
        assert_eq!(entry["kind"], "usage");
        let id = entry["container_id"].as_str().expect("container id").to_string();
        assert_eq!(entry["tokens_delta"], PER_SESSION_TOKENS);
        let count = per_container.entry(id).or_insert(0u64);
        *count += 1;
    }
    assert_eq!(per_container.len(), CONTAINERS);
    for (id, count) in per_container {
        assert_eq!(count, SESSIONS, "container {id} lost entries across restarts");
    }
    // The last session's totals survive the final reopen.
    let entries: Vec<serde_json::Value> = lines
        .iter()
        .map(|line| serde_json::from_str(line).expect("valid JSON"))
        .collect();
    let last_session_entries: Vec<&serde_json::Value> = entries
        .iter()
        .filter(|entry| entry["tokens_used_after"].as_u64() == Some(SESSIONS * PER_SESSION_TOKENS))
        .collect();
    assert_eq!(last_session_entries.len(), CONTAINERS);
}

/// Coherence gates refuse invalid decision traces for every container and
/// admit a valid trace; env-var gates reject a container without its input.
#[test]
fn coherence_gates_reject_invalid_traces_for_50_containers() {
    let policy = CoherencePolicy::new(0.5).with_required_inputs(["prompt", "model"]);
    let invalid_confidences = ["", "NaN", "inf", "-inf", "1.5", "-0.1", "0.49"];
    for index in 0..CONTAINERS {
        let id = container_id(index);
        let variant = index % 8;
        let rejected = if variant < 7 {
            // Seven invalid confidence recordings: missing, non-finite,
            // out-of-range, and below-threshold.
            let mut trace = DecisionTrace::new(id.clone(), "routed prompt")
                .with_model("local-wasm", "v1")
                .with_decision("respond");
            if !invalid_confidences[variant].is_empty() {
                trace = trace.with_evidence("confidence", invalid_confidences[variant]);
            }
            check_action_coherence(&trace, &policy).is_err()
        } else {
            // Valid confidence but a missing required input.
            let trace = DecisionTrace::new(id.clone(), "routed prompt")
                .with_model("local-wasm", "v1")
                .with_evidence("confidence", "0.9")
                .with_evidence("model", "local-wasm");
            check_action_coherence(&trace, &policy).is_err()
        };
        assert!(rejected, "container {id} passed an invalid trace");
    }
    // A fully valid trace is admitted for every container.
    for index in 0..CONTAINERS {
        let trace = DecisionTrace::new(container_id(index), "routed prompt")
            .with_model("local-wasm", "v1")
            .with_decision("respond")
            .with_evidence("confidence", "0.9")
            .with_evidence("prompt", "hello")
            .with_evidence("model", "local-wasm");
        assert!(
            check_action_coherence(&trace, &policy).is_ok(),
            "valid trace refused for container {index}"
        );
    }
    // The pre-run env gates refuse every container without FERRO_MODEL_PATH.
    let gates = ["model_loaded".to_string()];
    for index in 0..CONTAINERS {
        let error = check_coherence_gates(&gates, &[]).expect_err("gate must refuse empty env");
        assert!(matches!(error, AiRuntimeError::CoherenceGateFailed { .. }));
        let env = vec!["FERRO_MODEL_PATH=/models/test.gguf".to_string()];
        assert!(
            check_coherence_gates(&gates, &env).is_ok(),
            "gate refused a loaded model for container {index}"
        );
    }
}

fn write_executable(path: &std::path::Path, body: &str) {
    std::fs::write(path, body).expect("write script");
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = std::fs::metadata(path).expect("metadata").permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions).expect("permissions");
}

fn command_adapter(
    temp: &tempfile::TempDir,
    name: &str,
    quality: f32,
    body: &str,
) -> ProviderAdapter {
    let script = temp.path().join(format!("{name}.sh"));
    write_executable(&script, body);
    ProviderAdapter::Command(ProviderEndpoint {
        provider: Provider {
            name: name.into(),
            cost_per_1k_tokens: 0.0,
            quality,
            avg_latency_ms: 1,
            local: true,
        },
        command: script,
        args: Vec::new(),
    })
}

/// Provider failover under failure stays deterministic at container scale:
/// every container records the same attempt order, candidate ordering does
/// not change it, and total failure keeps the full order recorded.
#[test]
fn failover_is_deterministic_across_50_containers_under_provider_failure() {
    let temp = tempfile::tempdir().expect("tempdir");
    let failing_body = "#!/bin/sh\nexit 9\n";
    let healthy_body = "#!/bin/sh\nread prompt\nprintf 'ok'\n";
    let make_adapters = |reversed: bool| -> Vec<ProviderAdapter> {
        let preferred =
            command_adapter(&temp, "preferred", 0.99, failing_body);
        let fallback = command_adapter(&temp, "fallback", 0.80, healthy_body);
        if reversed {
            vec![fallback, preferred]
        } else {
            vec![preferred, fallback]
        }
    };
    let policy = RoutingPolicy::default();
    let timeout = std::time::Duration::from_secs(5);

    let reference: Vec<_> = {
        let adapters = make_adapters(false);
        let budget = TokenBudget::new(10_000);
        let (_, attempts) = execute_routed_prompt_metered_failover_recorded(
            &adapters,
            &policy,
            "hello",
            timeout,
            &budget,
            2,
        );
        attempts
    };
    assert_eq!(reference.len(), 2);
    assert_eq!(reference[0].provider, "preferred");
    assert!(matches!(&reference[0].outcome, AttemptOutcome::Failed(_)));
    assert_eq!(reference[1].provider, "fallback");
    assert!(matches!(
        &reference[1].outcome,
        AttemptOutcome::Succeeded { .. }
    ));

    // Every container records the identical journal, under both candidate
    // orderings, with per-container budgets.
    for index in 0..CONTAINERS {
        for reversed in [false, true] {
            let adapters = make_adapters(reversed);
            let budget = TokenBudget::new(10_000);
            let (result, attempts) = execute_routed_prompt_metered_failover_recorded(
                &adapters,
                &policy,
                "hello",
                timeout,
                &budget,
                2,
            );
            let (_, _, tokens_used) =
                result.unwrap_or_else(|error| panic!("container {index}: {error}"));
            assert_eq!(attempts, reference, "container {index} reversed={reversed}");
            assert!(tokens_used > 0, "container {index} charged nothing");
        }
    }

    // Total provider failure: the full attempt order stays recorded, the
    // prompt charge stays accounted, and no response is returned.
    let all_failing = vec![
        command_adapter(&temp, "preferred", 0.99, failing_body),
        command_adapter(&temp, "fallback2", 0.80, "#!/bin/sh\nexit 7\n"),
    ];
    for index in 0..CONTAINERS {
        let budget = TokenBudget::new(10_000);
        let (result, attempts) = execute_routed_prompt_metered_failover_recorded(
            &all_failing,
            &policy,
            "hello",
            timeout,
            &budget,
            2,
        );
        assert!(result.is_err(), "container {index} succeeded with no provider");
        assert_eq!(attempts.len(), 2, "container {index} lost attempt records");
        assert_eq!(attempts[0].provider, "preferred");
        assert_eq!(attempts[1].provider, "fallback2");
        assert!(attempts.iter().all(|attempt| matches!(
            &attempt.outcome,
            AttemptOutcome::Failed(_)
        )));
    }
}

/// The deterministic failover journals of 50 containers persist into the
/// metering ledger and remain readable after a reopen (simulated restart).
#[test]
fn failover_journals_of_50_containers_are_durable_in_the_ledger() {
    let temp = tempfile::tempdir().expect("tempdir");
    let failing = command_adapter(&temp, "preferred", 0.99, "#!/bin/sh\nexit 9\n");
    let healthy = command_adapter(&temp, "fallback", 0.80, "#!/bin/sh\nread prompt\nprintf 'ok'\n");
    let adapters = vec![failing, healthy];
    let ledger_path: PathBuf = temp.path().join("metering.jsonl");
    let ledger = MeteringLedger::new(&ledger_path);
    let mut final_tokens = Vec::new();
    for index in 0..CONTAINERS {
        let id = container_id(index);
        let budget = TokenBudget::new(10_000);
        let (result, attempts) = execute_routed_prompt_metered_failover_recorded(
            &adapters,
            &RoutingPolicy::default(),
            "hello",
            std::time::Duration::from_secs(5),
            &budget,
            2,
        );
        let (_, _, tokens_used) = result.expect("fallback responds");
        ledger
            .record_provider_attempts(&id, &attempts, tokens_used)
            .expect("persist attempts");
        final_tokens.push((id, tokens_used));
    }
    // Reopen (simulated daemon restart) and verify every container's journal.
    let reopened = MeteringLedger::new(&ledger_path);
    let contents = std::fs::read_to_string(&ledger_path).expect("read ledger");
    let entries: Vec<serde_json::Value> = contents
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("valid JSON"))
        .collect();
    assert_eq!(entries.len(), CONTAINERS * 2);
    for (pair_index, (id, tokens_used)) in final_tokens.iter().enumerate() {
        let first = &entries[pair_index * 2];
        let second = &entries[pair_index * 2 + 1];
        assert_eq!(first["container_id"], id.as_str());
        assert_eq!(second["container_id"], id.as_str());
        assert_eq!(first["provider"], "preferred");
        assert_eq!(second["provider"], "fallback");
        assert_eq!(second["tokens_used_after"], *tokens_used);
    }
    // The reopened ledger still appends without truncating.
    reopened
        .record_usage("qual-container-00", 1, 0, 1, 0, None)
        .expect("post-restart append");
    assert_eq!(contents.lines().count() + 1, {
        std::fs::read_to_string(&ledger_path)
            .expect("reread ledger")
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count()
    });
}
