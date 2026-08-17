//! Deterministic rolling-update planning.
//!
//! This module produces an ordered, side-effect-free plan. Applying a plan
//! still belongs to the authorized controller/agent reconciliation path.

use std::collections::BTreeSet;

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RolloutPolicy {
    /// Maximum number of replacements started in one step.
    pub max_surge: usize,
    /// Maximum number of obsolete instances stopped in one step.
    pub max_unavailable: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RolloutStep {
    pub start: Vec<String>,
    pub stop: Vec<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RolloutError {
    #[error("instance id must not be empty")]
    EmptyId,
    #[error("instance ids must be unique")]
    DuplicateId,
    #[error("max_surge must be non-zero when starting replacements")]
    ZeroSurge,
    #[error("max_unavailable must be non-zero when stopping without a replacement")]
    ZeroUnavailable,
}

/// Build a stable replacement plan from current and desired instance IDs.
///
/// Replacement steps start new instances before stopping their old peers. The
/// planner batches starts and stops according to the supplied policy and never
/// mutates the input vectors. IDs are sorted, making output independent of
/// discovery order.
pub fn plan(
    current: &[String],
    desired: &[String],
    policy: RolloutPolicy,
) -> Result<Vec<RolloutStep>, RolloutError> {
    let current = unique_sorted(current)?;
    let desired = unique_sorted(desired)?;
    let current_set: BTreeSet<_> = current.iter().collect();
    let desired_set: BTreeSet<_> = desired.iter().collect();
    let mut starts: Vec<String> = desired_set
        .difference(&current_set)
        .map(|id| (*id).clone())
        .collect();
    let mut stops: Vec<String> = current_set
        .difference(&desired_set)
        .map(|id| (*id).clone())
        .collect();

    if starts.is_empty() && stops.is_empty() {
        return Ok(Vec::new());
    }
    if !starts.is_empty() && policy.max_surge == 0 {
        return Err(RolloutError::ZeroSurge);
    }
    if starts.is_empty() && !stops.is_empty() && policy.max_unavailable == 0 {
        return Err(RolloutError::ZeroUnavailable);
    }

    let mut steps = Vec::new();
    while !starts.is_empty() || !stops.is_empty() {
        let start_count = if starts.is_empty() {
            0
        } else {
            policy.max_surge.min(starts.len())
        };
        let stop_count = if stops.is_empty() {
            0
        } else if start_count > 0 {
            // A replacement can stop its old peer after the new instances have
            // started, even when max_unavailable is zero.
            policy.max_unavailable.max(1).min(stops.len())
        } else {
            policy.max_unavailable.min(stops.len())
        };
        let step_start = starts.drain(..start_count).collect();
        let step_stop = stops.drain(..stop_count).collect();
        steps.push(RolloutStep {
            start: step_start,
            stop: step_stop,
        });
    }
    Ok(steps)
}

fn unique_sorted(ids: &[String]) -> Result<Vec<String>, RolloutError> {
    let mut result = ids.to_vec();
    if result.iter().any(|id| id.trim().is_empty()) {
        return Err(RolloutError::EmptyId);
    }
    result.sort();
    if result.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(RolloutError::DuplicateId);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).into()).collect()
    }

    #[test]
    fn replacements_start_before_stopping_and_are_stable() {
        let policy = RolloutPolicy {
            max_surge: 1,
            max_unavailable: 0,
        };
        let forward = plan(&ids(&["old-b", "old-a"]), &ids(&["new-b", "new-a"]), policy).unwrap();
        let reverse = plan(&ids(&["old-a", "old-b"]), &ids(&["new-a", "new-b"]), policy).unwrap();
        assert_eq!(forward, reverse);
        assert_eq!(forward[0].start, ids(&["new-a"]));
        assert_eq!(forward[0].stop, ids(&["old-a"]));
        assert_eq!(forward[1].start, ids(&["new-b"]));
    }

    #[test]
    fn scale_down_requires_unavailability_budget() {
        let error = plan(
            &ids(&["a", "b"]),
            &ids(&["a"]),
            RolloutPolicy {
                max_surge: 1,
                max_unavailable: 0,
            },
        )
        .unwrap_err();
        assert_eq!(error, RolloutError::ZeroUnavailable);
    }

    #[test]
    fn duplicate_and_empty_ids_fail_closed() {
        assert_eq!(
            plan(
                &ids(&["a", "a"]),
                &[],
                RolloutPolicy {
                    max_surge: 1,
                    max_unavailable: 1
                }
            ),
            Err(RolloutError::DuplicateId)
        );
        assert_eq!(
            plan(
                &ids(&["a"]),
                &ids(&[""]),
                RolloutPolicy {
                    max_surge: 1,
                    max_unavailable: 1
                }
            ),
            Err(RolloutError::EmptyId)
        );
    }

    #[test]
    fn no_change_is_a_noop() {
        assert!(plan(
            &ids(&["a"]),
            &ids(&["a"]),
            RolloutPolicy {
                max_surge: 0,
                max_unavailable: 0
            }
        )
        .unwrap()
        .is_empty());
    }
}
