//! Single-node workload lifecycle integration.
//!
//! This module wires the existing manager primitives — node enrollment
//! (`crate::enrollment`), deterministic placement (`crate::scheduler`),
//! service discovery (`crate::service_discovery`), and rollout planning
//! (`crate::rollout`) — into one reconciliation loop for a single node:
//!
//! * `identity` — stable node identity and capability record, persisted and
//!   digest-verified on restart.
//! * `workload` — declarative, versioned desired workload specification.
//! * `executor` — authorization-bound instance mutations plus an in-memory
//!   recording executor used by tests.
//! * `journal` — append-only intent/outcome journal with crash recovery.
//! * `supervisor` — the convergence loop: rolling updates with revision
//!   floors, health-driven restarts, and service-catalog publication.
//!
//! Multi-node clustering is out of scope. Every mutation the supervisor
//! issues is signed, verified by the executor, and journaled before and
//! after its effect, so a crash at any boundary converges on restart.

pub mod executor;
pub mod identity;
pub mod journal;
pub mod supervisor;
pub mod workload;
