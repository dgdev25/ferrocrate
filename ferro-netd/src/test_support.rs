use crate::{
    grants::{GrantPhase, GrantVerifier},
    policy::Policy,
    protocol::{response_frame, MAX_FRAME_BYTES},
    server::NetdServer,
};
use nix::sys::socket::{
    getsockopt, recvmsg, sockopt::PeerCredentials, ControlMessageOwned, MsgFlags,
};
use std::{
    collections::{BTreeMap, VecDeque},
    io::Write,
    os::{fd::AsRawFd, unix::net::UnixListener},
    path::PathBuf,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantReceiptSummary {
    pub request_id: String,
    pub nonce: [u8; 16],
    pub result_identity: Option<String>,
    pub outcome: Option<String>,
    pub phase: String,
}
impl GrantVerifier {
    pub fn receipt_summaries(&self) -> Vec<GrantReceiptSummary> {
        self.ledger
            .state
            .consumed
            .values()
            .map(|operation| {
                let result = self.ledger.state.results.get(&operation.claims.request_id);
                GrantReceiptSummary {
                    request_id: operation.claims.request_id.clone(),
                    nonce: operation.claims.nonce,
                    result_identity: result.map(|v| v.result_identity.clone()),
                    outcome: result.map(|v| v.outcome.clone()),
                    phase: match operation.phase {
                        GrantPhase::Pending => "pending",
                        GrantPhase::ConsumedBeforeEffect => "consumed-before-effect",
                        GrantPhase::Succeeded => "succeeded",
                        GrantPhase::Failed => "failed",
                        GrantPhase::OutcomeUnknown => "outcome-unknown",
                    }
                    .into(),
                }
            })
            .collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetdTestSnapshot {
    pub overlays: Vec<String>,
    pub endpoints: BTreeMap<String, String>,
    pub routes: BTreeMap<String, Vec<String>>,
    pub receipts: Vec<GrantReceiptSummary>,
    pub quarantined: Vec<String>,
    pub intents: BTreeMap<String, String>,
    pub topology_exact: bool,
    pub ownership_consistent: bool,
}
impl NetdServer {
    pub fn deterministic(uid: u32, policy: Policy, kernel_state: PathBuf) -> Self {
        Self::deterministic_with_faults(uid, policy, kernel_state, Default::default())
    }
    pub fn deterministic_with_faults(
        uid: u32,
        policy: Policy,
        kernel_state: PathBuf,
        faults: FaultHandle,
    ) -> Self {
        let mut server = Self::new(uid, policy);
        server.kernel = Box::new(
            crate::kernel_ops::deterministic::PersistentKernelOps::with_faults(
                kernel_state,
                faults.clone(),
            ),
        );
        server.test_faults = faults;
        server
    }
    pub fn test_snapshot(&self) -> NetdTestSnapshot {
        let topology_exact = self.effect_receipts.values().all(|receipt| {
            self.kernel.observe_effect(receipt) == crate::kernel_ops::LiveEffectObservation::Exact
        });
        let ownership_consistent = self.overlays.iter().all(|overlay| {
            self.effect_receipts
                .contains_key(&format!("overlay:{overlay}"))
        }) && self.endpoints.keys().all(|endpoint| {
            self.effect_receipts
                .contains_key(&format!("endpoint:{endpoint}"))
        });
        NetdTestSnapshot {
            overlays: self.overlays.iter().cloned().collect(),
            endpoints: self.endpoints.clone(),
            routes: self.routes.clone(),
            receipts: self
                .grants
                .as_ref()
                .map(GrantVerifier::receipt_summaries)
                .unwrap_or_default(),
            quarantined: self.quarantined.iter().cloned().collect(),
            intents: self
                .overlay_intents
                .iter()
                .map(|(identity, intent)| (identity.clone(), intent.phase.clone()))
                .collect(),
            topology_exact,
            ownership_consistent,
        }
    }
}

pub fn normalized_request_parameters(
    request: &crate::protocol::NetdRequest,
) -> Result<
    (
        ferro_core::authorization::helper_grant::GrantAction,
        ferro_core::authorization::helper_grant::GrantParameters,
    ),
    crate::protocol::RejectionCode,
> {
    crate::request_binding::request_parameters(request)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FaultPoint {
    Effect,
    StatePersist,
    OwnershipPersist,
    ResultPersist,
    PhasePersist(String),
    JournalPersist(String),
}

#[derive(Clone, Default)]
pub struct FaultHandle(std::sync::Arc<std::sync::Mutex<VecDeque<FaultPoint>>>);
impl FaultHandle {
    pub fn fail_once(&self, point: FaultPoint) {
        self.0.lock().expect("fault lock").push_back(point);
    }
    pub fn fail_phase_once(&self, phase: impl Into<String>) {
        self.fail_once(FaultPoint::PhasePersist(phase.into()));
    }
    pub fn fail_journal_once(&self, phase: impl Into<String>) {
        self.fail_once(FaultPoint::JournalPersist(phase.into()));
    }
    pub(crate) fn take(&self, point: FaultPoint) -> bool {
        let mut faults = self.0.lock().expect("fault lock");
        if faults.front() == Some(&point) {
            faults.pop_front();
            true
        } else {
            false
        }
    }
}

/// Serves exactly one bounded request. UID is checked before any request bytes are read.
pub fn serve_one(
    listener: &UnixListener,
    server: &mut NetdServer,
    expected_uid: u32,
    now: u64,
) -> Result<(), String> {
    let (mut stream, _) = listener.accept().map_err(|e| e.to_string())?;
    let credentials = getsockopt(&stream, PeerCredentials).map_err(|e| e.to_string())?;
    if credentials.uid() != expected_uid {
        return Err("unexpected Unix peer UID".into());
    }
    let mut prefix = [0_u8; 4];
    receive_no_fds(&stream, &mut prefix)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length > MAX_FRAME_BYTES {
        return Err("frame exceeds 1 MiB".into());
    }
    let mut body = vec![0; length];
    receive_no_fds(&stream, &mut body)?;
    let mut frame = prefix.to_vec();
    frame.extend(body);
    let response = server.handle_peer(expected_uid, &frame, now);
    stream
        .write_all(&response_frame(&response).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())
}

fn receive_no_fds(stream: &std::os::unix::net::UnixStream, bytes: &mut [u8]) -> Result<(), String> {
    let mut offset = 0;
    while offset < bytes.len() {
        let mut iov = [std::io::IoSliceMut::new(&mut bytes[offset..])];
        let mut cmsg = nix::cmsg_space!([std::os::fd::RawFd; 1]);
        let message = recvmsg::<()>(
            stream.as_raw_fd(),
            &mut iov,
            Some(&mut cmsg),
            MsgFlags::empty(),
        )
        .map_err(|e| e.to_string())?;
        if message.bytes == 0
            || message
                .cmsgs()
                .map_err(|e| e.to_string())?
                .any(|v| matches!(v, ControlMessageOwned::ScmRights(_)))
        {
            return Err("invalid framed request".into());
        }
        offset += message.bytes;
    }
    Ok(())
}
