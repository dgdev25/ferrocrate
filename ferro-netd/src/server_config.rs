use crate::{
    grants::GrantVerifier,
    kernel_ops::{NetKernelOps, RealNetKernelOps},
    policy::Policy,
};
use ferro_core::authorization::AuthorizationServiceMode;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    path::PathBuf,
};

pub struct NetdServer {
    pub(crate) uid: u32,
    pub(crate) policy: Policy,
    pub(crate) grants: Option<GrantVerifier>,
    pub(crate) overlays: BTreeSet<String>,
    pub(crate) endpoints: BTreeMap<String, String>,
    pub(crate) routes: BTreeMap<String, Vec<String>>,
    pub(crate) addresses: BTreeMap<String, Vec<String>>,
    pub(crate) effect_receipts: BTreeMap<String, crate::effect_receipt::EffectReceipt>,
    pub(crate) quarantined: BTreeSet<String>,
    pub(crate) overlay_intents: BTreeMap<String, crate::server_state::OverlayMutationIntent>,
    pub(crate) authorization_identity: Option<(AuthorizationServiceMode, String)>,
    pub(crate) journal: Option<PathBuf>,
    pub(crate) journal_lock: Option<File>,
    pub(crate) journal_id: [u8; 16],
    pub(crate) journal_generation: u64,
    pub(crate) kernel: Box<dyn NetKernelOps>,
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) test_faults: crate::test_support::FaultHandle,
}

impl NetdServer {
    pub fn new(uid: u32, policy: Policy) -> Self {
        Self::compose(uid, policy, Box::new(RealNetKernelOps::new()))
    }
    pub fn with_wireguard(uid: u32, policy: Policy, key: PathBuf, port: u16) -> Self {
        Self::compose(
            uid,
            policy,
            Box::new(RealNetKernelOps::with_wireguard(key, port)),
        )
    }
    fn compose(uid: u32, policy: Policy, kernel: Box<dyn NetKernelOps>) -> Self {
        Self {
            uid,
            policy,
            kernel,
            grants: None,
            overlays: BTreeSet::new(),
            endpoints: BTreeMap::new(),
            routes: BTreeMap::new(),
            addresses: BTreeMap::new(),
            effect_receipts: BTreeMap::new(),
            quarantined: BTreeSet::new(),
            overlay_intents: BTreeMap::new(),
            authorization_identity: None,
            journal: None,
            journal_lock: None,
            journal_id: [0; 16],
            journal_generation: 0,
            #[cfg(any(test, feature = "test-support"))]
            test_faults: Default::default(),
        }
    }
    pub fn with_grants(mut self, grants: GrantVerifier) -> Self {
        self.grants = Some(grants);
        self
    }
    pub fn with_authorization_identity(
        mut self,
        mode: AuthorizationServiceMode,
        boot: impl Into<String>,
    ) -> Self {
        self.authorization_identity = Some((mode, boot.into()));
        self
    }
}
