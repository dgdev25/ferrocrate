use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum GrantBuildError {
    #[error("invalid resource binding")]
    InvalidResource,
    #[error("invalid normalized parameters")]
    InvalidParameters,
    #[error("invalid grant claims")]
    InvalidClaims,
    #[error("invalid cleanup provenance")]
    InvalidCleanup,
    #[error("action cannot be delegated to helper")]
    UnsupportedAction,
    #[error("durable intent does not bind the authorized resource generation")]
    IntentMismatch,
    #[error("helper grant signing key custody requirements were not met")]
    KeyCustody,
}
