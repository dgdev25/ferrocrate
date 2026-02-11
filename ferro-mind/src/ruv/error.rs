// Adapted from MIT-licensed ruvector-core (https://github.com/ruvnet/ruvector)

use thiserror::Error;

pub type Result<T> = std::result::Result<T, RuvError>;

#[derive(Error, Debug)]
pub enum RuvError {
    #[error("Dimension mismatch: expected {expected}, got {actual}")]
    DimensionMismatch { expected: usize, actual: usize },
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Internal error: {0}")]
    Internal(String),
}
