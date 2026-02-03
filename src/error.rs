//! Error types for AMT protocol

use std::fmt;

pub type Result<T> = std::result::Result<T, AmtError>;

#[derive(Debug, Clone, PartialEq)]
pub enum AmtError {
    InvalidMessage(String),
    InvalidState,
    InvalidNonce,
    UnexpectedMessage,
    NoResponseMac,
    IoError(String),
}

impl fmt::Display for AmtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AmtError::InvalidMessage(msg) => write!(f, "Invalid AMT message: {}", msg),
            AmtError::InvalidState => write!(f, "Invalid state for operation"),
            AmtError::InvalidNonce => write!(f, "Nonce mismatch"),
            AmtError::UnexpectedMessage => write!(f, "Unexpected message type"),
            AmtError::NoResponseMac => write!(f, "No response MAC available"),
            AmtError::IoError(msg) => write!(f, "IO error: {}", msg),
        }
    }
}

impl std::error::Error for AmtError {}
