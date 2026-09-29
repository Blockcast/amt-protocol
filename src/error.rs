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
    /// The relay's Membership Query carried no Gateway Address fields (G flag
    /// unset, RFC 7450 §5.1.4.5), so no Teardown it could authenticate exists.
    NoGatewayAddress,
    IoError(String),
    // Subscription-layer additions (M1 — BLO-3457 follow-up)
    FamilyMismatch,
    TunnelFull,
    DiscoveryFailed,
    QueryFailed,
    MalformedInner,
    ShutdownInProgress,
}

impl fmt::Display for AmtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AmtError::InvalidMessage(msg) => write!(f, "Invalid AMT message: {}", msg),
            AmtError::InvalidState => write!(f, "Invalid state for operation"),
            AmtError::InvalidNonce => write!(f, "Nonce mismatch"),
            AmtError::UnexpectedMessage => write!(f, "Unexpected message type"),
            AmtError::NoResponseMac => write!(f, "No response MAC available"),
            AmtError::NoGatewayAddress => write!(
                f,
                "No gateway address available: the relay's Membership Query did not set the G flag"
            ),
            AmtError::IoError(msg) => write!(f, "IO error: {}", msg),
            AmtError::FamilyMismatch => {
                write!(f, "IP family mismatch between relay, group, and source")
            }
            AmtError::TunnelFull => write!(f, "Tunnel group cap (64) reached"),
            AmtError::DiscoveryFailed => write!(f, "Relay Discovery failed after retries"),
            AmtError::QueryFailed => write!(f, "Membership Query not received within timeout"),
            AmtError::MalformedInner => write!(f, "Malformed inner IP/UDP packet in MulticastData"),
            AmtError::ShutdownInProgress => {
                write!(f, "Operation rejected: manager is shutting down or closed")
            }
        }
    }
}

impl std::error::Error for AmtError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_error_variants_display() {
        assert_eq!(
            format!("{}", AmtError::FamilyMismatch),
            "IP family mismatch between relay, group, and source"
        );
        assert_eq!(
            format!("{}", AmtError::TunnelFull),
            "Tunnel group cap (64) reached"
        );
        assert_eq!(
            format!("{}", AmtError::DiscoveryFailed),
            "Relay Discovery failed after retries"
        );
        assert_eq!(
            format!("{}", AmtError::QueryFailed),
            "Membership Query not received within timeout"
        );
        assert_eq!(
            format!("{}", AmtError::MalformedInner),
            "Malformed inner IP/UDP packet in MulticastData"
        );
        assert_eq!(
            format!("{}", AmtError::ShutdownInProgress),
            "Operation rejected: manager is shutting down or closed"
        );
        assert_eq!(
            format!("{}", AmtError::NoGatewayAddress),
            "No gateway address available: the relay's Membership Query did not set the G flag"
        );
    }
}
