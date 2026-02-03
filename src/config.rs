//! AMT Gateway Configuration
//!
//! AMT relay addresses and ports are **not** hardcoded - they are either:
//! 1. Discovered via DRIAD (RFC 8777) - DNS-based relay discovery
//! 2. Manually configured by the user

use std::net::IpAddr;
use crate::constants::DEFAULT_AMT_PORT;

/// AMT Gateway Configuration
#[derive(Debug, Clone)]
pub struct AmtConfig {
    /// AMT relay address
    /// - Discovered via DRIAD (preferred)
    /// - Or manually configured
    pub relay_address: IpAddr,

    /// AMT relay port
    /// Default: 2268 (RFC 7450)
    pub relay_port: u16,

    /// Enable DRIAD relay discovery
    /// If true, will attempt DNS-based relay discovery before using relay_address
    pub enable_driad: bool,

    /// Keep-alive interval in seconds
    /// Send periodic Membership Update to maintain tunnel state
    /// Default: 60 seconds, 0 to disable
    /// RFC 7450 Section 5.2.3.4: "The gateway MAY send periodic Membership Update messages"
    pub keepalive_interval_secs: u32,
}

impl AmtConfig {
    /// Default keep-alive interval (60 seconds)
    pub const DEFAULT_KEEPALIVE_SECS: u32 = 60;

    /// Create new AMT configuration with manual relay
    pub fn new(relay_address: IpAddr, relay_port: Option<u16>) -> Self {
        Self {
            relay_address,
            relay_port: relay_port.unwrap_or(DEFAULT_AMT_PORT),
            enable_driad: false,
            keepalive_interval_secs: Self::DEFAULT_KEEPALIVE_SECS,
        }
    }

    /// Create configuration with DRIAD discovery enabled
    /// Falls back to provided relay if DRIAD fails
    pub fn with_driad(fallback_relay: IpAddr, relay_port: Option<u16>) -> Self {
        Self {
            relay_address: fallback_relay,
            relay_port: relay_port.unwrap_or(DEFAULT_AMT_PORT),
            enable_driad: true,
            keepalive_interval_secs: Self::DEFAULT_KEEPALIVE_SECS,
        }
    }

    /// Create configuration with DRIAD discovery only (no fallback)
    /// Will fail if DRIAD lookup fails
    pub fn driad_only() -> Self {
        Self {
            relay_address: "0.0.0.0".parse().unwrap(), // Placeholder
            relay_port: DEFAULT_AMT_PORT,
            enable_driad: true,
            keepalive_interval_secs: Self::DEFAULT_KEEPALIVE_SECS,
        }
    }

    /// Set keep-alive interval
    pub fn with_keepalive(mut self, interval_secs: u32) -> Self {
        self.keepalive_interval_secs = interval_secs;
        self
    }
}

impl Default for AmtConfig {
    /// Default: Enable DRIAD with no fallback
    fn default() -> Self {
        Self::driad_only()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manual_config() {
        let cfg = AmtConfig::new("192.0.2.1".parse().unwrap(), None);
        assert_eq!(cfg.relay_port, DEFAULT_AMT_PORT);
        assert!(!cfg.enable_driad);
    }

    #[test]
    fn test_driad_with_fallback() {
        let cfg = AmtConfig::with_driad("192.0.2.1".parse().unwrap(), Some(3000));
        assert_eq!(cfg.relay_port, 3000);
        assert!(cfg.enable_driad);
    }

    #[test]
    fn test_driad_only() {
        let cfg = AmtConfig::driad_only();
        assert!(cfg.enable_driad);
    }
}
