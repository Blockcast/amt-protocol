//! AMT and IGMP/MLD constants

// ============================================================================
// Protocol Constants (True constants from RFCs)
// ============================================================================

/// IGMP Protocol Number (RFC 2236)
pub const IPPROTO_IGMP: u8 = 2;

/// UDP Protocol Number (RFC 768)
pub const IPPROTO_UDP: u8 = 17;

/// IGMPv3 Membership Report Type (RFC 3376)
pub const IGMP_V3_MEMBERSHIP_REPORT: u8 = 0x22;

/// MLDv2 Multicast Listener Report Type - ICMPv6 (RFC 3810)
pub const MLD_V2_LISTENER_REPORT: u8 = 143;

// ============================================================================
// Default Values (Can be overridden via configuration)
// ============================================================================

/// Default AMT UDP port (RFC 7450 Section 7)
/// NOTE: This is a default - actual relay port is configurable or discovered via DRIAD
pub const DEFAULT_AMT_PORT: u16 = 2268;
