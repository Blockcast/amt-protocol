//! DRIAD - DNS Reverse IP AMT Discovery (RFC 8777)
//!
//! Implements DNS-based discovery of AMT relays using reverse IP lookups.
//!
//! Per RFC 8777, DRIAD discovers relays based on the **source address**, not the
//! multicast group. The source network operator configures DNS records for their
//! source IPs to advertise which AMT relay(s) can tunnel their traffic.
//!
//! Example: For source 69.25.95.10 sending to group 232.0.0.1:
//!   Query: 10.95.25.69.amt.in-addr.arpa (source-based, NOT group-based)

use std::net::IpAddr;

/// DRIAD Resolver for AMT relay discovery
///
/// This module builds DNS query names for DRIAD lookups based on source address.
/// Actual DNS resolution is handled by the browser's DNS resolver.
pub struct DriadResolver;

impl DriadResolver {
    /// Build DRIAD query name for IPv4 source address (RFC 8777)
    ///
    /// Format: <reverse-source-ip>.amt.in-addr.arpa
    /// Example: 10.95.25.69.amt.in-addr.arpa for source 69.25.95.10
    ///
    /// Returns query name for A/AAAA record lookup to find AMT relay
    pub fn build_query_ipv4(source: std::net::Ipv4Addr) -> String {
        let octets = source.octets();
        format!(
            "{}.{}.{}.{}.amt.in-addr.arpa",
            octets[3], octets[2], octets[1], octets[0]
        )
    }

    /// Build DRIAD query name for IPv6 source address (RFC 8777)
    ///
    /// Format: <reverse-nibbles>.amt.ip6.arpa
    /// Example: For source 2001:db8::1, reverse nibbles in ip6.arpa format
    ///
    /// Returns query name for AAAA record lookup to find AMT relay
    pub fn build_query_ipv6(source: std::net::Ipv6Addr) -> String {
        let segments = source.segments();
        let mut nibbles = Vec::new();

        // Convert to full 32 hex digits (128 bits / 4 bits per nibble)
        for segment in segments.iter().rev() {
            let hex = format!("{:04x}", segment);
            // Reverse the nibbles within each segment
            for c in hex.chars().rev() {
                nibbles.push(c);
            }
        }

        // Join with dots and append domain
        let reversed = nibbles
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(".");

        format!("{}.amt.ip6.arpa", reversed)
    }

    /// Build DRIAD query for any IP source address (RFC 8777)
    ///
    /// The source address identifies the multicast sender whose AMT relay we need.
    pub fn build_query(source: IpAddr) -> String {
        match source {
            IpAddr::V4(addr) => Self::build_query_ipv4(addr),
            IpAddr::V6(addr) => Self::build_query_ipv6(addr),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_ipv4_source_query() {
        // Source address 69.25.95.10 (multicast sender)
        let source: Ipv4Addr = "69.25.95.10".parse().unwrap();
        let query = DriadResolver::build_query_ipv4(source);
        assert_eq!(query, "10.95.25.69.amt.in-addr.arpa");
    }

    #[test]
    fn test_ipv4_source_query_complex() {
        // Source address 192.168.1.100
        let source: Ipv4Addr = "192.168.1.100".parse().unwrap();
        let query = DriadResolver::build_query_ipv4(source);
        assert_eq!(query, "100.1.168.192.amt.in-addr.arpa");
    }

    #[test]
    fn test_ipv6_source_query_simple() {
        // Source address 2001:db8::1
        let source: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let query = DriadResolver::build_query_ipv6(source);

        // Reverse nibbles for 2001:0db8:0000:0000:0000:0000:0000:0001
        assert_eq!(
            query,
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.amt.ip6.arpa"
        );
    }

    #[test]
    fn test_ipv6_source_query_full() {
        // Source address 2001:db8:1234:5678:9abc:def0:1234:5678
        let source: Ipv6Addr = "2001:db8:1234:5678:9abc:def0:1234:5678".parse().unwrap();
        let query = DriadResolver::build_query_ipv6(source);

        // Each segment reversed in nibbles
        assert_eq!(
            query,
            "8.7.6.5.4.3.2.1.0.f.e.d.c.b.a.9.8.7.6.5.4.3.2.1.8.b.d.0.1.0.0.2.amt.ip6.arpa"
        );
    }

    #[test]
    fn test_build_query_v4_source() {
        // Source address for SSM multicast
        let source: IpAddr = "69.25.95.10".parse().unwrap();
        let query = DriadResolver::build_query(source);
        assert_eq!(query, "10.95.25.69.amt.in-addr.arpa");
    }

    #[test]
    fn test_build_query_v6_source() {
        let source: IpAddr = "2001:db8::1".parse().unwrap();
        let query = DriadResolver::build_query(source);
        assert_eq!(
            query,
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.amt.ip6.arpa"
        );
    }
}
