//! DRIAD - DNS Reverse IP AMT Discovery (RFC 8777)
//!
//! Implements DNS-based discovery of AMT relays using reverse IP lookups.
//!
//! Per RFC 8777, DRIAD discovers relays based on the **source address**, not the
//! multicast group. The source network operator configures DNS records for their
//! source IPs to advertise which AMT relay(s) can tunnel their traffic.
//!
//! Example: For source 69.25.95.10 sending to group 232.0.0.1:
//!   Query: 10.95.25.69.in-addr.arpa (source-based, NOT group-based)
//!
//! This module provides:
//! - DNS query name construction (for DoH or text display)
//! - DNS wire-format query packet building (RFC 1035)
//! - DNS wire-format response parsing for TYPE260 AMTRELAY records

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// DNS record type for AMTRELAY (RFC 8777)
const AMTRELAY_TYPE: u16 = 260;

/// DNS class IN
const DNS_CLASS_IN: u16 = 1;

/// DRIAD Resolver for AMT relay discovery
///
/// Builds DNS query names and wire-format packets for DRIAD lookups.
/// Parses DNS responses containing TYPE260 AMTRELAY records.
pub struct DriadResolver;

impl DriadResolver {
    /// Build DRIAD query name for IPv4 source address (RFC 8777)
    ///
    /// Format: <reverse-source-ip>.in-addr.arpa
    /// Example: 10.95.25.69.in-addr.arpa for source 69.25.95.10
    pub fn build_query_ipv4(source: Ipv4Addr) -> String {
        let octets = source.octets();
        format!(
            "{}.{}.{}.{}.in-addr.arpa",
            octets[3], octets[2], octets[1], octets[0]
        )
    }

    /// Build DRIAD query name for IPv6 source address (RFC 8777)
    ///
    /// Format: <reverse-nibbles>.ip6.arpa
    pub fn build_query_ipv6(source: Ipv6Addr) -> String {
        let segments = source.segments();
        let mut nibbles = Vec::new();

        for segment in segments.iter().rev() {
            let hex = format!("{:04x}", segment);
            for c in hex.chars().rev() {
                nibbles.push(c);
            }
        }

        let reversed = nibbles
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(".");

        format!("{}.ip6.arpa", reversed)
    }

    /// Build DRIAD query name for any IP source address (RFC 8777)
    pub fn build_query(source: IpAddr) -> String {
        match source {
            IpAddr::V4(addr) => Self::build_query_ipv4(addr),
            IpAddr::V6(addr) => Self::build_query_ipv6(addr),
        }
    }

    /// Build a DNS wire-format query packet for AMTRELAY (TYPE260) lookup.
    ///
    /// Returns a complete DNS query packet (RFC 1035) ready to send over UDP to
    /// a DNS resolver (e.g., 8.8.8.8:53).
    ///
    /// The transaction ID is provided by the caller for matching responses.
    pub fn build_dns_query(source: IpAddr, transaction_id: u16) -> Vec<u8> {
        let qname = Self::build_query(source);
        Self::build_dns_query_packet(&qname, transaction_id)
    }

    /// Build DNS wire-format query packet from a domain name string.
    fn build_dns_query_packet(qname: &str, transaction_id: u16) -> Vec<u8> {
        let mut packet = Vec::with_capacity(64);

        // DNS Header (12 bytes) - RFC 1035 Section 4.1.1
        packet.extend_from_slice(&transaction_id.to_be_bytes()); // ID
        packet.extend_from_slice(&[0x01, 0x00]); // Flags: QR=0, OPCODE=0, RD=1
        packet.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
        packet.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
        packet.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
        packet.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0

        // Question section - RFC 1035 Section 4.1.2
        // QNAME: sequence of length-prefixed labels
        for label in qname.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0); // Root label (terminator)

        // QTYPE = 260 (AMTRELAY)
        packet.extend_from_slice(&AMTRELAY_TYPE.to_be_bytes());
        // QCLASS = IN (1)
        packet.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

        packet
    }

    /// Parse a DNS response packet and extract the relay IP from the first
    /// AMTRELAY (TYPE260) answer record.
    ///
    /// Returns the relay IP address, or None if no valid AMTRELAY record found.
    pub fn parse_dns_response(data: &[u8]) -> Option<IpAddr> {
        if data.len() < 12 {
            return None;
        }

        // DNS Header
        let flags = u16::from_be_bytes([data[2], data[3]]);
        let qr = (flags >> 15) & 1;
        let rcode = flags & 0x0F;

        // Must be a response (QR=1) with no error (RCODE=0)
        if qr != 1 || rcode != 0 {
            return None;
        }

        let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
        let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;

        if ancount == 0 {
            return None;
        }

        // Skip past the question section
        let mut offset = 12;
        for _ in 0..qdcount {
            offset = Self::skip_dns_name(data, offset)?;
            offset += 4; // QTYPE(2) + QCLASS(2)
            if offset > data.len() {
                return None;
            }
        }

        // Parse answer records
        for _ in 0..ancount {
            // Skip NAME (may be a pointer)
            offset = Self::skip_dns_name(data, offset)?;
            if offset + 10 > data.len() {
                return None;
            }

            let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
            // skip CLASS(2) + TTL(4)
            let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
            offset += 10;

            if offset + rdlength > data.len() {
                return None;
            }

            if rtype == AMTRELAY_TYPE {
                return Self::parse_amtrelay_rdata(&data[offset..offset + rdlength]);
            }

            // Skip this record's RDATA
            offset += rdlength;
        }

        None
    }

    /// Parse AMTRELAY RDATA (RFC 8777 Section 4.2)
    ///
    /// Wire format: [precedence:1][D+type:1][relay:variable]
    ///   D (bit 7): discovery optional flag
    ///   type (bits 6-0): 0=none, 1=IPv4, 2=IPv6, 3=domain name
    fn parse_amtrelay_rdata(rdata: &[u8]) -> Option<IpAddr> {
        if rdata.len() < 2 {
            return None;
        }

        // rdata[0] = precedence (unused for now)
        let relay_type = rdata[1] & 0x7F;

        match relay_type {
            1 => {
                // IPv4: 4 bytes
                if rdata.len() < 6 {
                    return None;
                }
                Some(IpAddr::V4(Ipv4Addr::new(
                    rdata[2], rdata[3], rdata[4], rdata[5],
                )))
            }
            2 => {
                // IPv6: 16 bytes
                if rdata.len() < 18 {
                    return None;
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&rdata[2..18]);
                Some(IpAddr::V6(Ipv6Addr::from(octets)))
            }
            // Type 3 (domain name) not supported — would require additional DNS resolution
            _ => None,
        }
    }

    /// Skip a DNS name at the given offset, handling both labels and pointers.
    /// Returns the offset after the name, or None if malformed.
    fn skip_dns_name(data: &[u8], mut offset: usize) -> Option<usize> {
        let mut jumped = false;
        let mut return_offset = 0;

        loop {
            if offset >= data.len() {
                return None;
            }

            let len = data[offset] as usize;

            if len == 0 {
                // Root label — end of name
                offset += 1;
                break;
            }

            if (len & 0xC0) == 0xC0 {
                // DNS pointer (compression) — 2 bytes
                if !jumped {
                    return_offset = offset + 2;
                    jumped = true;
                }
                if offset + 1 >= data.len() {
                    return None;
                }
                let ptr = ((len & 0x3F) << 8) | (data[offset + 1] as usize);
                if ptr >= offset {
                    // Prevent forward/self pointers (infinite loop)
                    return None;
                }
                offset = ptr;
                continue;
            }

            // Regular label
            offset += 1 + len;
        }

        Some(if jumped { return_offset } else { offset })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_source_query() {
        let source: Ipv4Addr = "69.25.95.10".parse().unwrap();
        let query = DriadResolver::build_query_ipv4(source);
        assert_eq!(query, "10.95.25.69.in-addr.arpa");
    }

    #[test]
    fn test_ipv4_source_query_complex() {
        let source: Ipv4Addr = "192.168.1.100".parse().unwrap();
        let query = DriadResolver::build_query_ipv4(source);
        assert_eq!(query, "100.1.168.192.in-addr.arpa");
    }

    #[test]
    fn test_ipv6_source_query_simple() {
        let source: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let query = DriadResolver::build_query_ipv6(source);
        assert_eq!(
            query,
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        );
    }

    #[test]
    fn test_ipv6_source_query_full() {
        let source: Ipv6Addr = "2001:db8:1234:5678:9abc:def0:1234:5678".parse().unwrap();
        let query = DriadResolver::build_query_ipv6(source);
        assert_eq!(
            query,
            "8.7.6.5.4.3.2.1.0.f.e.d.c.b.a.9.8.7.6.5.4.3.2.1.8.b.d.0.1.0.0.2.ip6.arpa"
        );
    }

    #[test]
    fn test_build_query_v4_source() {
        let source: IpAddr = "69.25.95.10".parse().unwrap();
        let query = DriadResolver::build_query(source);
        assert_eq!(query, "10.95.25.69.in-addr.arpa");
    }

    #[test]
    fn test_build_query_v6_source() {
        let source: IpAddr = "2001:db8::1".parse().unwrap();
        let query = DriadResolver::build_query(source);
        assert_eq!(
            query,
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        );
    }

    #[test]
    fn test_build_dns_query_packet_structure() {
        let source: IpAddr = "69.25.95.128".parse().unwrap();
        let packet = DriadResolver::build_dns_query(source, 0x1234);

        // Header: 12 bytes
        assert_eq!(packet[0], 0x12); // Transaction ID high
        assert_eq!(packet[1], 0x34); // Transaction ID low
        assert_eq!(packet[2], 0x01); // Flags: RD=1
        assert_eq!(packet[3], 0x00);
        assert_eq!(u16::from_be_bytes([packet[4], packet[5]]), 1);  // QDCOUNT
        assert_eq!(u16::from_be_bytes([packet[6], packet[7]]), 0);  // ANCOUNT
        assert_eq!(u16::from_be_bytes([packet[8], packet[9]]), 0);  // NSCOUNT
        assert_eq!(u16::from_be_bytes([packet[10], packet[11]]), 0); // ARCOUNT

        // QNAME for 128.95.25.69.in-addr.arpa
        let mut offset = 12;
        // "128"
        assert_eq!(packet[offset], 3); offset += 1;
        assert_eq!(&packet[offset..offset+3], b"128"); offset += 3;
        // "95"
        assert_eq!(packet[offset], 2); offset += 1;
        assert_eq!(&packet[offset..offset+2], b"95"); offset += 2;
        // "25"
        assert_eq!(packet[offset], 2); offset += 1;
        assert_eq!(&packet[offset..offset+2], b"25"); offset += 2;
        // "69"
        assert_eq!(packet[offset], 2); offset += 1;
        assert_eq!(&packet[offset..offset+2], b"69"); offset += 2;
        // "in-addr"
        assert_eq!(packet[offset], 7); offset += 1;
        assert_eq!(&packet[offset..offset+7], b"in-addr"); offset += 7;
        // "arpa"
        assert_eq!(packet[offset], 4); offset += 1;
        assert_eq!(&packet[offset..offset+4], b"arpa"); offset += 4;
        // Root label
        assert_eq!(packet[offset], 0); offset += 1;

        // QTYPE = 260
        assert_eq!(u16::from_be_bytes([packet[offset], packet[offset+1]]), 260);
        offset += 2;
        // QCLASS = 1 (IN)
        assert_eq!(u16::from_be_bytes([packet[offset], packet[offset+1]]), 1);
    }

    #[test]
    fn test_parse_dns_response_ipv4_relay() {
        // Build a minimal DNS response with one TYPE260 answer containing IPv4 relay
        let source: IpAddr = "69.25.95.128".parse().unwrap();
        let query = DriadResolver::build_dns_query(source, 0xABCD);

        // Construct response by modifying the query
        let mut response = query.clone();
        // Set QR=1 (response) in flags
        response[2] = 0x81; // QR=1, RD=1
        response[3] = 0x80; // RA=1
        // ANCOUNT = 1
        response[6] = 0x00;
        response[7] = 0x01;

        // Append answer record
        // NAME: pointer to QNAME at offset 12
        response.push(0xC0);
        response.push(0x0C);
        // TYPE = 260
        response.extend_from_slice(&260u16.to_be_bytes());
        // CLASS = IN
        response.extend_from_slice(&1u16.to_be_bytes());
        // TTL = 300
        response.extend_from_slice(&300u32.to_be_bytes());
        // RDLENGTH = 6 (precedence:1 + D+type:1 + IPv4:4)
        response.extend_from_slice(&6u16.to_be_bytes());
        // RDATA
        response.push(10);  // precedence
        response.push(0x01); // D=0, type=1 (IPv4)
        response.extend_from_slice(&[192, 0, 2, 1]); // relay: 192.0.2.1

        let relay = DriadResolver::parse_dns_response(&response);
        assert_eq!(relay, Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
    }

    #[test]
    fn test_parse_dns_response_ipv6_relay() {
        let source: IpAddr = "69.25.95.128".parse().unwrap();
        let query = DriadResolver::build_dns_query(source, 0x5678);
        let mut response = query.clone();
        response[2] = 0x81;
        response[3] = 0x80;
        response[6] = 0x00;
        response[7] = 0x01;

        // Answer: pointer to QNAME
        response.push(0xC0);
        response.push(0x0C);
        response.extend_from_slice(&260u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&300u32.to_be_bytes());
        // RDLENGTH = 18 (precedence:1 + D+type:1 + IPv6:16)
        response.extend_from_slice(&18u16.to_be_bytes());
        response.push(10);   // precedence
        response.push(0x02); // D=0, type=2 (IPv6)
        // 2001:db8::1
        response.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

        let relay = DriadResolver::parse_dns_response(&response);
        assert_eq!(
            relay,
            Some(IpAddr::V6("2001:db8::1".parse().unwrap()))
        );
    }

    #[test]
    fn test_parse_dns_response_no_answer() {
        // Response with ANCOUNT=0
        let source: IpAddr = "69.25.95.128".parse().unwrap();
        let query = DriadResolver::build_dns_query(source, 0x1111);
        let mut response = query.clone();
        response[2] = 0x81;
        response[3] = 0x80;
        // ANCOUNT stays 0

        assert_eq!(DriadResolver::parse_dns_response(&response), None);
    }

    #[test]
    fn test_parse_dns_response_nxdomain() {
        // Response with RCODE=3 (NXDOMAIN)
        let source: IpAddr = "69.25.95.128".parse().unwrap();
        let query = DriadResolver::build_dns_query(source, 0x2222);
        let mut response = query.clone();
        response[2] = 0x81;
        response[3] = 0x83; // RA=1, RCODE=3

        assert_eq!(DriadResolver::parse_dns_response(&response), None);
    }

    #[test]
    fn test_parse_dns_response_too_short() {
        assert_eq!(DriadResolver::parse_dns_response(&[0; 5]), None);
    }

    #[test]
    fn test_parse_amtrelay_rdata_d_flag() {
        // D flag should be masked off — type is in lower 7 bits
        let rdata = [10, 0x81, 192, 0, 2, 1]; // D=1, type=1 (IPv4)
        let result = DriadResolver::parse_amtrelay_rdata(&rdata);
        assert_eq!(result, Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
    }

    #[test]
    fn test_parse_amtrelay_rdata_unsupported_type() {
        // Type 3 (domain name) — not supported
        let rdata = [10, 0x03, 4, b't', b'e', b's', b't', 0];
        assert_eq!(DriadResolver::parse_amtrelay_rdata(&rdata), None);
    }

    #[test]
    fn test_parse_amtrelay_rdata_truncated() {
        // IPv4 type but only 3 bytes of address
        let rdata = [10, 0x01, 192, 0, 2];
        assert_eq!(DriadResolver::parse_amtrelay_rdata(&rdata), None);
    }
}
