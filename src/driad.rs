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

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// DNS record type for AMTRELAY (RFC 8777)
const AMTRELAY_TYPE: u16 = 260;

/// DNS record type A (IPv4 address)
const DNS_TYPE_A: u16 = 1;

/// DNS record type AAAA (IPv6 address)
const DNS_TYPE_AAAA: u16 = 28;

/// DNS class IN
const DNS_CLASS_IN: u16 = 1;

/// Result of DRIAD relay discovery — may be an IP or a DNS name requiring resolution
#[derive(Debug, Clone, PartialEq)]
pub enum DriadRelayAddress {
    Ip(IpAddr),
    DnsName(String),
}

impl fmt::Display for DriadRelayAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DriadRelayAddress::Ip(addr) => write!(f, "{}", addr),
            DriadRelayAddress::DnsName(name) => write!(f, "{}", name),
        }
    }
}

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
        Self::build_dns_query_packet(&qname, AMTRELAY_TYPE, transaction_id)
    }

    /// Build a DNS wire-format A record query for a hostname.
    ///
    /// Used to resolve DRIAD type=3 DNS name relays to IPv4 addresses.
    pub fn build_dns_a_query(hostname: &str, transaction_id: u16) -> Vec<u8> {
        Self::build_dns_query_packet(hostname, DNS_TYPE_A, transaction_id)
    }

    /// Build a DNS wire-format AAAA record query for a hostname.
    ///
    /// Used to resolve DRIAD type=3 DNS name relays to IPv6 addresses.
    pub fn build_dns_aaaa_query(hostname: &str, transaction_id: u16) -> Vec<u8> {
        Self::build_dns_query_packet(hostname, DNS_TYPE_AAAA, transaction_id)
    }

    /// Build DNS wire-format query packet for any QNAME and QTYPE.
    fn build_dns_query_packet(qname: &str, qtype: u16, transaction_id: u16) -> Vec<u8> {
        let mut packet = Vec::with_capacity(64);

        // DNS Header (12 bytes) - RFC 1035 Section 4.1.1
        packet.extend_from_slice(&transaction_id.to_be_bytes()); // ID
        packet.extend_from_slice(&[0x01, 0x00]); // Flags: QR=0, OPCODE=0, RD=1
        packet.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
        packet.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
        packet.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
        packet.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0

        // Question section - RFC 1035 Section 4.1.2
        // QNAME: sequence of length-prefixed labels.
        //
        // Empty labels are skipped so that a fully-qualified name written with a
        // trailing dot ("relay.example.") frames identically to its relative
        // spelling ("relay.example"). `split('.')` yields a trailing "" for the
        // former, which previously emitted a second zero length-octet after the
        // explicit root label below — two root labels, a QNAME one byte longer
        // than the parser computes, and every subsequent section misaligned.
        for label in qname.split('.').filter(|label| !label.is_empty()) {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0); // Root label (terminator)

        // QTYPE
        packet.extend_from_slice(&qtype.to_be_bytes());
        // QCLASS = IN (1)
        packet.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

        packet
    }

    /// Parse a DNS response packet and extract the best AMTRELAY (TYPE260) relay.
    ///
    /// Records are considered in RFC 8777 §4.2 precedence order (lower value
    /// preferred); if the most-preferred record is unusable the next is tried.
    ///
    /// Answer records are accepted only when their owner name and class match
    /// the question echoed in this same response. That is self-consistency, not
    /// authentication: it cannot detect a spoofed reply that rewrote the
    /// question to match its own forged answers. Callers that hold the query
    /// they sent MUST use [`parse_dns_response_validated`], which additionally
    /// binds the transaction ID and question to the outgoing request.
    ///
    /// [`parse_dns_response_validated`]: DriadResolver::parse_dns_response_validated
    pub fn parse_dns_response(data: &[u8]) -> Option<DriadRelayAddress> {
        Self::select_amtrelay(data, None)
    }

    /// Parse a DNS response, binding it to the query that produced it.
    ///
    /// Rejects the reply unless, in addition to the checks in
    /// [`parse_dns_response`], the response transaction ID equals the query's
    /// and the echoed question matches the question we asked. This is the entry
    /// point for any unauthenticated transport (plain UDP:53), where an off-path
    /// attacker can race a forged answer and redirect relay discovery.
    ///
    /// [`parse_dns_response`]: DriadResolver::parse_dns_response
    pub fn parse_dns_response_validated(query: &[u8], data: &[u8]) -> Option<DriadRelayAddress> {
        let expect = DnsQuestionRef::from_query(query)?;
        Self::select_amtrelay(data, Some(&expect))
    }

    /// Collect every acceptable AMTRELAY answer, then pick by precedence.
    fn select_amtrelay(data: &[u8], expect: Option<&DnsQuestionRef>) -> Option<DriadRelayAddress> {
        let mut best: Option<(u8, DriadRelayAddress)> = None;
        Self::for_each_answer(data, AMTRELAY_TYPE, expect, |rdata| {
            // A record whose RDATA does not decode (unknown relay type, truncated
            // relay field, type 0 "no relay") is skipped, not fatal — RFC 8777
            // §4.2 requires falling through to the next candidate.
            if let Some((precedence, addr)) = Self::parse_amtrelay_record(rdata) {
                // Strictly-lower precedence wins, so ties keep the first record
                // in wire order (stable selection).
                if best.as_ref().is_none_or(|(b, _)| precedence < *b) {
                    best = Some((precedence, addr));
                }
            }
        })?;
        best.map(|(_, addr)| addr)
    }

    /// Parse a DNS A record response and extract the first IPv4 address.
    ///
    /// Used to resolve DRIAD type=3 DNS name relays.
    pub fn parse_dns_a_response(data: &[u8]) -> Option<IpAddr> {
        Self::first_address(data, DNS_TYPE_A, None)
    }

    /// Query-bound variant of [`parse_dns_a_response`].
    ///
    /// [`parse_dns_a_response`]: DriadResolver::parse_dns_a_response
    pub fn parse_dns_a_response_validated(query: &[u8], data: &[u8]) -> Option<IpAddr> {
        let expect = DnsQuestionRef::from_query(query)?;
        Self::first_address(data, DNS_TYPE_A, Some(&expect))
    }

    /// Parse a DNS AAAA record response and extract the first IPv6 address.
    ///
    /// Used to resolve DRIAD type=3 DNS name relays to IPv6.
    pub fn parse_dns_aaaa_response(data: &[u8]) -> Option<IpAddr> {
        Self::first_address(data, DNS_TYPE_AAAA, None)
    }

    /// Query-bound variant of [`parse_dns_aaaa_response`].
    ///
    /// [`parse_dns_aaaa_response`]: DriadResolver::parse_dns_aaaa_response
    pub fn parse_dns_aaaa_response_validated(query: &[u8], data: &[u8]) -> Option<IpAddr> {
        let expect = DnsQuestionRef::from_query(query)?;
        Self::first_address(data, DNS_TYPE_AAAA, Some(&expect))
    }

    /// Return the address from the first acceptable A/AAAA answer.
    fn first_address(
        data: &[u8],
        record_type: u16,
        expect: Option<&DnsQuestionRef>,
    ) -> Option<IpAddr> {
        let mut found: Option<IpAddr> = None;
        Self::for_each_answer(data, record_type, expect, |rdata| {
            if found.is_some() {
                return;
            }
            found = match (record_type, rdata.len()) {
                (DNS_TYPE_A, 4) => Some(IpAddr::V4(Ipv4Addr::new(
                    rdata[0], rdata[1], rdata[2], rdata[3],
                ))),
                (DNS_TYPE_AAAA, 16) => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(rdata);
                    Some(IpAddr::V6(Ipv6Addr::from(octets)))
                }
                _ => None,
            };
        })?;
        found
    }

    /// Walk the answer section, invoking `visit` with the RDATA of every record
    /// whose TYPE and CLASS match and whose owner name matches the question.
    ///
    /// Returns None if the message is not a usable response at all (malformed,
    /// not a reply, RCODE set, or failing `expect`); Some(()) when the answer
    /// section was walked successfully, even if nothing matched.
    fn for_each_answer(
        data: &[u8],
        record_type: u16,
        expect: Option<&DnsQuestionRef>,
        mut visit: impl FnMut(&[u8]),
    ) -> Option<()> {
        if data.len() < 12 {
            return None;
        }

        let flags = u16::from_be_bytes([data[2], data[3]]);
        // Must be a response (QR=1) with no error (RCODE=0).
        if (flags >> 15) & 1 != 1 || flags & 0x0F != 0 {
            return None;
        }

        let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
        let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;

        // Exactly one question: DRIAD never pipelines, and a multi-question
        // reply gives us no single owner name to hold answers to.
        if qdcount != 1 {
            return None;
        }

        if let Some(expect) = expect {
            let txid = u16::from_be_bytes([data[0], data[1]]);
            if txid != expect.txid {
                return None;
            }
        }

        // Decode the question: its owner name is what every answer must match.
        let qname = DnsName::decode(data, 12)?;
        let after_qname = qname.end;
        if after_qname + 4 > data.len() {
            return None;
        }
        let qtype = u16::from_be_bytes([data[after_qname], data[after_qname + 1]]);
        let qclass = u16::from_be_bytes([data[after_qname + 2], data[after_qname + 3]]);

        if let Some(expect) = expect {
            if qtype != expect.qtype || qclass != expect.qclass {
                return None;
            }
            if !DnsName::eq(data, &qname, expect.msg, &expect.name) {
                return None;
            }
        }

        let mut offset = after_qname + 4;
        for _ in 0..ancount {
            let owner = DnsName::decode(data, offset)?;
            offset = owner.end;
            if offset + 10 > data.len() {
                return None;
            }

            let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let rclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            // data[offset+4..offset+8] = TTL, unused for selection.
            let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
            offset += 10;

            if offset + rdlength > data.len() {
                return None;
            }

            // Owner/class must match the question. An in-bailiwick reply can
            // otherwise smuggle a record for an unrelated name (or a bogus
            // class) into the answer section and have it read as ours.
            if rtype == record_type
                && rclass == qclass
                && DnsName::eq(data, &owner, data, &qname)
            {
                visit(&data[offset..offset + rdlength]);
            }

            offset += rdlength;
        }

        Some(())
    }

    /// Parse AMTRELAY RDATA (RFC 8777 Section 4.2), returning its precedence.
    ///
    /// Wire format: [precedence:1][D+type:1][relay:variable]
    ///   D (bit 7): discovery optional flag
    ///   type (bits 6-0): 0=none, 1=IPv4, 2=IPv6, 3=domain name
    fn parse_amtrelay_record(rdata: &[u8]) -> Option<(u8, DriadRelayAddress)> {
        if rdata.len() < 2 {
            return None;
        }

        let precedence = rdata[0];
        let relay_type = rdata[1] & 0x7F;

        let addr = match relay_type {
            1 => {
                // IPv4: exactly 4 bytes of relay field.
                if rdata.len() < 6 {
                    return None;
                }
                DriadRelayAddress::Ip(IpAddr::V4(Ipv4Addr::new(
                    rdata[2], rdata[3], rdata[4], rdata[5],
                )))
            }
            2 => {
                // IPv6: exactly 16 bytes of relay field.
                if rdata.len() < 18 {
                    return None;
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&rdata[2..18]);
                DriadRelayAddress::Ip(IpAddr::V6(Ipv6Addr::from(octets)))
            }
            3 => {
                // DNS wire-format name (RFC 1035 Section 3.3)
                // Per RFC 8777: compression pointers are NOT allowed in AMTRELAY RDATA
                DriadRelayAddress::DnsName(Self::parse_dns_wire_name(&rdata[2..])?)
            }
            // Type 0 is "no relay"; anything else is unassigned. Both are
            // unusable, so the caller falls through to the next record.
            _ => return None,
        };

        Some((precedence, addr))
    }

    /// Parse AMTRELAY RDATA, discarding precedence. Retained for the RDATA-level
    /// unit tests; production selection goes through `parse_amtrelay_record` so
    /// that precedence is never dropped on the way.
    #[cfg(test)]
    fn parse_amtrelay_rdata(rdata: &[u8]) -> Option<DriadRelayAddress> {
        Self::parse_amtrelay_record(rdata).map(|(_, addr)| addr)
    }

    /// Parse a DNS wire-format domain name (uncompressed label sequence).
    ///
    /// Format: [len][label][len][label]...[0]
    /// Example: 05 "sfo12" 05 "bcast" 02 "id" 00 → "sfo12.bcast.id"
    fn parse_dns_wire_name(data: &[u8]) -> Option<String> {
        let mut labels = Vec::new();
        let mut offset = 0;

        loop {
            if offset >= data.len() {
                return None;
            }
            let len = data[offset] as usize;
            if len == 0 {
                break;
            }
            // Compression pointers not allowed per RFC 8777
            if (len & 0xC0) != 0 {
                return None;
            }
            offset += 1;
            if offset + len > data.len() {
                return None;
            }
            let label = std::str::from_utf8(&data[offset..offset + len]).ok()?;
            labels.push(label.to_string());
            offset += len;
        }

        if labels.is_empty() {
            return None;
        }

        Some(labels.join("."))
    }
}

/// Re-exports of the private RDATA/name decoders for the `fuzz/` crate.
/// See `crate::fuzz_api` for why these are not part of the public API.
#[cfg(feature = "fuzzing")]
pub mod fuzz_exports {
    use super::{DriadRelayAddress, DriadResolver};

    pub fn parse_amtrelay_rdata(rdata: &[u8]) -> Option<(u8, DriadRelayAddress)> {
        DriadResolver::parse_amtrelay_record(rdata)
    }

    pub fn parse_dns_wire_name(data: &[u8]) -> Option<String> {
        DriadResolver::parse_dns_wire_name(data)
    }
}

/// The question we asked, borrowed from the query packet we sent.
struct DnsQuestionRef<'a> {
    msg: &'a [u8],
    txid: u16,
    name: DnsName,
    qtype: u16,
    qclass: u16,
}

impl<'a> DnsQuestionRef<'a> {
    /// Read back the transaction ID and question from an outgoing query.
    ///
    /// Deriving the expectation from the query bytes — rather than threading the
    /// pieces through every call site — keeps one description of "what we asked"
    /// and makes it impossible for a caller to validate against a question it
    /// did not send.
    fn from_query(query: &'a [u8]) -> Option<Self> {
        if query.len() < 12 {
            return None;
        }
        if u16::from_be_bytes([query[4], query[5]]) != 1 {
            return None; // exactly one question
        }
        let name = DnsName::decode(query, 12)?;
        let end = name.end;
        if end + 4 > query.len() {
            return None;
        }
        Some(Self {
            msg: query,
            txid: u16::from_be_bytes([query[0], query[1]]),
            qtype: u16::from_be_bytes([query[end], query[end + 1]]),
            qclass: u16::from_be_bytes([query[end + 2], query[end + 3]]),
            name,
        })
    }
}

/// Maximum compression-pointer jumps allowed while decoding one name. A legal
/// name needs none; the cap makes termination independent of the guard below.
const MAX_NAME_JUMPS: usize = 16;

/// Maximum labels in one name. RFC 1035 caps a name at 255 octets, so a name
/// cannot carry more than 127 non-empty labels.
const MAX_NAME_LABELS: usize = 128;

/// A decoded DNS name: the byte ranges of its labels within the message, plus
/// the offset just past the name.
///
/// Labels are kept as ranges rather than `String`s so comparison neither
/// allocates nor has to decide what to do with non-UTF-8 label bytes (which are
/// legal on the wire).
struct DnsName {
    labels: Vec<(usize, usize)>,
    end: usize,
}

impl DnsName {
    /// Decode the name at `start`, following compression pointers.
    fn decode(msg: &[u8], start: usize) -> Option<Self> {
        let mut labels = Vec::new();
        let mut offset = start;
        let mut jumps = 0usize;
        let mut end = None;

        loop {
            if offset >= msg.len() {
                return None;
            }
            let len = msg[offset] as usize;

            if len == 0 {
                end.get_or_insert(offset + 1);
                break;
            }

            match len & 0xC0 {
                0x00 => {
                    if labels.len() >= MAX_NAME_LABELS {
                        return None;
                    }
                    let from = offset + 1;
                    let to = from + len;
                    if to > msg.len() {
                        return None;
                    }
                    labels.push((from, to));
                    offset = to;
                }
                0xC0 => {
                    if offset + 1 >= msg.len() {
                        return None;
                    }
                    // The name ends after the first pointer, wherever it leads.
                    end.get_or_insert(offset + 2);
                    jumps += 1;
                    if jumps > MAX_NAME_JUMPS {
                        return None;
                    }
                    let ptr = ((len & 0x3F) << 8) | msg[offset + 1] as usize;
                    // Backward-only: with a strictly decreasing target this
                    // cannot cycle, and the jump cap bounds it regardless.
                    if ptr >= offset {
                        return None;
                    }
                    offset = ptr;
                }
                // 0x40/0x80 are reserved label types (RFC 6891 §6.1 / RFC 2671).
                _ => return None,
            }
        }

        Some(Self {
            labels,
            end: end?,
        })
    }

    /// Compare two decoded names case-insensitively (DNS names are ASCII-case
    /// insensitive per RFC 4343). The names may live in different messages.
    fn eq(a_msg: &[u8], a: &Self, b_msg: &[u8], b: &Self) -> bool {
        if a.labels.len() != b.labels.len() {
            return false;
        }
        a.labels
            .iter()
            .zip(b.labels.iter())
            .all(|(&(a0, a1), &(b0, b1))| {
                a1 - a0 == b1 - b0 && a_msg[a0..a1].eq_ignore_ascii_case(&b_msg[b0..b1])
            })
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
        assert_eq!(
            relay,
            Some(DriadRelayAddress::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))))
        );
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
            Some(DriadRelayAddress::Ip(IpAddr::V6("2001:db8::1".parse().unwrap())))
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
        assert_eq!(
            result,
            Some(DriadRelayAddress::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))))
        );
    }

    #[test]
    fn test_parse_amtrelay_rdata_type3_dns_name() {
        // Type 3: DNS wire-format name for sfo12.bcast.id
        // Wire: 05 "sfo12" 05 "bcast" 02 "id" 00
        let rdata = [
            10,   // precedence
            0x03, // D=0, type=3 (DNS name)
            5, b's', b'f', b'o', b'1', b'2', // label "sfo12"
            5, b'b', b'c', b'a', b's', b't', // label "bcast"
            2, b'i', b'd',                    // label "id"
            0,                                // root label
        ];
        let result = DriadResolver::parse_amtrelay_rdata(&rdata);
        assert_eq!(
            result,
            Some(DriadRelayAddress::DnsName("sfo12.bcast.id".to_string()))
        );
    }

    #[test]
    fn test_parse_amtrelay_rdata_type3_real_wire_data() {
        // Real RDATA from production: 0A 03 05 73 66 6F 31 32 05 62 63 61 73 74 02 69 64 00
        let rdata = [
            0x0A, 0x03, 0x05, 0x73, 0x66, 0x6F, 0x31, 0x32,
            0x05, 0x62, 0x63, 0x61, 0x73, 0x74, 0x02, 0x69,
            0x64, 0x00,
        ];
        let result = DriadResolver::parse_amtrelay_rdata(&rdata);
        assert_eq!(
            result,
            Some(DriadRelayAddress::DnsName("sfo12.bcast.id".to_string()))
        );
    }

    #[test]
    fn test_parse_dns_response_type3_dns_name() {
        // Full DNS response with TYPE260 answer containing type=3 DNS name
        let source: IpAddr = "69.25.95.128".parse().unwrap();
        let query = DriadResolver::build_dns_query(source, 0x9999);
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
        // RDATA: precedence(1) + D+type(1) + DNS name for "sfo12.bcast.id"
        let dns_name_wire = [
            5, b's', b'f', b'o', b'1', b'2',
            5, b'b', b'c', b'a', b's', b't',
            2, b'i', b'd',
            0,
        ];
        let rdlength = (2 + dns_name_wire.len()) as u16;
        response.extend_from_slice(&rdlength.to_be_bytes());
        response.push(10);   // precedence
        response.push(0x03); // D=0, type=3 (DNS name)
        response.extend_from_slice(&dns_name_wire);

        let relay = DriadResolver::parse_dns_response(&response);
        assert_eq!(
            relay,
            Some(DriadRelayAddress::DnsName("sfo12.bcast.id".to_string()))
        );
    }

    #[test]
    fn test_parse_amtrelay_rdata_unsupported_type() {
        // Type 4 (unknown) — not supported
        let rdata = [10, 0x04, 0, 0, 0, 0];
        assert_eq!(DriadResolver::parse_amtrelay_rdata(&rdata), None);
    }

    #[test]
    fn test_parse_amtrelay_rdata_truncated() {
        // IPv4 type but only 3 bytes of address
        let rdata = [10, 0x01, 192, 0, 2];
        assert_eq!(DriadResolver::parse_amtrelay_rdata(&rdata), None);
    }

    #[test]
    fn test_parse_dns_wire_name_empty() {
        // Just root label — invalid for a relay name
        assert_eq!(DriadResolver::parse_dns_wire_name(&[0]), None);
    }

    #[test]
    fn test_parse_dns_wire_name_truncated() {
        // Label claims 5 bytes but only 3 available
        assert_eq!(DriadResolver::parse_dns_wire_name(&[5, b'a', b'b']), None);
    }

    #[test]
    fn test_parse_dns_wire_name_compression_rejected() {
        // Compression pointer (0xC0) — not allowed in AMTRELAY RDATA
        assert_eq!(DriadResolver::parse_dns_wire_name(&[0xC0, 0x0C]), None);
    }

    #[test]
    fn test_build_dns_a_query() {
        let packet = DriadResolver::build_dns_a_query("sfo12.bcast.id", 0x4321);
        // Verify header
        assert_eq!(packet[0], 0x43);
        assert_eq!(packet[1], 0x21);
        // Verify QNAME contains "sfo12"
        assert_eq!(packet[12], 5); // label length
        assert_eq!(&packet[13..18], b"sfo12");
        // Find QTYPE at end of QNAME
        // sfo12(6) + bcast(6) + id(3) + root(1) = 16 bytes for QNAME
        let qtype_offset = 12 + 16;
        assert_eq!(u16::from_be_bytes([packet[qtype_offset], packet[qtype_offset + 1]]), 1); // TYPE A
    }

    #[test]
    fn test_parse_dns_a_response() {
        // Build a DNS A record response for sfo12.bcast.id → 69.25.95.128
        let query = DriadResolver::build_dns_a_query("sfo12.bcast.id", 0x5555);
        let mut response = query.clone();
        response[2] = 0x81;
        response[3] = 0x80;
        response[6] = 0x00;
        response[7] = 0x01;

        // Answer: pointer to QNAME
        response.push(0xC0);
        response.push(0x0C);
        response.extend_from_slice(&1u16.to_be_bytes());    // TYPE A
        response.extend_from_slice(&1u16.to_be_bytes());    // CLASS IN
        response.extend_from_slice(&300u32.to_be_bytes());  // TTL
        response.extend_from_slice(&4u16.to_be_bytes());    // RDLENGTH = 4
        response.extend_from_slice(&[69, 25, 95, 128]);     // 69.25.95.128

        let ip = DriadResolver::parse_dns_a_response(&response);
        assert_eq!(ip, Some(IpAddr::V4(Ipv4Addr::new(69, 25, 95, 128))));
    }

    #[test]
    fn test_driad_relay_address_display() {
        let ip = DriadRelayAddress::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(ip.to_string(), "192.0.2.1");

        let dns = DriadRelayAddress::DnsName("sfo12.bcast.id".to_string());
        assert_eq!(dns.to_string(), "sfo12.bcast.id");
    }

    #[test]
    fn build_dns_aaaa_query_packet_structure() {
        let packet = DriadResolver::build_dns_aaaa_query("relay.example.", 0x1234);
        // DNS header: ID(2) + flags(2) + counts(8) = 12 bytes
        assert_eq!(&packet[..2], &[0x12, 0x34]);
        // QTYPE at end before QCLASS: AAAA = 28 = 0x001C
        let qtype_off = packet.len() - 4;
        assert_eq!(&packet[qtype_off..qtype_off + 2], &[0x00, 0x1C]);
    }

    #[test]
    fn parse_dns_aaaa_response_extracts_ipv6() {
        // Construct minimal AAAA response: header + question echo + 1 answer.
        // No trailing dot — the builder's `split('.')` adds an extra zero label
        // for empty trailing labels, which misaligns the question-section length
        // with what the parser computes. Same convention as build_dns_a_query tests.
        let query = DriadResolver::build_dns_aaaa_query("relay.example", 0xABCD);
        let mut response = query.clone();
        // Set flags: response (QR=1) + recursion available
        response[2] = 0x81;
        response[3] = 0x80;
        // Set ANCOUNT to 1 (bytes 6-7)
        response[6] = 0;
        response[7] = 1;
        // Append answer: pointer (0xC00C) + TYPE(28) + CLASS(1) + TTL(4) + RDLEN(16) + IPv6(16)
        response.extend_from_slice(&[
            0xC0, 0x0C, // pointer to QNAME at offset 12
            0x00, 0x1C, // TYPE AAAA = 28
            0x00, 0x01, // CLASS IN
            0x00, 0x00, 0x00, 0x3C, // TTL
            0x00, 0x10, // RDLENGTH = 16
            0x20, 0x01, 0x0D, 0xB8, // IPv6 2001:db8::
            0x00, 0x00, 0x00, 0x00, //
            0x00, 0x00, 0x00, 0x00, //
            0x00, 0x00, 0x00, 0x01, // ::1
        ]);

        let addr = DriadResolver::parse_dns_aaaa_response(&response).expect("AAAA parse");
        assert_eq!(addr, "2001:db8::1".parse::<std::net::IpAddr>().unwrap());
    }
}
