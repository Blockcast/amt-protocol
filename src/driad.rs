//! DRIAD - DNS Reverse IP AMT Discovery (RFC 8777)
//!
//! Implements DNS-based discovery of AMT relays using reverse IP lookups.
//!
//! Per RFC 8777, DRIAD discovers relays based on the **source address**, not the
//! multicast group. The source network operator configures DNS records for their
//! source IPs to advertise which AMT relay(s) can tunnel their traffic.
//!
//! Example: For source 192.0.2.10 sending to group 232.0.0.1:
//!   Query: 10.2.0.192.in-addr.arpa (source-based, NOT group-based)
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

/// OPT pseudo-RR type (RFC 6891 §6.1.1).
const DNS_TYPE_OPT: u16 = 41;

/// Fixed DNS header length (RFC 1035 §4.1.1).
const DNS_HEADER_LEN: usize = 12;

/// TC (truncation) bit in the 16-bit header flags word (RFC 1035 §4.1.1).
const DNS_FLAG_TC: u16 = 0x0200;

/// Largest TTL a resolver may honour; RFC 2181 §8 reads a value with the top
/// bit set as zero.
const MAX_TTL: u32 = i32::MAX as u32;

/// D-bit, the top bit of the second AMTRELAY RDATA octet (RFC 8777 §4.2.2).
const AMTRELAY_D_BIT: u8 = 0x80;

/// Relay-type bits below the D-bit (RFC 8777 §4.2.3).
const AMTRELAY_TYPE_MASK: u8 = 0x7F;

/// IPv6 minimum link MTU (RFC 8200 §5).
const IPV6_MIN_MTU: u16 = 1280;

/// Fixed IPv6 header length (RFC 8200 §3).
const IPV6_HEADER_LEN: u16 = 40;

/// UDP header length (RFC 768).
const UDP_HEADER_LEN: u16 = 8;

/// Result of DRIAD relay discovery — may be an IP or a DNS name requiring resolution
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriadRelayAddress {
    Ip(IpAddr),
    DnsName(String),
}

/// One usable AMTRELAY answer, keeping everything RFC 8777 lets a gateway act
/// on rather than only the relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriadCandidate {
    /// Lower is tried first (RFC 8777 §4.2.1).
    pub precedence: u8,
    /// The D-bit (RFC 8777 §4.2.2). When false the gateway MUST receive a
    /// Relay Advertisement from this address before sending it a Request.
    pub discovery_optional: bool,
    pub relay: DriadRelayAddress,
    /// Seconds this binding stays valid: the record's TTL, or for an expanded
    /// type-3 relay the smaller of the AMTRELAY and address-record TTLs.
    pub ttl: u32,
}

/// One A or AAAA answer, with its TTL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriadAddress {
    pub addr: IpAddr,
    pub ttl: u32,
}

impl DriadCandidate {
    /// The address candidates a type-3 relay stands for, given the A/AAAA
    /// answers its name resolved to. RFC 8777 §4.2.4: the precedence and D-bit
    /// carry over to each address. The TTL is the smaller of the two records',
    /// because the derived binding expires as soon as either one does.
    ///
    /// An address candidate is already resolved and comes back unchanged.
    pub fn expand(&self, addresses: &[DriadAddress]) -> Vec<DriadCandidate> {
        match self.relay {
            DriadRelayAddress::Ip(_) => vec![self.clone()],
            DriadRelayAddress::DnsName(_) => addresses
                .iter()
                .map(|address| DriadCandidate {
                    precedence: self.precedence,
                    discovery_optional: self.discovery_optional,
                    relay: DriadRelayAddress::Ip(address.addr),
                    ttl: self.ttl.min(address.ttl),
                })
                .collect(),
        }
    }
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
    /// Example: 10.2.0.192.in-addr.arpa for source 192.0.2.10
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

    /// UDP payload size advertised in the EDNS(0) OPT record: the largest DNS
    /// message an unfragmented datagram carries on the IPv6 minimum MTU. Traffic
    /// Router advertises the same size, and a multi-relay AMTRELAY answer
    /// outgrows the 512 octets plain DNS allows.
    pub const EDNS_UDP_PAYLOAD_SIZE: u16 = IPV6_MIN_MTU - IPV6_HEADER_LEN - UDP_HEADER_LEN;

    /// [`build_dns_query`] plus an EDNS(0) OPT record (RFC 6891) advertising
    /// [`EDNS_UDP_PAYLOAD_SIZE`], so a resolver can answer with every relay
    /// instead of truncating at 512 octets.
    ///
    /// [`build_dns_query`]: DriadResolver::build_dns_query
    /// [`EDNS_UDP_PAYLOAD_SIZE`]: DriadResolver::EDNS_UDP_PAYLOAD_SIZE
    pub fn build_dns_query_edns(source: IpAddr, transaction_id: u16) -> Vec<u8> {
        Self::with_edns(Self::build_dns_query(source, transaction_id))
    }

    /// [`build_dns_a_query`] plus an EDNS(0) OPT record.
    ///
    /// [`build_dns_a_query`]: DriadResolver::build_dns_a_query
    pub fn build_dns_a_query_edns(hostname: &str, transaction_id: u16) -> Vec<u8> {
        Self::with_edns(Self::build_dns_a_query(hostname, transaction_id))
    }

    /// [`build_dns_aaaa_query`] plus an EDNS(0) OPT record.
    ///
    /// [`build_dns_aaaa_query`]: DriadResolver::build_dns_aaaa_query
    pub fn build_dns_aaaa_query_edns(hostname: &str, transaction_id: u16) -> Vec<u8> {
        Self::with_edns(Self::build_dns_aaaa_query(hostname, transaction_id))
    }

    /// Append the OPT pseudo-RR (RFC 6891 §6.1.2) to a query this module built,
    /// which has an empty additional section.
    fn with_edns(mut packet: Vec<u8>) -> Vec<u8> {
        packet[10..12].copy_from_slice(&1u16.to_be_bytes()); // ARCOUNT
        packet.push(0); // owner: the root name
        packet.extend_from_slice(&DNS_TYPE_OPT.to_be_bytes());
        packet.extend_from_slice(&Self::EDNS_UDP_PAYLOAD_SIZE.to_be_bytes());
        // Extended RCODE 0, version 0, DO and Z clear, then RDLENGTH 0.
        packet.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        packet
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

    /// Every usable AMTRELAY answer, in wire order, with its precedence, D-bit
    /// and TTL. Empty when the response is rejected or carries no usable record.
    ///
    /// [`parse_dns_response`] returns one relay of the lowest precedence present,
    /// chosen at random (RFC 8777 §3.1.2). A caller that wants to fail over
    /// takes this list instead and walks it in [`order_candidates`] order.
    ///
    /// [`parse_dns_response`]: DriadResolver::parse_dns_response
    /// [`order_candidates`]: DriadResolver::order_candidates
    pub fn parse_dns_response_candidates(data: &[u8]) -> Vec<DriadCandidate> {
        Self::collect_candidates(data, None).unwrap_or_default()
    }

    /// Query-bound variant of [`parse_dns_response_candidates`]: also requires
    /// the reply's transaction ID and question to match `query`.
    ///
    /// [`parse_dns_response_candidates`]: DriadResolver::parse_dns_response_candidates
    pub fn parse_dns_response_candidates_validated(
        query: &[u8],
        data: &[u8],
    ) -> Vec<DriadCandidate> {
        DnsQuestionRef::from_query(query)
            .and_then(|expect| Self::collect_candidates(data, Some(&expect)))
            .unwrap_or_default()
    }

    /// Put candidates in the order a gateway should try them: lower precedence
    /// first (RFC 8777 §4.2.1), and a uniformly random order among equal
    /// precedence (RFC 8777 §3.1.2 SHOULD), so gateways sharing one resolver
    /// cache spread across the relays a source lists.
    pub fn order_candidates(candidates: &mut [DriadCandidate]) {
        Self::order_candidates_with(candidates, random_below);
    }

    /// [`order_candidates`] with the random source supplied: `below(n)` returns
    /// a uniform integer in `0..n`.
    ///
    /// [`order_candidates`]: DriadResolver::order_candidates
    pub fn order_candidates_with(
        candidates: &mut [DriadCandidate],
        mut below: impl FnMut(u32) -> u32,
    ) {
        // Stable insertion sort, so the shuffle below is the only source of tie
        // order. std's stable sort would add kilobytes to the browser build, and
        // an RRset is bounded by one DNS message, so the quadratic worst case
        // stays small even for a hostile reply.
        for i in 1..candidates.len() {
            let mut j = i;
            while j > 0 && candidates[j - 1].precedence > candidates[j].precedence {
                candidates.swap(j - 1, j);
                j -= 1;
            }
        }
        for tie in candidates.chunk_by_mut(|a, b| a.precedence == b.precedence) {
            // Fisher-Yates: every ordering of the tie is equally likely.
            for i in (1..tie.len()).rev() {
                let j = below(i as u32 + 1) as usize;
                tie.swap(i, j);
            }
        }
    }

    /// Collect every acceptable AMTRELAY answer, then pick by precedence.
    fn select_amtrelay(data: &[u8], expect: Option<&DnsQuestionRef>) -> Option<DriadRelayAddress> {
        Self::select_amtrelay_with(data, expect, random_below)
    }

    /// The lowest precedence wins, and among equal precedence the choice is
    /// uniformly random. RFC 8777 §3.1.2: a gateway SHOULD choose
    /// non-deterministically among equal-precedence relays, so that a source
    /// listing several relays spreads load instead of sending every gateway
    /// behind one resolver cache to the first record. `below(n)` returns a
    /// uniform integer in `0..n`.
    fn select_amtrelay_with(
        data: &[u8],
        expect: Option<&DnsQuestionRef>,
        below: impl FnOnce(u32) -> u32,
    ) -> Option<DriadRelayAddress> {
        let mut set = Self::lowest_precedence_set(data, expect)?;
        if set.is_empty() {
            return None;
        }
        let pick = below(set.len() as u32) as usize;
        Some(set.swap_remove(pick))
    }

    /// The acceptable AMTRELAY relays sharing the lowest precedence, in wire
    /// order, or `None` when the response is rejected. Derived from the same
    /// walk as the candidate list, so a selection always lies in that list.
    fn lowest_precedence_set(
        data: &[u8],
        expect: Option<&DnsQuestionRef>,
    ) -> Option<Vec<DriadRelayAddress>> {
        let candidates = Self::collect_candidates(data, expect)?;
        let Some(best) = candidates.iter().map(|c| c.precedence).min() else {
            return Some(Vec::new());
        };
        Some(
            candidates
                .into_iter()
                .filter(|c| c.precedence == best)
                .map(|c| c.relay)
                .collect(),
        )
    }

    /// Every acceptable AMTRELAY answer in wire order, or `None` when the
    /// response is rejected.
    fn collect_candidates(
        data: &[u8],
        expect: Option<&DnsQuestionRef>,
    ) -> Option<Vec<DriadCandidate>> {
        let mut candidates = Vec::new();
        Self::for_each_answer(data, AMTRELAY_TYPE, expect, |ttl, rdata| {
            // A record whose RDATA does not decode (unknown relay type, truncated
            // relay field, type 0 "no relay") is skipped, not fatal — RFC 8777
            // §4.2 requires falling through to the next candidate.
            if let Some(candidate) = Self::parse_amtrelay_candidate(ttl, rdata) {
                candidates.push(candidate);
            }
        })?;
        Some(candidates)
    }

    /// Every address answer to `query`, an A or AAAA query this module built,
    /// with its TTL and in wire order. The record type is the query's QTYPE, and
    /// the reply must match the query's transaction ID and question. Empty when
    /// the reply is rejected or carries no address of that type.
    pub fn parse_dns_addresses_validated(query: &[u8], data: &[u8]) -> Vec<DriadAddress> {
        let Some(expect) = DnsQuestionRef::from_query(query) else {
            return Vec::new();
        };
        let record_type = expect.qtype;
        let mut addresses = Vec::new();
        let walked = Self::for_each_answer(data, record_type, Some(&expect), |ttl, rdata| {
            if let Some(addr) = Self::address_from_rdata(record_type, rdata) {
                addresses.push(DriadAddress { addr, ttl });
            }
        });
        if walked.is_none() {
            return Vec::new();
        }
        addresses
    }

    /// True when `data` answers `query` (same transaction ID and question) with
    /// the TC bit set: the reply was cut to fit the transport, so its answer
    /// section may be incomplete and the query must be re-asked over TCP
    /// (RFC 1035 §4.2.1, RFC 7766 §5). A stray or forged datagram that does not
    /// bind to `query` never triggers the retry.
    pub fn is_truncated_reply(query: &[u8], data: &[u8]) -> bool {
        let Some(expect) = DnsQuestionRef::from_query(query) else {
            return false;
        };
        if data.len() < DNS_HEADER_LEN {
            return false;
        }
        let flags = u16::from_be_bytes([data[2], data[3]]);
        flags & DNS_FLAG_TC != 0 && Self::question_matches(data, &expect).is_some()
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
        Self::for_each_answer(data, record_type, expect, |_ttl, rdata| {
            if found.is_none() {
                found = Self::address_from_rdata(record_type, rdata);
            }
        })?;
        found
    }

    /// The address in an A (4-octet) or AAAA (16-octet) RDATA, or `None` when
    /// the length does not fit the type.
    fn address_from_rdata(record_type: u16, rdata: &[u8]) -> Option<IpAddr> {
        match record_type {
            DNS_TYPE_A => <[u8; 4]>::try_from(rdata)
                .ok()
                .map(|octets| IpAddr::V4(Ipv4Addr::from(octets))),
            DNS_TYPE_AAAA => <[u8; 16]>::try_from(rdata)
                .ok()
                .map(|octets| IpAddr::V6(Ipv6Addr::from(octets))),
            _ => None,
        }
    }

    /// Walk the answer section, invoking `visit` with the TTL and RDATA of every
    /// record whose TYPE and CLASS match and whose owner name matches the
    /// question. A TTL with the top bit set reads as zero (RFC 2181 §8).
    ///
    /// Returns None if the message is not a usable response at all (malformed,
    /// not a reply, RCODE set, or failing `expect`); Some(()) when the answer
    /// section was walked successfully, even if nothing matched.
    fn for_each_answer(
        data: &[u8],
        record_type: u16,
        expect: Option<&DnsQuestionRef>,
        mut visit: impl FnMut(u32, &[u8]),
    ) -> Option<()> {
        let (qname, mut offset, qclass) = Self::question_section(data, expect)?;

        let flags = u16::from_be_bytes([data[2], data[3]]);
        // No error (RCODE=0).
        if flags & 0x0F != 0 {
            return None;
        }
        let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;

        for _ in 0..ancount {
            let owner = DnsName::decode(data, offset)?;
            offset = owner.end;
            if offset + 10 > data.len() {
                return None;
            }

            let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let rclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            let ttl = u32::from_be_bytes([
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]);
            let ttl = if ttl > MAX_TTL { 0 } else { ttl };
            let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
            offset += 10;

            if offset + rdlength > data.len() {
                return None;
            }

            // Owner/class must match the question. An in-bailiwick reply can
            // otherwise smuggle a record for an unrelated name (or a bogus
            // class) into the answer section and have it read as ours.
            if rtype == record_type && rclass == qclass && DnsName::eq(data, &owner, data, &qname) {
                visit(ttl, &data[offset..offset + rdlength]);
            }

            offset += rdlength;
        }

        Some(())
    }

    /// `question_section` with the query binding required, for callers that
    /// need only the verdict.
    fn question_matches(data: &[u8], expect: &DnsQuestionRef) -> Option<()> {
        Self::question_section(data, Some(expect)).map(|_| ())
    }

    /// Check that `data` is a reply (QR=1) with exactly one question and, when
    /// `expect` is given, that its transaction ID and question match the query.
    /// Returns the question name, the offset just past the question, and its
    /// class.
    fn question_section(
        data: &[u8],
        expect: Option<&DnsQuestionRef>,
    ) -> Option<(DnsName, usize, u16)> {
        if data.len() < DNS_HEADER_LEN {
            return None;
        }

        let flags = u16::from_be_bytes([data[2], data[3]]);
        // Must be a response (QR=1).
        if (flags >> 15) & 1 != 1 {
            return None;
        }

        // Exactly one question: DRIAD never pipelines, and a multi-question
        // reply gives us no single owner name to hold answers to.
        if u16::from_be_bytes([data[4], data[5]]) != 1 {
            return None;
        }

        if let Some(expect) = expect {
            let txid = u16::from_be_bytes([data[0], data[1]]);
            if txid != expect.txid {
                return None;
            }
        }

        // Decode the question: its owner name is what every answer must match.
        let qname = DnsName::decode(data, DNS_HEADER_LEN)?;
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

        Some((qname, after_qname + 4, qclass))
    }

    /// Decode one AMTRELAY answer into a candidate: the relay plus the
    /// precedence, the D-bit and the record's TTL.
    fn parse_amtrelay_candidate(ttl: u32, rdata: &[u8]) -> Option<DriadCandidate> {
        let (precedence, relay) = Self::parse_amtrelay_record(rdata)?;
        Some(DriadCandidate {
            precedence,
            discovery_optional: rdata[1] & AMTRELAY_D_BIT != 0,
            relay,
            ttl,
        })
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
        let relay_type = rdata[1] & AMTRELAY_TYPE_MASK;

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
    use super::{DriadCandidate, DriadRelayAddress, DriadResolver};

    pub fn parse_amtrelay_rdata(rdata: &[u8]) -> Option<(u8, DriadRelayAddress)> {
        DriadResolver::parse_amtrelay_record(rdata)
    }

    pub fn parse_amtrelay_candidate(ttl: u32, rdata: &[u8]) -> Option<DriadCandidate> {
        DriadResolver::parse_amtrelay_candidate(ttl, rdata)
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

        Some(Self { labels, end: end? })
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

/// Uniform integer in `0..n` for the equal-precedence relay choice. The modulo
/// bias is below n/2^32, negligible at relay-list sizes.
fn random_below(n: u32) -> u32 {
    let mut buf = [0u8; 4];
    getrandom::getrandom(&mut buf).expect("getrandom for DRIAD relay choice");
    u32::from_le_bytes(buf) % n
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
        assert_eq!(u16::from_be_bytes([packet[4], packet[5]]), 1); // QDCOUNT
        assert_eq!(u16::from_be_bytes([packet[6], packet[7]]), 0); // ANCOUNT
        assert_eq!(u16::from_be_bytes([packet[8], packet[9]]), 0); // NSCOUNT
        assert_eq!(u16::from_be_bytes([packet[10], packet[11]]), 0); // ARCOUNT

        // QNAME for 128.95.25.69.in-addr.arpa
        let mut offset = 12;
        // "128"
        assert_eq!(packet[offset], 3);
        offset += 1;
        assert_eq!(&packet[offset..offset + 3], b"128");
        offset += 3;
        // "95"
        assert_eq!(packet[offset], 2);
        offset += 1;
        assert_eq!(&packet[offset..offset + 2], b"95");
        offset += 2;
        // "25"
        assert_eq!(packet[offset], 2);
        offset += 1;
        assert_eq!(&packet[offset..offset + 2], b"25");
        offset += 2;
        // "69"
        assert_eq!(packet[offset], 2);
        offset += 1;
        assert_eq!(&packet[offset..offset + 2], b"69");
        offset += 2;
        // "in-addr"
        assert_eq!(packet[offset], 7);
        offset += 1;
        assert_eq!(&packet[offset..offset + 7], b"in-addr");
        offset += 7;
        // "arpa"
        assert_eq!(packet[offset], 4);
        offset += 1;
        assert_eq!(&packet[offset..offset + 4], b"arpa");
        offset += 4;
        // Root label
        assert_eq!(packet[offset], 0);
        offset += 1;

        // QTYPE = 260
        assert_eq!(
            u16::from_be_bytes([packet[offset], packet[offset + 1]]),
            260
        );
        offset += 2;
        // QCLASS = 1 (IN)
        assert_eq!(u16::from_be_bytes([packet[offset], packet[offset + 1]]), 1);
    }

    /// A DRIAD response for `source` carrying one IPv4 AMTRELAY answer per
    /// `(precedence, relay)`, in the given wire order.
    fn amtrelay_v4_response(source: IpAddr, answers: &[(u8, [u8; 4])]) -> Vec<u8> {
        let mut response = DriadResolver::build_dns_query(source, 0xABCD);
        response[2] = 0x81; // QR=1, RD=1
        response[3] = 0x80; // RA=1
        response[6..8].copy_from_slice(&(answers.len() as u16).to_be_bytes());
        for (precedence, relay) in answers {
            response.extend_from_slice(&[0xC0, 0x0C]); // owner: pointer to QNAME
            response.extend_from_slice(&260u16.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&300u32.to_be_bytes());
            response.extend_from_slice(&6u16.to_be_bytes());
            response.push(*precedence);
            response.push(0x01); // D=0, type=1 (IPv4)
            response.extend_from_slice(relay);
        }
        response
    }

    #[test]
    fn equal_precedence_choice_is_driven_by_the_random_draw() {
        // RFC 8777 §3.1.2: lowest precedence first, then a non-deterministic choice
        // among equal precedence. The draw indexes the tied set in wire order, and
        // the lower-precedence relay wins regardless of wire position or draw.
        let source: IpAddr = "69.25.95.192".parse().unwrap();
        let response = amtrelay_v4_response(
            source,
            &[
                (20, [192, 0, 2, 9]),
                (10, [192, 0, 2, 1]),
                (10, [192, 0, 2, 2]),
                (10, [192, 0, 2, 3]),
            ],
        );
        let v4 = |d| {
            Some(DriadRelayAddress::Ip(IpAddr::V4(Ipv4Addr::new(
                192, 0, 2, d,
            ))))
        };
        assert_eq!(
            DriadResolver::select_amtrelay_with(&response, None, |_| 0),
            v4(1)
        );
        assert_eq!(
            DriadResolver::select_amtrelay_with(&response, None, |n| n - 1),
            v4(3)
        );
        assert_eq!(
            DriadResolver::lowest_precedence_set(&response, None),
            Some(vec![v4(1).unwrap(), v4(2).unwrap(), v4(3).unwrap()])
        );
        // The candidate list keeps the precedence-20 backup too, in wire order.
        let relays: Vec<_> = DriadResolver::parse_dns_response_candidates(&response)
            .into_iter()
            .map(|c| (c.precedence, c.relay))
            .collect();
        assert_eq!(
            relays,
            vec![
                (
                    20,
                    DriadRelayAddress::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)))
                ),
                (10, v4(1).unwrap()),
                (10, v4(2).unwrap()),
                (10, v4(3).unwrap()),
            ]
        );

        let backup_first =
            amtrelay_v4_response(source, &[(20, [192, 0, 2, 9]), (10, [192, 0, 2, 1])]);
        assert_eq!(
            DriadResolver::select_amtrelay_with(&backup_first, None, |_| 0),
            v4(1)
        );
    }

    #[test]
    fn candidate_keeps_d_bit_and_reads_a_top_bit_ttl_as_zero() {
        let source: IpAddr = "69.25.95.192".parse().unwrap();
        let mut response = amtrelay_v4_response(source, &[(10, [192, 0, 2, 1])]);
        let rdata_at = response.len() - 6;
        response[rdata_at + 1] |= AMTRELAY_D_BIT;
        // TTL(4) and RDLENGTH(2) immediately precede RDATA.
        let ttl_at = rdata_at - 6;
        response[ttl_at..ttl_at + 4].copy_from_slice(&(MAX_TTL + 1).to_be_bytes());
        assert_eq!(
            DriadResolver::parse_dns_response_candidates(&response),
            vec![DriadCandidate {
                precedence: 10,
                discovery_optional: true,
                relay: DriadRelayAddress::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
                ttl: 0,
            }]
        );
    }

    #[test]
    fn truncated_reply_is_detected_only_when_bound_to_the_query() {
        let source: IpAddr = "69.25.95.192".parse().unwrap();
        let query = DriadResolver::build_dns_query_edns(source, 0xABCD);
        let mut reply = amtrelay_v4_response(source, &[]);
        assert!(!DriadResolver::is_truncated_reply(&query, &reply));
        reply[2] |= (DNS_FLAG_TC >> 8) as u8;
        assert!(DriadResolver::is_truncated_reply(&query, &reply));
        // A truncated reply to some other query does not trigger a retry.
        let other = DriadResolver::build_dns_query_edns(source, 0x1111);
        assert!(!DriadResolver::is_truncated_reply(&other, &reply));
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
        response.push(10); // precedence
        response.push(0x01); // D=0, type=1 (IPv4)
        response.extend_from_slice(&[192, 0, 2, 1]); // relay: 192.0.2.1

        let relay = DriadResolver::parse_dns_response(&response);
        assert_eq!(
            relay,
            Some(DriadRelayAddress::Ip(IpAddr::V4(Ipv4Addr::new(
                192, 0, 2, 1
            ))))
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
        response.push(10); // precedence
        response.push(0x02); // D=0, type=2 (IPv6)
                             // 2001:db8::1
        response.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

        let relay = DriadResolver::parse_dns_response(&response);
        assert_eq!(
            relay,
            Some(DriadRelayAddress::Ip(IpAddr::V6(
                "2001:db8::1".parse().unwrap()
            )))
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
            Some(DriadRelayAddress::Ip(IpAddr::V4(Ipv4Addr::new(
                192, 0, 2, 1
            ))))
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
            2, b'i', b'd', // label "id"
            0,    // root label
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
            0x0A, 0x03, 0x05, 0x73, 0x66, 0x6F, 0x31, 0x32, 0x05, 0x62, 0x63, 0x61, 0x73, 0x74,
            0x02, 0x69, 0x64, 0x00,
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
            5, b's', b'f', b'o', b'1', b'2', 5, b'b', b'c', b'a', b's', b't', 2, b'i', b'd', 0,
        ];
        let rdlength = (2 + dns_name_wire.len()) as u16;
        response.extend_from_slice(&rdlength.to_be_bytes());
        response.push(10); // precedence
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
        assert_eq!(
            u16::from_be_bytes([packet[qtype_offset], packet[qtype_offset + 1]]),
            1
        ); // TYPE A
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
        response.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
        response.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        response.extend_from_slice(&300u32.to_be_bytes()); // TTL
        response.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH = 4
        response.extend_from_slice(&[69, 25, 95, 128]); // 69.25.95.128

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
