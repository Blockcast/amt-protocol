//! Parser for inner IPv4/IPv6 + UDP packets carried inside AMT MulticastData.
//!
//! Returns (src, group, src_port, dst_port, payload). Best-effort — caller
//! treats parse failure as a `Warning(MalformedInner)` event, not fatal.
//!
//! **Deliberate limitation**: IPv6 packets with extension headers
//! (Hop-by-Hop, Routing, Fragment, ESP, AH, Destination Options) are NOT
//! decoded. Only IPv6 packets whose `Next Header` is directly UDP (17)
//! are accepted; anything else returns `MalformedInner`. AMT data from
//! a relay rarely carries extension headers in practice, and walking them
//! is a separate ~80 LOC concern. If real traffic needs them, lift this
//! limitation in a follow-up.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use crate::error::{AmtError, Result};

#[derive(Debug, Clone, PartialEq)]
pub struct InnerPacket<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

const IP_PROTOCOL_UDP: u8 = 17;
const IPV6_NEXT_UDP: u8 = 17;

pub fn parse_inner(bytes: &[u8]) -> Result<InnerPacket<'_>> {
    if bytes.is_empty() {
        return Err(AmtError::MalformedInner);
    }
    let version = bytes[0] >> 4;
    match version {
        4 => parse_ipv4(bytes),
        6 => parse_ipv6(bytes),
        _ => Err(AmtError::MalformedInner),
    }
}

fn parse_ipv4(bytes: &[u8]) -> Result<InnerPacket<'_>> {
    if bytes.len() < 20 {
        return Err(AmtError::MalformedInner);
    }
    let ihl = (bytes[0] & 0x0F) as usize * 4;
    if ihl < 20 {
        return Err(AmtError::MalformedInner);
    }
    // IP total length is authoritative; trailing bytes are not part of this datagram.
    let total_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    if total_len < ihl + 8 || bytes.len() < total_len {
        return Err(AmtError::MalformedInner);
    }
    if bytes[9] != IP_PROTOCOL_UDP {
        return Err(AmtError::MalformedInner);
    }
    let src = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
    let dst = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);
    let udp = &bytes[ihl..total_len];  // trimmed to declared IP boundary
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if udp_len < 8 || udp.len() < udp_len {
        return Err(AmtError::MalformedInner);
    }
    Ok(InnerPacket {
        src: IpAddr::V4(src),
        dst: IpAddr::V4(dst),
        src_port,
        dst_port,
        payload: &udp[8..udp_len],
    })
}

fn parse_ipv6(bytes: &[u8]) -> Result<InnerPacket<'_>> {
    if bytes.len() < 40 + 8 {
        return Err(AmtError::MalformedInner);
    }
    // IPv6 payload length is authoritative; field excludes the 40-byte fixed header.
    let payload_len = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
    if payload_len < 8 || bytes.len() < 40 + payload_len {
        return Err(AmtError::MalformedInner);
    }
    if bytes[6] != IPV6_NEXT_UDP {
        return Err(AmtError::MalformedInner);
    }
    let src_octets: [u8; 16] = bytes[8..24].try_into().map_err(|_| AmtError::MalformedInner)?;
    let dst_octets: [u8; 16] = bytes[24..40].try_into().map_err(|_| AmtError::MalformedInner)?;
    let udp = &bytes[40..40 + payload_len];  // trimmed to declared IPv6 boundary
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if udp_len < 8 || udp.len() < udp_len {
        return Err(AmtError::MalformedInner);
    }
    Ok(InnerPacket {
        src: IpAddr::V6(Ipv6Addr::from(src_octets)),
        dst: IpAddr::V6(Ipv6Addr::from(dst_octets)),
        src_port,
        dst_port,
        payload: &udp[8..udp_len],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_udp_packet(src: [u8; 4], dst: [u8; 4], sp: u16, dp: u16, payload: &[u8]) -> Vec<u8> {
        let total_len = (20 + 8 + payload.len()) as u16;
        let mut buf = vec![
            0x45, 0x00,                          // version+IHL, ToS
            (total_len >> 8) as u8, total_len as u8,
            0x00, 0x00, 0x40, 0x00, 0x40,        // ID, flags, frag, TTL
            17,                                  // protocol UDP
            0x00, 0x00,                          // checksum (ignored)
        ];
        buf.extend_from_slice(&src);
        buf.extend_from_slice(&dst);
        // UDP header
        buf.extend_from_slice(&sp.to_be_bytes());
        buf.extend_from_slice(&dp.to_be_bytes());
        let udp_len = (8 + payload.len()) as u16;
        buf.extend_from_slice(&udp_len.to_be_bytes());
        buf.extend_from_slice(&[0, 0]); // checksum
        buf.extend_from_slice(payload);
        buf
    }

    #[test]
    fn parse_ipv4_udp_happy_path() {
        let pkt = ipv4_udp_packet([10, 0, 0, 1], [232, 0, 0, 1], 5004, 5004, b"hello");
        let p = parse_inner(&pkt).unwrap();
        assert_eq!(p.src, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(p.dst, "232.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(p.src_port, 5004);
        assert_eq!(p.dst_port, 5004);
        assert_eq!(p.payload, b"hello");
    }

    #[test]
    fn parse_truncated_returns_err() {
        let p = parse_inner(&[0x45, 0x00, 0x00]);
        assert_eq!(p, Err(AmtError::MalformedInner));
    }

    #[test]
    fn parse_non_udp_returns_err() {
        let mut pkt = ipv4_udp_packet([10, 0, 0, 1], [232, 0, 0, 1], 5004, 5004, b"x");
        pkt[9] = 6; // TCP
        assert_eq!(parse_inner(&pkt), Err(AmtError::MalformedInner));
    }

    #[test]
    fn parse_unknown_version_returns_err() {
        assert_eq!(parse_inner(&[0x50; 40]), Err(AmtError::MalformedInner));
    }

    #[test]
    fn parse_ipv6_udp_happy_path() {
        let mut pkt = vec![0x60, 0x00, 0x00, 0x00];
        let payload_len: u16 = 8 + 3;
        pkt.extend_from_slice(&payload_len.to_be_bytes());
        pkt.push(17); // next header UDP
        pkt.push(64); // hop limit
        pkt.extend_from_slice(&[0xfd; 16]); // src
        let mut dst = vec![0xff, 0x0e]; dst.extend_from_slice(&[0; 14]); pkt.extend_from_slice(&dst);
        pkt.extend_from_slice(&5004u16.to_be_bytes());
        pkt.extend_from_slice(&5005u16.to_be_bytes());
        pkt.extend_from_slice(&payload_len.to_be_bytes());
        pkt.extend_from_slice(&[0, 0]); // checksum
        pkt.extend_from_slice(b"abc");
        let p = parse_inner(&pkt).unwrap();
        assert_eq!(p.src_port, 5004);
        assert_eq!(p.dst_port, 5005);
        assert_eq!(p.payload, b"abc");
    }

    #[test]
    fn parse_ipv4_with_options_ihl_6() {
        // IHL = 6 (24-byte header). Insert a 4-byte option word at the end of the
        // mandatory 20-byte header so the parser must skip past it to find UDP.
        let mut pkt = ipv4_udp_packet([10, 0, 0, 1], [232, 0, 0, 1], 5004, 5005, b"hi");
        // Bump IHL nibble: 0x45 → 0x46
        pkt[0] = 0x46;
        // Insert 4 zero option bytes after the 20-byte fixed header (before UDP).
        let opt_pos = 20;
        for _ in 0..4 { pkt.insert(opt_pos, 0); }
        // Re-stamp total_length (bytes 2-3) — new total is original + 4.
        let new_total = (24 + 8 + 2) as u16;
        pkt[2] = (new_total >> 8) as u8;
        pkt[3] = new_total as u8;
        let p = parse_inner(&pkt).unwrap();
        assert_eq!(p.src_port, 5004);
        assert_eq!(p.dst_port, 5005);
        assert_eq!(p.payload, b"hi");
    }

    #[test]
    fn parse_ipv6_non_udp_next_header_returns_err() {
        // IPv6 Hop-by-Hop (Next Header = 0). Per the deliberate-limitation
        // doc comment, extension headers are NOT walked — the parser must
        // return MalformedInner.
        let mut pkt = vec![0x60, 0x00, 0x00, 0x00];
        let payload_len: u16 = 8 + 1;
        pkt.extend_from_slice(&payload_len.to_be_bytes());
        pkt.push(0);  // Next Header = Hop-by-Hop (NOT UDP)
        pkt.push(64); // hop limit
        pkt.extend_from_slice(&[0xfd; 16]);
        let mut dst = vec![0xff, 0x0e]; dst.extend_from_slice(&[0; 14]); pkt.extend_from_slice(&dst);
        pkt.extend_from_slice(&5004u16.to_be_bytes());
        pkt.extend_from_slice(&5005u16.to_be_bytes());
        pkt.extend_from_slice(&payload_len.to_be_bytes());
        pkt.extend_from_slice(&[0, 0]);
        pkt.push(0xAA);
        assert_eq!(parse_inner(&pkt), Err(AmtError::MalformedInner));
    }

    #[test]
    fn parse_ipv4_udp_zero_payload() {
        // udp_len = 8 (UDP header only, no payload). Must succeed; payload empty.
        let pkt = ipv4_udp_packet([10, 0, 0, 1], [232, 0, 0, 1], 5004, 5005, b"");
        let p = parse_inner(&pkt).unwrap();
        assert_eq!(p.payload, b"");
        assert_eq!(p.src_port, 5004);
        assert_eq!(p.dst_port, 5005);
    }
}
