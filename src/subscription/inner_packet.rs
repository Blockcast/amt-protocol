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
    if ihl < 20 || bytes.len() < ihl + 8 {
        return Err(AmtError::MalformedInner);
    }
    if bytes[9] != IP_PROTOCOL_UDP {
        return Err(AmtError::MalformedInner);
    }
    let src = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
    let dst = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);
    let udp = &bytes[ihl..];
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
    if bytes[6] != IPV6_NEXT_UDP {
        return Err(AmtError::MalformedInner);
    }
    let src_octets: [u8; 16] = bytes[8..24].try_into().map_err(|_| AmtError::MalformedInner)?;
    let dst_octets: [u8; 16] = bytes[24..40].try_into().map_err(|_| AmtError::MalformedInner)?;
    let udp = &bytes[40..];
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
}
