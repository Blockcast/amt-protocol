//! The one field of a relay's encapsulated General Query that the manager acts
//! on: the Querier's Robustness Variable.
//!
//! A Membership Query carries an IPv4 datagram with an IGMPv3 Membership Query,
//! or an IPv6 datagram with an MLDv2 Listener Query (RFC 7450 §5.1.4.8). Its
//! QRV is "used by a relay to specify the number of times a gateway should
//! retransmit unsolicited membership reports, encapsulated within Membership
//! Update messages" (same section).

/// IPv4 Protocol number of IGMP.
const IP_PROTOCOL_IGMP: u8 = 2;
/// IGMP Type of a Membership Query (RFC 3376 §4).
const IGMP_MEMBERSHIP_QUERY: u8 = 0x11;
/// An IGMPv3 Query is at least 12 octets; 8 octets is an IGMPv1/v2 Query,
/// which has no QRV (RFC 3376 §7.1).
const IGMPV3_QUERY_MIN_LEN: usize = 12;
/// Offset of the `Resv|S|QRV` octet in an IGMPv3 Query (RFC 3376 §4.1).
const IGMPV3_QRV_AT: usize = 8;
/// Offset and length of the Group Address in an IGMPv3 Query (RFC 3376 §4.1).
const IGMPV3_GROUP: std::ops::Range<usize> = 4..8;

/// Length of the fixed IPv6 header (RFC 8200 §3).
const IPV6_HEADER_LEN: usize = 40;
/// Next Header values of the extension headers an MLD Query may carry before
/// its ICMPv6 message: Hop-by-Hop Options (RFC 2711's Router Alert lives
/// here), Routing, and Destination Options. All share the length encoding
/// RFC 8200 §4.3 gives them. A Fragment header (44) is not walked: a fragment
/// is not a General Query this gateway can read.
const IPV6_EXT_HOP_BY_HOP: u8 = 0;
const IPV6_EXT_ROUTING: u8 = 43;
const IPV6_EXT_DESTINATION_OPTIONS: u8 = 60;
/// Next Header value of ICMPv6.
const IPV6_NEXT_ICMPV6: u8 = 58;
/// ICMPv6 Type of a Multicast Listener Query (RFC 3810 §5).
const MLD_LISTENER_QUERY: u8 = 130;
/// An MLDv2 Query is at least 28 octets; 24 octets is an MLDv1 Query, which
/// has no QRV (RFC 3810 §8.1).
const MLDV2_QUERY_MIN_LEN: usize = 28;
/// Offset of the `Resv|S|QRV` octet in an MLDv2 Query (RFC 3810 §5.1).
const MLDV2_QRV_AT: usize = 24;
/// Offset and length of the Multicast Address in an MLDv2 Query (RFC 3810 §5.1).
const MLDV2_MULTICAST_ADDRESS: std::ops::Range<usize> = 8..24;

/// QRV is the low three bits of its octet (RFC 3376 §4.1.6, RFC 3810 §5.1.8).
const QRV_MASK: u8 = 0x07;

/// The QRV of the General Query in `datagram`, the IP datagram a Membership
/// Query encapsulates, or `None` when there is no count to read: the datagram
/// is not an IGMPv3 or MLDv2 General Query, or its QRV is zero.
///
/// Zero means the querier's Robustness Variable exceeds 7 or is unstated
/// (RFC 3376 §4.1.6), and a relay "MUST set the Querier's Robustness Variable
/// (QRV) field in the General Query to a non-zero value" (RFC 7450 §5.3.3.3).
/// Neither tells the gateway how many times to send a report, so neither yields
/// one.
pub(crate) fn querier_robustness(datagram: &[u8]) -> Option<u8> {
    let qrv = match datagram.first()? >> 4 {
        4 => igmpv3_qrv(datagram)?,
        6 => mldv2_qrv(datagram)?,
        _ => return None,
    };
    (qrv != 0).then_some(qrv)
}

fn igmpv3_qrv(datagram: &[u8]) -> Option<u8> {
    let header_len = usize::from(datagram.first()? & 0x0F) * 4;
    let total_len = usize::from(u16::from_be_bytes([*datagram.get(2)?, *datagram.get(3)?]));
    // A fragment cannot be read as a whole Query: MF set, or a non-zero offset.
    let fragment = u16::from_be_bytes([*datagram.get(6)?, *datagram.get(7)?]) & 0x3FFF;
    if header_len < 20
        || total_len > datagram.len()
        || fragment != 0
        || *datagram.get(9)? != IP_PROTOCOL_IGMP
    {
        return None;
    }
    let igmp = datagram.get(header_len..total_len)?;
    if igmp.len() < IGMPV3_QUERY_MIN_LEN
        || igmp[0] != IGMP_MEMBERSHIP_QUERY
        || igmp[IGMPV3_GROUP].iter().any(|&b| b != 0)
    {
        return None;
    }
    Some(igmp[IGMPV3_QRV_AT] & QRV_MASK)
}

fn mldv2_qrv(datagram: &[u8]) -> Option<u8> {
    let payload_len = usize::from(u16::from_be_bytes([*datagram.get(4)?, *datagram.get(5)?]));
    let end = IPV6_HEADER_LEN.checked_add(payload_len)?;
    let packet = datagram.get(..end)?;
    let mut next = *packet.get(6)?;
    let mut at = IPV6_HEADER_LEN;
    while matches!(
        next,
        IPV6_EXT_HOP_BY_HOP | IPV6_EXT_ROUTING | IPV6_EXT_DESTINATION_OPTIONS
    ) {
        next = *packet.get(at)?;
        at = at.checked_add((usize::from(*packet.get(at + 1)?) + 1) * 8)?;
    }
    if next != IPV6_NEXT_ICMPV6 {
        return None;
    }
    let mld = packet.get(at..)?;
    if mld.len() < MLDV2_QUERY_MIN_LEN
        || mld[0] != MLD_LISTENER_QUERY
        || mld[MLDV2_MULTICAST_ADDRESS].iter().any(|&b| b != 0)
    {
        return None;
    }
    Some(mld[MLDV2_QRV_AT] & QRV_MASK)
}

/// Well-formed General Queries for tests here and in the manager's.
#[cfg(test)]
pub(crate) mod fixtures {
    fn checksum(words: &[u8]) -> u16 {
        let mut sum: u32 = words
            .chunks(2)
            .map(|w| u32::from(u16::from_be_bytes([w[0], *w.get(1).unwrap_or(&0)])))
            .sum();
        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// IPv4 with a Router Alert option (RFC 2113) to 224.0.0.1, TTL 1,
    /// carrying an IGMPv3 General Query (RFC 3376 §4.1) whose `Resv|S|QRV`
    /// octet is `s_qrv`.
    pub(crate) fn igmpv3_general_query(s_qrv: u8) -> Vec<u8> {
        let mut igmp = vec![0x11, 1, 0, 0, 0, 0, 0, 0, s_qrv, 125, 0, 0];
        let c = checksum(&igmp);
        igmp[2..4].copy_from_slice(&c.to_be_bytes());
        let total = (24 + igmp.len()) as u16;
        let mut ip = vec![0x46, 0xC0];
        ip.extend_from_slice(&total.to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0, 0, 1, 2, 0, 0]);
        ip.extend_from_slice(&[192, 0, 2, 96]);
        ip.extend_from_slice(&[224, 0, 0, 1]);
        ip.extend_from_slice(&[0x94, 0x04, 0, 0]);
        let c = checksum(&ip);
        ip[10..12].copy_from_slice(&c.to_be_bytes());
        ip.extend_from_slice(&igmp);
        ip
    }

    /// IPv6 to ff02::1, hop limit 1, with a Hop-by-Hop Router Alert (RFC
    /// 2711), carrying an MLDv2 General Query (RFC 3810 §5.1) whose
    /// `Resv|S|QRV` octet is `s_qrv`. The ICMPv6 checksum is left zero: no
    /// reader here checks it.
    pub(crate) fn mldv2_general_query(s_qrv: u8) -> Vec<u8> {
        let mut mld = vec![130, 0, 0, 0, 0x03, 0xE8, 0, 0];
        mld.extend_from_slice(&[0; 16]);
        mld.extend_from_slice(&[s_qrv, 125, 0, 0]);
        let hbh = [58, 0, 0x05, 0x02, 0x00, 0x00, 0x01, 0x00];
        let mut ip = vec![0x60, 0, 0, 0];
        ip.extend_from_slice(&((hbh.len() + mld.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 1]);
        ip.extend_from_slice(&[0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        ip.extend_from_slice(&[0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        ip.extend_from_slice(&hbh);
        ip.extend_from_slice(&mld);
        ip
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::{igmpv3_general_query, mldv2_general_query};
    use super::*;

    #[test]
    fn reads_the_qrv_of_an_igmpv3_general_query() {
        assert_eq!(querier_robustness(&igmpv3_general_query(2)), Some(2));
        assert_eq!(querier_robustness(&igmpv3_general_query(7)), Some(7));
    }

    /// Resv and S share the octet with QRV and must not leak into it.
    #[test]
    fn reads_qrv_alone_out_of_its_octet() {
        assert_eq!(
            querier_robustness(&igmpv3_general_query(0xF0 | 0x08 | 3)),
            Some(3)
        );
        assert_eq!(
            querier_robustness(&mldv2_general_query(0xF0 | 0x08 | 3)),
            Some(3)
        );
    }

    #[test]
    fn reads_an_igmpv3_general_query_without_ip_options() {
        let with_ra = igmpv3_general_query(2);
        let mut plain = vec![0x45, 0xC0];
        plain.extend_from_slice(&((20 + 12) as u16).to_be_bytes());
        plain.extend_from_slice(&with_ra[4..20]);
        plain.extend_from_slice(&with_ra[24..]);
        assert_eq!(querier_robustness(&plain), Some(2));
    }

    #[test]
    fn a_zero_qrv_yields_no_count() {
        assert_eq!(querier_robustness(&igmpv3_general_query(0)), None);
        assert_eq!(querier_robustness(&mldv2_general_query(0)), None);
    }

    #[test]
    fn an_igmpv2_query_has_no_qrv() {
        let mut q = igmpv3_general_query(2);
        q.truncate(24 + 8);
        q[2..4].copy_from_slice(&((24 + 8) as u16).to_be_bytes());
        assert_eq!(querier_robustness(&q), None);
    }

    #[test]
    fn a_group_specific_query_is_not_a_general_query() {
        let mut q = igmpv3_general_query(2);
        q[24 + 4..24 + 8].copy_from_slice(&[232, 0, 0, 1]);
        assert_eq!(querier_robustness(&q), None);
        let mut q = mldv2_general_query(2);
        q[48 + 8] = 0xFF;
        assert_eq!(querier_robustness(&q), None);
    }

    #[test]
    fn rejects_what_is_not_an_igmp_query() {
        let mut not_igmp = igmpv3_general_query(2);
        not_igmp[9] = 17;
        assert_eq!(querier_robustness(&not_igmp), None);
        let mut report = igmpv3_general_query(2);
        report[24] = 0x22;
        assert_eq!(querier_robustness(&report), None);
        let mut fragment = igmpv3_general_query(2);
        fragment[6] = 0x20;
        assert_eq!(querier_robustness(&fragment), None);
    }

    #[test]
    fn rejects_truncated_and_placeholder_datagrams() {
        let q = igmpv3_general_query(2);
        for len in 0..q.len() {
            assert_eq!(querier_robustness(&q[..len]), None, "{len} bytes");
        }
        let q = mldv2_general_query(2);
        for len in 0..q.len() {
            assert_eq!(querier_robustness(&q[..len]), None, "{len} bytes");
        }
        assert_eq!(querier_robustness(&[0x11; 12]), None);
        assert_eq!(querier_robustness(&[]), None);
    }

    #[test]
    fn reads_the_qrv_of_an_mldv2_general_query_behind_hop_by_hop() {
        assert_eq!(querier_robustness(&mldv2_general_query(2)), Some(2));
    }

    #[test]
    fn an_mldv1_query_has_no_qrv() {
        let mut q = mldv2_general_query(2);
        q.truncate(48 + 24);
        q[4..6].copy_from_slice(&((8 + 24) as u16).to_be_bytes());
        assert_eq!(querier_robustness(&q), None);
    }

    #[test]
    fn rejects_an_mld_message_that_is_not_a_listener_query() {
        let mut q = mldv2_general_query(2);
        q[48] = 143;
        assert_eq!(querier_robustness(&q), None);
        let mut q = mldv2_general_query(2);
        q[40] = 17;
        assert_eq!(querier_robustness(&q), None);
    }
}
