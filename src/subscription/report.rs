//! IGMPv3 / MLDv2 report assembly from a group set.
//!
//! Produces the bytes that go into AmtMessage::MembershipUpdate.report_data.
//!
//! Per RFC 7450 §5.1.5 the Update payload must be a full IP packet
//! ("Encapsulated Group Membership Update — IPv4:IGMP(Membership Report) /
//! IPv6:MLDv2(Listener Report)"). The kernel relay's amt_update_handler
//! calls ip_mc_check_igmp / ipv6_mc_check_mld which expect a valid IP
//! header in front of the IGMP/MLD body — without it the Update is
//! silently dropped and no upstream join is installed.
//!
//! IP envelope conventions:
//!   v4: src=0.0.0.0, dst=224.0.0.22 (IGMPv3 reports) + RouterAlert option
//!   v6: src=::,      dst=ff02::16   (MLDv2 reports)  + HBH RouterAlert
//! Records inside the IP packet carry the actual (S, G) tuples.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use crate::error::{AmtError, Result};
use crate::gateway::GroupKey;
use crate::igmp::{IgmpRecord, IgmpV3Report, RecordType as IgmpRecordType};
use crate::mld::{MldRecord, MldV2Report};

/// Canonical IPv4 destination for IGMPv3 Reports per RFC 3376 §4.2.
const IGMPV3_REPORTS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 22);
/// Canonical IPv6 destination for MLDv2 Reports per RFC 3810 §5.2.14.
const MLDV2_REPORTS_GROUP: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x16);

/// Build a current-state IGMPv3 report covering all v4 (S,G) entries in `keys`.
/// Used at handshake completion (response to MembershipQuery) and keep-alive.
pub fn build_current_state_v4<'a, I: IntoIterator<Item = &'a GroupKey>>(
    keys: I,
) -> Result<Vec<u8>> {
    let mut report = IgmpV3Report::new();
    let mut any = false;
    for k in keys {
        match (k.group, k.source) {
            (IpAddr::V4(g), Some(IpAddr::V4(s))) => {
                report.add_record(IgmpRecord::ssm_join(g, s));
                any = true;
            }
            (IpAddr::V4(g), None) => {
                report.add_record(IgmpRecord::asm_join(g));
                any = true;
            }
            _ => return Err(AmtError::FamilyMismatch),
        }
    }
    if !any {
        // An empty current-state report is well-formed but rare; return zero records.
    }
    // Wrap in IPv4+RouterAlert envelope so the relay's ip_mc_check_igmp
    // accepts the inner. Source=0.0.0.0 is RFC-3376-canonical for hosts
    // that haven't assigned themselves an IP yet; the relay only uses the
    // header to validate framing, the (S, G) data is in the records.
    Ok(report.encode_with_ip(Ipv4Addr::UNSPECIFIED, IGMPV3_REPORTS_GROUP))
}

/// Build a current-state MLDv2 report covering all v6 (S,G) entries in `keys`.
pub fn build_current_state_v6<'a, I: IntoIterator<Item = &'a GroupKey>>(
    keys: I,
) -> Result<Vec<u8>> {
    let mut report = MldV2Report::new();
    for k in keys {
        match (k.group, k.source) {
            (IpAddr::V6(g), Some(IpAddr::V6(s))) => {
                report.add_record(MldRecord::ssm_join(g, s));
            }
            (IpAddr::V6(g), None) => {
                report.add_record(MldRecord::asm_join(g));
            }
            _ => return Err(AmtError::FamilyMismatch),
        }
    }
    Ok(report.encode_with_ip(Ipv6Addr::UNSPECIFIED, MLDV2_REPORTS_GROUP))
}

/// Build an incremental IGMPv3 record for one new (S,G) join in Active state.
pub fn build_allow_v4(key: &GroupKey) -> Result<Vec<u8>> {
    let mut report = IgmpV3Report::new();
    match (key.group, key.source) {
        (IpAddr::V4(g), Some(IpAddr::V4(s))) => {
            report.add_record(IgmpRecord::new(IgmpRecordType::AllowNewSources, g, vec![s]));
        }
        (IpAddr::V4(g), None) => {
            report.add_record(IgmpRecord::asm_join(g));
        }
        _ => return Err(AmtError::FamilyMismatch),
    }
    Ok(report.encode_with_ip(Ipv4Addr::UNSPECIFIED, IGMPV3_REPORTS_GROUP))
}

/// Build an incremental IGMPv3 BLOCK record for unsubscribe in Active state.
pub fn build_block_v4(key: &GroupKey) -> Result<Vec<u8>> {
    let mut report = IgmpV3Report::new();
    match (key.group, key.source) {
        (IpAddr::V4(g), Some(IpAddr::V4(s))) => {
            report.add_record(IgmpRecord::new(IgmpRecordType::BlockOldSources, g, vec![s]));
        }
        (IpAddr::V4(g), None) => {
            report.add_record(IgmpRecord::new(IgmpRecordType::ChangeToIncludeMode, g, vec![]));
        }
        _ => return Err(AmtError::FamilyMismatch),
    }
    Ok(report.encode_with_ip(Ipv4Addr::UNSPECIFIED, IGMPV3_REPORTS_GROUP))
}

/// Build an incremental MLDv2 ALLOW record for one new v6 (S,G) join in Active state.
/// MLDv2 record types mirror IGMPv3 (RFC 3810 §5.2.12); ALLOW_NEW_SOURCES = 5.
pub fn build_allow_v6(key: &GroupKey) -> Result<Vec<u8>> {
    use crate::mld::RecordType as MldRecordType;
    let mut report = MldV2Report::new();
    match (key.group, key.source) {
        (IpAddr::V6(g), Some(IpAddr::V6(s))) => {
            report.add_record(MldRecord::new(MldRecordType::AllowNewSources, g, vec![s]));
        }
        (IpAddr::V6(g), None) => {
            report.add_record(MldRecord::asm_join(g));
        }
        _ => return Err(AmtError::FamilyMismatch),
    }
    Ok(report.encode_with_ip(Ipv6Addr::UNSPECIFIED, MLDV2_REPORTS_GROUP))
}

/// Build an incremental MLDv2 BLOCK record for v6 unsubscribe in Active state.
pub fn build_block_v6(key: &GroupKey) -> Result<Vec<u8>> {
    use crate::mld::RecordType as MldRecordType;
    let mut report = MldV2Report::new();
    match (key.group, key.source) {
        (IpAddr::V6(g), Some(IpAddr::V6(s))) => {
            report.add_record(MldRecord::new(MldRecordType::BlockOldSources, g, vec![s]));
        }
        (IpAddr::V6(g), None) => {
            report.add_record(MldRecord::new(MldRecordType::ChangeToIncludeMode, g, vec![]));
        }
        _ => return Err(AmtError::FamilyMismatch),
    }
    Ok(report.encode_with_ip(Ipv6Addr::UNSPECIFIED, MLDV2_REPORTS_GROUP))
}

// Note: mld.rs already exposes RecordType (not MldRecordType) — the v6 helpers
// above import it as `RecordType as MldRecordType` for symmetry with the v4
// path which uses `RecordType as IgmpRecordType`. No changes needed to mld.rs.

#[cfg(test)]
mod tests {
    use super::*;

    fn k(group: &str, source: Option<&str>) -> GroupKey {
        GroupKey {
            group: group.parse().unwrap(),
            source: source.map(|s| s.parse().unwrap()),
        }
    }

    // Reports are now wrapped in IPv4 (24B = 20 header + 4 RA option) before
    // the IGMP body — IGMP type lands at offset 24, num-records at 30-31,
    // first record at offset 32.
    const V4_IGMP_OFF: usize = 24;
    // v6 reports get IPv6 (40B) + HBH RA (8B) = 48 bytes before the ICMPv6.
    const V6_MLD_OFF: usize = 48;

    #[test]
    fn current_state_v4_wraps_in_ip_with_records() {
        let keys = vec![
            k("232.0.0.1", Some("10.0.0.1")),
            k("232.0.0.2", Some("10.0.0.1")),
        ];
        let bytes = build_current_state_v4(keys.iter()).unwrap();
        // IP header: version=4, IHL=6 (0x46), then ToS=0xc0.
        assert_eq!(bytes[0], 0x46);
        assert_eq!(bytes[1], 0xc0);
        // dst (offset 16..20) is the RFC-3376 IGMPv3 Reports group.
        assert_eq!(&bytes[16..20], &[224, 0, 0, 22]);
        // IGMPv3 Report type at +24, num-records at +30..32 (big-endian).
        assert_eq!(bytes[V4_IGMP_OFF], 0x22);
        assert_eq!(u16::from_be_bytes([bytes[V4_IGMP_OFF + 6], bytes[V4_IGMP_OFF + 7]]), 2);
    }

    #[test]
    fn allow_v4_emits_allow_new_sources_record() {
        let bytes = build_allow_v4(&k("232.0.0.1", Some("10.0.0.1"))).unwrap();
        // First group record starts at IGMP offset +8.
        assert_eq!(bytes[V4_IGMP_OFF + 8], 5, "record type should be ALLOW_NEW_SOURCES");
    }

    #[test]
    fn block_v4_emits_block_old_sources_record() {
        let bytes = build_block_v4(&k("232.0.0.1", Some("10.0.0.1"))).unwrap();
        assert_eq!(bytes[V4_IGMP_OFF + 8], 6, "record type should be BLOCK_OLD_SOURCES");
    }

    #[test]
    fn allow_v6_wraps_in_ipv6_with_hbh_router_alert() {
        let bytes = build_allow_v6(&k("ff3e::1", Some("2001:db8::1"))).unwrap();
        // IPv6 header: version=6 in top nibble of byte 0.
        assert_eq!(bytes[0] >> 4, 6);
        // Next header (byte 6) = 0 (Hop-by-Hop Options).
        assert_eq!(bytes[6], 0);
        // dst (offset 24..40) is ff02::16, the all-MLDv2-routers group.
        assert_eq!(bytes[24], 0xff);
        assert_eq!(bytes[25], 0x02);
        assert_eq!(bytes[39], 0x16);
        // HBH header at offset 40: next=58 (ICMPv6), hdr_ext_len=0.
        assert_eq!(bytes[40], 58);
        assert_eq!(bytes[41], 0);
        // MLDv2 Listener Report type 143 at offset 48.
        assert_eq!(bytes[V6_MLD_OFF], 143);
    }

    #[test]
    fn family_mismatch_returns_err() {
        let v6 = k("ff0e::1", Some("2001:db8::1"));
        assert_eq!(build_allow_v4(&v6).unwrap_err(), AmtError::FamilyMismatch);
    }
}
