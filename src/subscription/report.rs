//! IGMPv3 / MLDv2 report assembly from a group set.
//!
//! Produces the bytes that go into AmtMessage::MembershipUpdate.report_data.

use std::net::IpAddr;
use crate::error::{AmtError, Result};
use crate::gateway::GroupKey;
use crate::igmp::{IgmpRecord, IgmpV3Report, RecordType as IgmpRecordType};
use crate::mld::{MldRecord, MldV2Report};

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
    Ok(report.encode())
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
    Ok(report.encode())
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
    Ok(report.encode())
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
    Ok(report.encode())
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
    Ok(report.encode())
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
    Ok(report.encode())
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

    #[test]
    fn current_state_v4_emits_one_record_per_group() {
        let keys = vec![
            k("232.0.0.1", Some("10.0.0.1")),
            k("232.0.0.2", Some("10.0.0.1")),
        ];
        let bytes = build_current_state_v4(keys.iter()).unwrap();
        assert!(!bytes.is_empty());
        // IGMPv3 report type = 0x22, number of group records at offset 6-7 (big-endian).
        assert_eq!(bytes[0], 0x22);
        assert_eq!(u16::from_be_bytes([bytes[6], bytes[7]]), 2);
    }

    #[test]
    fn allow_v4_emits_allow_new_sources_record() {
        let bytes = build_allow_v4(&k("232.0.0.1", Some("10.0.0.1"))).unwrap();
        // First group record starts at offset 8: record_type (1 byte).
        assert_eq!(bytes[8], 5, "record type should be ALLOW_NEW_SOURCES");
    }

    #[test]
    fn block_v4_emits_block_old_sources_record() {
        let bytes = build_block_v4(&k("232.0.0.1", Some("10.0.0.1"))).unwrap();
        assert_eq!(bytes[8], 6, "record type should be BLOCK_OLD_SOURCES");
    }

    #[test]
    fn family_mismatch_returns_err() {
        let v6 = k("ff0e::1", Some("2001:db8::1"));
        assert_eq!(build_allow_v4(&v6).unwrap_err(), AmtError::FamilyMismatch);
    }
}
