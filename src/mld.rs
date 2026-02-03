//! MLDv2 Multicast Listener Report Generation (RFC 3810)
//!
//! Generates MLDv2 (Multicast Listener Discovery v2) reports for IPv6 multicast.

use std::net::Ipv6Addr;
use crate::constants::MLD_V2_LISTENER_REPORT;

/// MLDv2 Multicast Address Record Type (RFC 3810 Section 5.2.12)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordType {
    /// MODE_IS_INCLUDE - Current-state record
    ModeIsInclude = 1,

    /// MODE_IS_EXCLUDE - Current-state record
    ModeIsExclude = 2,

    /// CHANGE_TO_INCLUDE_MODE - Filter-mode change record
    ChangeToIncludeMode = 3,

    /// CHANGE_TO_EXCLUDE_MODE - Filter-mode change record
    ChangeToExcludeMode = 4,

    /// ALLOW_NEW_SOURCES - Source-list change record
    AllowNewSources = 5,

    /// BLOCK_OLD_SOURCES - Source-list change record
    BlockOldSources = 6,
}

/// MLDv2 Multicast Address Record
#[derive(Debug, Clone)]
pub struct MldRecord {
    /// Record type
    pub record_type: RecordType,

    /// Multicast address
    pub multicast_address: Ipv6Addr,

    /// Source addresses (empty for ASM, one or more for SSM)
    pub source_addresses: Vec<Ipv6Addr>,
}

impl MldRecord {
    /// Create new MLD record
    pub fn new(
        record_type: RecordType,
        multicast_address: Ipv6Addr,
        source_addresses: Vec<Ipv6Addr>,
    ) -> Self {
        Self {
            record_type,
            multicast_address,
            source_addresses,
        }
    }

    /// Create SSM (source-specific) join record
    /// Uses MODE_IS_INCLUDE (Type 1) for current-state report in response to Query
    pub fn ssm_join(group: Ipv6Addr, source: Ipv6Addr) -> Self {
        Self::new(RecordType::ModeIsInclude, group, vec![source])
    }

    /// Create ASM (any-source) join record
    /// Uses MODE_IS_EXCLUDE (Type 2) for current-state report in response to Query
    pub fn asm_join(group: Ipv6Addr) -> Self {
        Self::new(RecordType::ModeIsExclude, group, vec![])
    }

    /// Encode record to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Record Type (1 byte)
        buf.push(self.record_type as u8);

        // Aux Data Len (1 byte) - always 0
        buf.push(0);

        // Number of Sources (2 bytes)
        let num_sources = self.source_addresses.len() as u16;
        buf.extend_from_slice(&num_sources.to_be_bytes());

        // Multicast Address (16 bytes)
        buf.extend_from_slice(&self.multicast_address.octets());

        // Source Addresses (16 bytes each)
        for source in &self.source_addresses {
            buf.extend_from_slice(&source.octets());
        }

        buf
    }
}

/// MLDv2 Multicast Listener Report
#[derive(Debug, Clone)]
pub struct MldV2Report {
    /// Multicast address records
    records: Vec<MldRecord>,
}

impl MldV2Report {
    /// Create new empty report
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    /// Add multicast address record
    pub fn add_record(&mut self, record: MldRecord) {
        self.records.push(record);
    }

    /// Encode report to bytes (ICMPv6 payload)
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // ICMPv6 Type (1 byte) - MLDv2 Listener Report
        buf.push(MLD_V2_LISTENER_REPORT);

        // Code (1 byte) - always 0 for MLD
        buf.push(0);

        // Checksum (2 bytes) - placeholder (computed by kernel/network stack)
        buf.extend_from_slice(&[0, 0]);

        // Reserved (2 bytes)
        buf.extend_from_slice(&[0, 0]);

        // Number of Multicast Address Records (2 bytes)
        let num_records = self.records.len() as u16;
        buf.extend_from_slice(&num_records.to_be_bytes());

        // Multicast Address Records
        for record in &self.records {
            buf.extend_from_slice(&record.encode());
        }

        buf
    }

    /// Calculate ICMPv6 checksum (RFC 2463)
    ///
    /// Note: For ICMPv6, the checksum includes a pseudo-header with source/dest IPv6 addresses.
    /// This is typically computed by the kernel, so this is a simplified version.
    pub fn calculate_checksum(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;

        // Sum all 16-bit words
        for i in (0..data.len()).step_by(2) {
            let word = if i + 1 < data.len() {
                u16::from_be_bytes([data[i], data[i + 1]]) as u32
            } else {
                // Odd length - pad with zero
                (data[i] as u32) << 8
            };

            sum += word;

            // Fold carry
            if sum > 0xFFFF {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
        }

        // One's complement
        !sum as u16
    }
}

impl Default for MldV2Report {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssm_record() {
        let group: Ipv6Addr = "ff3e::1234:5678".parse().unwrap();
        let source: Ipv6Addr = "2001:db8::1".parse().unwrap();

        let record = MldRecord::ssm_join(group, source);
        assert_eq!(record.record_type, RecordType::ModeIsInclude);
        assert_eq!(record.multicast_address, group);
        assert_eq!(record.source_addresses.len(), 1);
        assert_eq!(record.source_addresses[0], source);

        let encoded = record.encode();
        assert_eq!(encoded[0], RecordType::ModeIsInclude as u8);
        assert_eq!(u16::from_be_bytes([encoded[2], encoded[3]]), 1); // 1 source
    }

    #[test]
    fn test_asm_record() {
        let group: Ipv6Addr = "ff05::1".parse().unwrap();

        let record = MldRecord::asm_join(group);
        assert_eq!(record.record_type, RecordType::ModeIsExclude);
        assert_eq!(record.multicast_address, group);
        assert_eq!(record.source_addresses.len(), 0);

        let encoded = record.encode();
        assert_eq!(encoded[0], RecordType::ModeIsExclude as u8);
        assert_eq!(u16::from_be_bytes([encoded[2], encoded[3]]), 0); // 0 sources
    }

    #[test]
    fn test_report_encode() {
        let mut report = MldV2Report::new();

        let group: Ipv6Addr = "ff3e::1234:5678".parse().unwrap();
        let source: Ipv6Addr = "2001:db8::1".parse().unwrap();
        report.add_record(MldRecord::ssm_join(group, source));

        let encoded = report.encode();

        // Check header
        assert_eq!(encoded[0], MLD_V2_LISTENER_REPORT);
        assert_eq!(encoded[1], 0); // Code = 0
        assert_eq!(u16::from_be_bytes([encoded[6], encoded[7]]), 1); // 1 record
    }

    #[test]
    fn test_multiple_records() {
        let mut report = MldV2Report::new();

        report.add_record(MldRecord::ssm_join(
            "ff3e::1234:5678".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
        ));

        report.add_record(MldRecord::asm_join("ff05::1".parse().unwrap()));

        let encoded = report.encode();

        // Check number of records
        assert_eq!(u16::from_be_bytes([encoded[6], encoded[7]]), 2);
    }

    #[test]
    fn test_record_size() {
        let group: Ipv6Addr = "ff3e::1234:5678".parse().unwrap();
        let source: Ipv6Addr = "2001:db8::1".parse().unwrap();

        let record = MldRecord::ssm_join(group, source);
        let encoded = record.encode();

        // Type(1) + AuxLen(1) + NumSources(2) + Group(16) + Source(16) = 36 bytes
        assert_eq!(encoded.len(), 36);
    }

    #[test]
    fn test_checksum_calculation() {
        // Test with known data
        let data = vec![0x8f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        let checksum = MldV2Report::calculate_checksum(&data);

        // Verify checksum by computing sum including checksum
        let mut test_data = data.clone();
        test_data[2..4].copy_from_slice(&checksum.to_be_bytes());

        let verify = MldV2Report::calculate_checksum(&test_data);
        // Should be 0xFFFF or 0x0000 if correct
        assert!(verify == 0xFFFF || verify == 0x0000);
    }

    #[test]
    fn test_checksum_odd_length() {
        // Test with odd-length data
        let data = vec![0x8f, 0x00, 0x00, 0x00, 0x00];
        let checksum = MldV2Report::calculate_checksum(&data);

        // Checksum should be computed correctly with padding
        assert_ne!(checksum, 0);
    }
}
