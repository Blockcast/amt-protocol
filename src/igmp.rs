//! IGMPv3 Membership Report Generation (RFC 3376)
//!
//! Generates IGMPv3 Membership Reports for AMT tunnel establishment.
//! For AMT, the IGMP report must be encapsulated in an IPv4 packet.

use std::net::Ipv4Addr;
use crate::constants::IGMP_V3_MEMBERSHIP_REPORT;

/// IGMPv3 Reports destination address (RFC 3376)
pub const IGMP_V3_REPORT_DEST: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 22);

/// IPv4 Protocol number for IGMP
pub const IP_PROTOCOL_IGMP: u8 = 2;

/// IGMPv3 Group Record Type (RFC 3376 Section 4.2.12)
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

/// IGMPv3 Group Record
#[derive(Debug, Clone)]
pub struct IgmpRecord {
    /// Record type
    pub record_type: RecordType,

    /// Multicast group address
    pub multicast_address: Ipv4Addr,

    /// Source addresses (empty for ASM, one or more for SSM)
    pub source_addresses: Vec<Ipv4Addr>,
}

impl IgmpRecord {
    /// Create new IGMP record
    pub fn new(
        record_type: RecordType,
        multicast_address: Ipv4Addr,
        source_addresses: Vec<Ipv4Addr>,
    ) -> Self {
        Self {
            record_type,
            multicast_address,
            source_addresses,
        }
    }

    /// Create SSM (source-specific) join record
    /// Uses MODE_IS_INCLUDE (Type 1) for current-state report in response to Query
    pub fn ssm_join(group: Ipv4Addr, source: Ipv4Addr) -> Self {
        Self::new(RecordType::ModeIsInclude, group, vec![source])
    }

    /// Create ASM (any-source) join record
    /// Uses MODE_IS_EXCLUDE (Type 2) for current-state report in response to Query
    pub fn asm_join(group: Ipv4Addr) -> Self {
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

        // Multicast Address (4 bytes)
        buf.extend_from_slice(&self.multicast_address.octets());

        // Source Addresses (4 bytes each)
        for source in &self.source_addresses {
            buf.extend_from_slice(&source.octets());
        }

        buf
    }
}

/// IGMPv3 Membership Report
#[derive(Debug, Clone)]
pub struct IgmpV3Report {
    /// Group records
    records: Vec<IgmpRecord>,
}

impl IgmpV3Report {
    /// Create new empty report
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    /// Add group record
    pub fn add_record(&mut self, record: IgmpRecord) {
        self.records.push(record);
    }

    /// Encode report to bytes (ready for IP encapsulation)
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // IGMP Type (1 byte) - Membership Report
        buf.push(IGMP_V3_MEMBERSHIP_REPORT);

        // Reserved (1 byte)
        buf.push(0);

        // Checksum (2 bytes) - placeholder, will be calculated
        buf.extend_from_slice(&[0, 0]);

        // Reserved (2 bytes)
        buf.extend_from_slice(&[0, 0]);

        // Number of Group Records (2 bytes)
        let num_records = self.records.len() as u16;
        buf.extend_from_slice(&num_records.to_be_bytes());

        // Group Records
        for record in &self.records {
            buf.extend_from_slice(&record.encode());
        }

        // Calculate and insert checksum
        let checksum = Self::calculate_checksum(&buf);
        buf[2..4].copy_from_slice(&checksum.to_be_bytes());

        buf
    }

    /// Calculate IP checksum (RFC 1071)
    fn calculate_checksum(data: &[u8]) -> u16 {
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

    /// Encode report with IPv4 encapsulation for AMT Membership Update
    ///
    /// AMT Membership Update (RFC 7450) requires the IGMP report to be
    /// encapsulated in an IPv4 packet. This matches the go-amt implementation.
    ///
    /// For SSM joins, go-amt uses:
    /// - SrcIP = multicast source address (the sender of multicast data)
    /// - DstIP = multicast group address
    ///
    /// IPv4 Header format (24 bytes with Router Alert option):
    /// - Version=4, IHL=6 (24 bytes)
    /// - TOS=0xc0 (DSCP: Network Control)
    /// - Total Length
    /// - Identification=1
    /// - Flags=0, Fragment Offset=0
    /// - TTL=1
    /// - Protocol=2 (IGMP)
    /// - Header Checksum
    /// - Source IP = multicast source
    /// - Destination IP = multicast group
    /// - Router Alert Option (0x94, 0x04, 0x00, 0x00)
    pub fn encode_with_ip(&self, multicast_source: Ipv4Addr, multicast_group: Ipv4Addr) -> Vec<u8> {
        // First encode the IGMP report
        let igmp_report = self.encode();

        // IPv4 header with Router Alert option = 24 bytes
        let ip_header_len: u16 = 24;
        let total_len = ip_header_len + igmp_report.len() as u16;

        let mut buf = Vec::with_capacity(total_len as usize);

        // Version (4) + IHL (6 = 24 bytes / 4)
        buf.push(0x46);

        // TOS (DSCP: Network Control)
        buf.push(0xc0);

        // Total Length
        buf.extend_from_slice(&total_len.to_be_bytes());

        // Identification = 1 (matching go-amt)
        buf.extend_from_slice(&[0, 1]);

        // Flags + Fragment Offset
        buf.extend_from_slice(&[0, 0]);

        // TTL = 1 (link-local)
        buf.push(1);

        // Protocol = 2 (IGMP)
        buf.push(IP_PROTOCOL_IGMP);

        // Header Checksum - placeholder (will be calculated)
        buf.extend_from_slice(&[0, 0]);

        // Source IP = multicast source (the sender of multicast data)
        buf.extend_from_slice(&multicast_source.octets());

        // Destination IP = multicast group address
        buf.extend_from_slice(&multicast_group.octets());

        // Options padding (4 zero bytes) - matching go-amt
        // go-amt uses empty IPv4Option array then appends 4 zero bytes
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        // Calculate and insert IP header checksum
        let checksum = Self::calculate_checksum(&buf);
        buf[10..12].copy_from_slice(&checksum.to_be_bytes());

        // Append IGMP report
        buf.extend_from_slice(&igmp_report);

        buf
    }
}

impl Default for IgmpV3Report {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssm_record() {
        let group: Ipv4Addr = "232.0.0.1".parse().unwrap();
        let source: Ipv4Addr = "69.25.95.10".parse().unwrap();

        let record = IgmpRecord::ssm_join(group, source);
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
        let group: Ipv4Addr = "224.0.0.1".parse().unwrap();

        let record = IgmpRecord::asm_join(group);
        assert_eq!(record.record_type, RecordType::ModeIsExclude);
        assert_eq!(record.multicast_address, group);
        assert_eq!(record.source_addresses.len(), 0);

        let encoded = record.encode();
        assert_eq!(encoded[0], RecordType::ModeIsExclude as u8);
        assert_eq!(u16::from_be_bytes([encoded[2], encoded[3]]), 0); // 0 sources
    }

    #[test]
    fn test_report_encode() {
        let mut report = IgmpV3Report::new();

        let group: Ipv4Addr = "232.0.0.1".parse().unwrap();
        let source: Ipv4Addr = "69.25.95.10".parse().unwrap();
        report.add_record(IgmpRecord::ssm_join(group, source));

        let encoded = report.encode();

        // Check header
        assert_eq!(encoded[0], IGMP_V3_MEMBERSHIP_REPORT);
        assert_eq!(u16::from_be_bytes([encoded[6], encoded[7]]), 1); // 1 record

        // Checksum should be non-zero
        let checksum = u16::from_be_bytes([encoded[2], encoded[3]]);
        assert_ne!(checksum, 0);
    }

    #[test]
    fn test_checksum_calculation() {
        // Test with known data
        let data = vec![0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        let checksum = IgmpV3Report::calculate_checksum(&data);

        // Verify checksum by computing sum including checksum
        let mut test_data = data.clone();
        test_data[2..4].copy_from_slice(&checksum.to_be_bytes());

        let verify = IgmpV3Report::calculate_checksum(&test_data);
        // Should be 0xFFFF or 0x0000 if correct
        assert!(verify == 0xFFFF || verify == 0x0000);
    }

    #[test]
    fn test_multiple_records() {
        let mut report = IgmpV3Report::new();

        report.add_record(IgmpRecord::ssm_join(
            "232.0.0.1".parse().unwrap(),
            "69.25.95.10".parse().unwrap(),
        ));

        report.add_record(IgmpRecord::asm_join("224.0.0.1".parse().unwrap()));

        let encoded = report.encode();

        // Check number of records
        assert_eq!(u16::from_be_bytes([encoded[6], encoded[7]]), 2);
    }

    #[test]
    fn test_encode_with_ip_encapsulation() {
        let mut report = IgmpV3Report::new();
        let group: Ipv4Addr = "232.0.0.1".parse().unwrap();
        let source: Ipv4Addr = "69.25.95.10".parse().unwrap();
        report.add_record(IgmpRecord::ssm_join(group, source));

        // go-amt uses multicast source as IPv4 SrcIP and group as DstIP
        let encoded = report.encode_with_ip(source, group);

        // Check IPv4 header
        assert_eq!(encoded[0], 0x46); // Version=4, IHL=6
        assert_eq!(encoded[1], 0xc0); // TOS
        assert_eq!(encoded[8], 1);    // TTL=1
        assert_eq!(encoded[9], 2);    // Protocol=IGMP

        // Check source IP = multicast source (69.25.95.10)
        assert_eq!(&encoded[12..16], &[69, 25, 95, 10]);

        // Check destination IP = multicast group (232.0.0.1)
        assert_eq!(&encoded[16..20], &[232, 0, 0, 1]);

        // Check options padding (4 zero bytes like go-amt)
        assert_eq!(&encoded[20..24], &[0x00, 0x00, 0x00, 0x00]);

        // Check IGMP report starts at byte 24
        assert_eq!(encoded[24], IGMP_V3_MEMBERSHIP_REPORT);

        // Verify IP header checksum
        let ip_header = &encoded[0..24];
        let checksum = IgmpV3Report::calculate_checksum(ip_header);
        // If checksum is correct, recalculating should give 0xFFFF or 0x0000
        assert!(checksum == 0xFFFF || checksum == 0x0000);
    }

    #[test]
    fn test_encode_with_ip_size() {
        let mut report = IgmpV3Report::new();
        let group: Ipv4Addr = "232.0.0.1".parse().unwrap();
        let source: Ipv4Addr = "69.25.95.10".parse().unwrap();
        report.add_record(IgmpRecord::ssm_join(group, source));

        let igmp_only = report.encode();
        let with_ip = report.encode_with_ip(source, group);

        // IPv4 header with Router Alert = 24 bytes
        assert_eq!(with_ip.len(), igmp_only.len() + 24);
    }
}
