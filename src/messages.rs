//! AMT Message Types and Encoding/Decoding (RFC 7450)
//!
//! AMT uses 7 message types for the gateway-relay protocol:
//! 1. Relay Discovery (Gateway → Discovery)
//! 2. Relay Advertisement (Relay → Gateway)
//! 3. Request (Gateway → Relay)
//! 4. Membership Query (Relay → Gateway)
//! 5. Membership Update (Gateway → Relay)
//! 6. Multicast Data (Relay → Gateway)
//! 7. Teardown (Gateway → Relay)

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use crate::error::{AmtError, Result};

/// AMT Message Type (RFC 7450 Section 5.1.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    RelayDiscovery = 1,
    RelayAdvertisement = 2,
    Request = 3,
    MembershipQuery = 4,
    MembershipUpdate = 5,
    MulticastData = 6,
    Teardown = 7,
}

impl MessageType {
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            1 => Ok(MessageType::RelayDiscovery),
            2 => Ok(MessageType::RelayAdvertisement),
            3 => Ok(MessageType::Request),
            4 => Ok(MessageType::MembershipQuery),
            5 => Ok(MessageType::MembershipUpdate),
            6 => Ok(MessageType::MulticastData),
            7 => Ok(MessageType::Teardown),
            _ => Err(AmtError::InvalidMessage(format!("Unknown message type: {}", value))),
        }
    }
}

/// AMT Message
#[derive(Debug, Clone, PartialEq)]
pub enum AmtMessage {
    /// Relay Discovery (Gateway → Discovery Address)
    /// Length: 8 bytes
    RelayDiscovery {
        nonce: u32,
    },

    /// Relay Advertisement (Relay → Gateway)
    /// Length: 12 bytes (IPv4) or 24 bytes (IPv6)
    RelayAdvertisement {
        nonce: u32,
        relay_address: IpAddr,
    },

    /// Request (Gateway → Relay)
    /// Length: 8 bytes
    Request {
        request_nonce: u32,
        p_flag: bool,  // Pseudo-header checksum flag
    },

    /// Membership Query (Relay → Gateway)
    /// Length: 14+ bytes
    MembershipQuery {
        request_nonce: u32,
        response_mac: [u8; 6],
        query_data: Vec<u8>,  // IGMP/MLD Query
    },

    /// Membership Update (Gateway → Relay)
    /// Length: 14+ bytes
    MembershipUpdate {
        request_nonce: u32,
        response_mac: [u8; 6],
        report_data: Vec<u8>,  // IGMPv3/MLDv2 Report
    },

    /// Multicast Data (Relay → Gateway)
    /// Length: 2+ bytes
    MulticastData {
        ip_packet: Vec<u8>,  // Encapsulated IP packet
    },

    /// Teardown (Gateway → Relay)
    /// Length: 14 bytes
    Teardown {
        request_nonce: u32,
        response_mac: [u8; 6],
    },
}

impl AmtMessage {
    /// Encode message to bytes (RFC 7450 Section 5)
    pub fn encode(&self) -> Vec<u8> {
        match self {
            AmtMessage::RelayDiscovery { nonce } => {
                // Type (1) | Reserved (1) | Reserved (2) | Nonce (4)
                let mut buf = Vec::with_capacity(8);
                buf.push(MessageType::RelayDiscovery as u8);
                buf.push(0); // Reserved
                buf.extend_from_slice(&[0, 0]); // Reserved
                buf.extend_from_slice(&nonce.to_be_bytes());
                buf
            }

            AmtMessage::RelayAdvertisement { nonce, relay_address } => {
                match relay_address {
                    IpAddr::V4(ipv4) => {
                        // Type (1) | Reserved (1) | Reserved (2) | Nonce (4) | IPv4 (4)
                        let mut buf = Vec::with_capacity(12);
                        buf.push(MessageType::RelayAdvertisement as u8);
                        buf.push(0); // Reserved
                        buf.extend_from_slice(&[0, 0]); // Reserved
                        buf.extend_from_slice(&nonce.to_be_bytes());
                        buf.extend_from_slice(&ipv4.octets());
                        buf
                    }
                    IpAddr::V6(ipv6) => {
                        // Type (1) | Reserved (1) | Reserved (2) | Nonce (4) | IPv6 (16)
                        let mut buf = Vec::with_capacity(24);
                        buf.push(MessageType::RelayAdvertisement as u8);
                        buf.push(0); // Reserved
                        buf.extend_from_slice(&[0, 0]); // Reserved
                        buf.extend_from_slice(&nonce.to_be_bytes());
                        buf.extend_from_slice(&ipv6.octets());
                        buf
                    }
                }
            }

            AmtMessage::Request { request_nonce, p_flag } => {
                // Type (1) | P-flag (1) | Reserved (2) | Request Nonce (4)
                let mut buf = Vec::with_capacity(8);
                buf.push(MessageType::Request as u8);
                buf.push(if *p_flag { 0x80 } else { 0x00 });
                buf.extend_from_slice(&[0, 0]); // Reserved
                buf.extend_from_slice(&request_nonce.to_be_bytes());
                buf
            }

            AmtMessage::MembershipQuery { request_nonce, response_mac, query_data } => {
                // RFC 7450: Type (1) | Reserved (1) | Response MAC (6) | Request Nonce (4) | Query (...)
                let mut buf = Vec::with_capacity(12 + query_data.len());
                buf.push(MessageType::MembershipQuery as u8);
                buf.push(0); // Reserved
                buf.extend_from_slice(response_mac); // MAC at bytes 2-7
                buf.extend_from_slice(&request_nonce.to_be_bytes()); // Nonce at bytes 8-11
                buf.extend_from_slice(query_data);
                buf
            }

            AmtMessage::MembershipUpdate { request_nonce, response_mac, report_data } => {
                // RFC 7450: Type (1) | Reserved (1) | Response MAC (6) | Request Nonce (4) | Report (...)
                let mut buf = Vec::with_capacity(12 + report_data.len());
                buf.push(MessageType::MembershipUpdate as u8);
                buf.push(0); // Reserved
                buf.extend_from_slice(response_mac); // MAC at bytes 2-7
                buf.extend_from_slice(&request_nonce.to_be_bytes()); // Nonce at bytes 8-11
                buf.extend_from_slice(report_data);
                buf
            }

            AmtMessage::MulticastData { ip_packet } => {
                // Type (1) | Reserved (1) | IP Packet (...)
                let mut buf = Vec::with_capacity(2 + ip_packet.len());
                buf.push(MessageType::MulticastData as u8);
                buf.push(0); // Reserved
                buf.extend_from_slice(ip_packet);
                buf
            }

            AmtMessage::Teardown { request_nonce, response_mac } => {
                // RFC 7450: Type (1) | Reserved (1) | Response MAC (6) | Request Nonce (4)
                let mut buf = Vec::with_capacity(12);
                buf.push(MessageType::Teardown as u8);
                buf.push(0); // Reserved
                buf.extend_from_slice(response_mac); // MAC at bytes 2-7
                buf.extend_from_slice(&request_nonce.to_be_bytes()); // Nonce at bytes 8-11
                buf
            }
        }
    }

    /// Decode message from bytes (RFC 7450 Section 5)
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < 2 {
            return Err(AmtError::InvalidMessage("Message too short".into()));
        }

        let msg_type = MessageType::from_u8(buf[0])?;

        match msg_type {
            MessageType::RelayDiscovery => {
                if buf.len() < 8 {
                    return Err(AmtError::InvalidMessage("RelayDiscovery too short".into()));
                }
                let nonce = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
                Ok(AmtMessage::RelayDiscovery { nonce })
            }

            MessageType::RelayAdvertisement => {
                if buf.len() < 8 {
                    return Err(AmtError::InvalidMessage("RelayAdvertisement too short".into()));
                }

                let nonce = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);

                // Determine IPv4 or IPv6 by length
                let relay_address = if buf.len() == 12 {
                    // IPv4
                    IpAddr::V4(Ipv4Addr::new(buf[8], buf[9], buf[10], buf[11]))
                } else if buf.len() == 24 {
                    // IPv6
                    let octets: [u8; 16] = buf[8..24].try_into()
                        .map_err(|_| AmtError::InvalidMessage("Invalid IPv6 address".into()))?;
                    IpAddr::V6(Ipv6Addr::from(octets))
                } else {
                    return Err(AmtError::InvalidMessage(
                        format!("Invalid advertisement length: {}", buf.len())
                    ));
                };

                Ok(AmtMessage::RelayAdvertisement { nonce, relay_address })
            }

            MessageType::Request => {
                if buf.len() < 8 {
                    return Err(AmtError::InvalidMessage("Request too short".into()));
                }
                let p_flag = (buf[1] & 0x80) != 0;
                let request_nonce = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
                Ok(AmtMessage::Request { request_nonce, p_flag })
            }

            MessageType::MembershipQuery => {
                if buf.len() < 14 {
                    return Err(AmtError::InvalidMessage("MembershipQuery too short".into()));
                }
                // RFC 7450: Bytes 2-7 are Response MAC, bytes 8-11 are Request Nonce
                let response_mac: [u8; 6] = buf[2..8].try_into()
                    .map_err(|_| AmtError::InvalidMessage("Invalid MAC".into()))?;
                let request_nonce = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
                let query_data = buf[12..].to_vec();
                Ok(AmtMessage::MembershipQuery { request_nonce, response_mac, query_data })
            }

            MessageType::MembershipUpdate => {
                if buf.len() < 12 {
                    return Err(AmtError::InvalidMessage("MembershipUpdate too short".into()));
                }
                // RFC 7450: Bytes 2-7 are Response MAC, bytes 8-11 are Request Nonce
                let response_mac: [u8; 6] = buf[2..8].try_into()
                    .map_err(|_| AmtError::InvalidMessage("Invalid MAC".into()))?;
                let request_nonce = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
                let report_data = buf[12..].to_vec();
                Ok(AmtMessage::MembershipUpdate { request_nonce, response_mac, report_data })
            }

            MessageType::MulticastData => {
                if buf.len() < 2 {
                    return Err(AmtError::InvalidMessage("MulticastData too short".into()));
                }
                let ip_packet = buf[2..].to_vec();
                Ok(AmtMessage::MulticastData { ip_packet })
            }

            MessageType::Teardown => {
                if buf.len() < 14 {
                    return Err(AmtError::InvalidMessage("Teardown too short".into()));
                }
                let request_nonce = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
                let response_mac: [u8; 6] = buf[8..14].try_into()
                    .map_err(|_| AmtError::InvalidMessage("Invalid MAC".into()))?;
                Ok(AmtMessage::Teardown { request_nonce, response_mac })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relay_discovery_encode() {
        let msg = AmtMessage::RelayDiscovery { nonce: 0x12345678 };
        let encoded = msg.encode();

        assert_eq!(encoded.len(), 8);
        assert_eq!(encoded[0], MessageType::RelayDiscovery as u8);
        assert_eq!(&encoded[4..8], &[0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn test_relay_discovery_decode() {
        let data = vec![0x01, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78];
        let msg = AmtMessage::decode(&data).unwrap();

        match msg {
            AmtMessage::RelayDiscovery { nonce } => {
                assert_eq!(nonce, 0x12345678);
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_relay_advertisement_ipv4_encode() {
        let msg = AmtMessage::RelayAdvertisement {
            nonce: 0x12345678,
            relay_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        };
        let encoded = msg.encode();

        assert_eq!(encoded.len(), 12);
        assert_eq!(encoded[0], MessageType::RelayAdvertisement as u8);
        assert_eq!(&encoded[4..8], &[0x12, 0x34, 0x56, 0x78]);
        assert_eq!(&encoded[8..12], &[192, 0, 2, 1]);
    }

    #[test]
    fn test_relay_advertisement_ipv4_decode() {
        let data = vec![
            0x02, 0x00, 0x00, 0x00,           // Type + Reserved
            0x12, 0x34, 0x56, 0x78,           // Nonce
            192, 0, 2, 1                      // IPv4
        ];
        let msg = AmtMessage::decode(&data).unwrap();

        match msg {
            AmtMessage::RelayAdvertisement { nonce, relay_address } => {
                assert_eq!(nonce, 0x12345678);
                assert_eq!(relay_address, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_request_encode() {
        let msg = AmtMessage::Request {
            request_nonce: 0xABCDEF01,
            p_flag: true,
        };
        let encoded = msg.encode();

        assert_eq!(encoded.len(), 8);
        assert_eq!(encoded[0], MessageType::Request as u8);
        assert_eq!(encoded[1], 0x80); // P-flag set
        assert_eq!(&encoded[4..8], &[0xAB, 0xCD, 0xEF, 0x01]);
    }

    #[test]
    fn test_request_decode() {
        let data = vec![
            0x03, 0x80, 0x00, 0x00,           // Type + P-flag + Reserved
            0xAB, 0xCD, 0xEF, 0x01            // Request Nonce
        ];
        let msg = AmtMessage::decode(&data).unwrap();

        match msg {
            AmtMessage::Request { request_nonce, p_flag } => {
                assert_eq!(request_nonce, 0xABCDEF01);
                assert!(p_flag);
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_membership_update_encode() {
        let msg = AmtMessage::MembershipUpdate {
            request_nonce: 0x11223344,
            response_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            report_data: vec![0x01, 0x02, 0x03],
        };
        let encoded = msg.encode();

        // RFC 7450: Type (1) | Reserved (1) | Response MAC (6) | Request Nonce (4) | Report (...)
        // Total: 12 header + 3 data = 15 bytes
        assert_eq!(encoded.len(), 15);
        assert_eq!(encoded[0], MessageType::MembershipUpdate as u8);
        assert_eq!(encoded[1], 0); // Reserved
        assert_eq!(&encoded[2..8], &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // Response MAC
        assert_eq!(&encoded[8..12], &[0x11, 0x22, 0x33, 0x44]); // Request Nonce
        assert_eq!(&encoded[12..15], &[0x01, 0x02, 0x03]); // Report data
    }

    #[test]
    fn test_multicast_data_roundtrip() {
        let ip_packet = vec![0x45, 0x00, 0x00, 0x20]; // IP header start
        let msg = AmtMessage::MulticastData { ip_packet: ip_packet.clone() };

        let encoded = msg.encode();
        let decoded = AmtMessage::decode(&encoded).unwrap();

        match decoded {
            AmtMessage::MulticastData { ip_packet: decoded_packet } => {
                assert_eq!(decoded_packet, ip_packet);
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_invalid_message_type() {
        let data = vec![0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let result = AmtMessage::decode(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_message_too_short() {
        let data = vec![0x01]; // Only type byte
        let result = AmtMessage::decode(&data);
        assert!(result.is_err());
    }
}
