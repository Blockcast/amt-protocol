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

use crate::error::{AmtError, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Type, Reserved, Response MAC and Request Nonce: the 1 + 1 + 6 + 4 bytes
/// that open the Membership Query, Membership Update and Teardown messages
/// alike (RFC 7450 Figures 14, 16 and 17).
const NONCE_MAC_HEADER_LEN: usize = 12;

/// The decoder's floor for a Membership Query, unchanged here; the G flag
/// raises it by the Gateway Address fields.
const MEMBERSHIP_QUERY_MIN_LEN: usize = 14;

/// Gateway Address (G) flag of a Membership Query (RFC 7450 §5.1.4.5). It is
/// bit 15 of the first word in Figure 14 (`| Reserved  |L|G|`), so the low bit
/// of the byte after the type.
const QUERY_G_FLAG: u8 = 0x01;

/// Gateway Port Number: "A 16-bit UDP port number" (RFC 7450 §5.1.4.9.1,
/// §5.1.7.6).
const GATEWAY_PORT_LEN: usize = 2;

/// Gateway IP Address: "A 16-byte IP address" (RFC 7450 §5.1.4.9.2,
/// §5.1.7.7).
const GATEWAY_IP_LEN: usize = 16;

/// The Gateway Address fields together. They trail a Membership Query whose G
/// flag is set -- §5.1.4.9 locates them by subtracting "the total length of
/// the fields (18 bytes)" from the datagram length -- and they end a Teardown.
const GATEWAY_ADDRESS_FIELDS_LEN: usize = GATEWAY_PORT_LEN + GATEWAY_IP_LEN;

/// A Teardown is fixed-length (RFC 7450 §5.1.7, Figure 17).
const TEARDOWN_LEN: usize = NONCE_MAC_HEADER_LEN + GATEWAY_ADDRESS_FIELDS_LEN;

/// Gateway Address fields (RFC 7450 §5.1.4.9): this gateway's tunnel endpoint
/// **as the relay observed it**, i.e. after any NAT between the two.
///
/// A relay that supports the Teardown procedure returns them in its Membership
/// Queries with the G flag set. The gateway copies them into its Teardown
/// (§5.2.3.7.2), and the relay authenticates that Teardown's Response MAC
/// against exactly these values rather than against the datagram's source
/// address (§5.3.3.5) -- which is what lets a gateway tear down a tunnel from
/// an endpoint the NAT has since remapped. The gateway cannot compute them
/// itself: its own socket address is the pre-NAT one.
///
/// `address` is the 16-byte wire field as the relay sent it: an IPv6 address,
/// or an IPv4 address stored as an IPv4-compatible IPv6 address (§5.1.4.9.2).
/// It is carried verbatim, never reinterpreted, because the relay's MAC covers
/// these exact bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GatewayAddress {
    /// Gateway Port Number: the UDP source port of the Request that triggered
    /// the Query, as the relay saw it (§5.1.4.9.1).
    pub port: u16,
    /// Gateway IP Address (§5.1.4.9.2).
    pub address: Ipv6Addr,
}

impl GatewayAddress {
    fn encode_into(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.port.to_be_bytes());
        buf.extend_from_slice(&self.address.octets());
    }

    fn decode(fields: &[u8]) -> Result<Self> {
        let fields: &[u8; GATEWAY_ADDRESS_FIELDS_LEN] = fields.try_into().map_err(|_| {
            AmtError::InvalidMessage(format!(
                "Gateway Address fields must be {GATEWAY_ADDRESS_FIELDS_LEN} bytes, got {}",
                fields.len()
            ))
        })?;
        let (port, address) = fields.split_at(GATEWAY_PORT_LEN);
        let mut octets = [0u8; GATEWAY_IP_LEN];
        octets.copy_from_slice(address);
        Ok(Self {
            port: u16::from_be_bytes([port[0], port[1]]),
            address: Ipv6Addr::from(octets),
        })
    }
}

impl From<SocketAddr> for GatewayAddress {
    /// The Gateway Address fields a relay reports for a Request it received
    /// from `endpoint`, with an IPv4 address in the IPv4-compatible form that
    /// §5.1.4.9.2 specifies.
    fn from(endpoint: SocketAddr) -> Self {
        let address = match endpoint.ip() {
            IpAddr::V4(v4) => v4.to_ipv6_compatible(),
            IpAddr::V6(v6) => v6,
        };
        Self {
            port: endpoint.port(),
            address,
        }
    }
}

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
            _ => Err(AmtError::InvalidMessage(format!(
                "Unknown message type: {}",
                value
            ))),
        }
    }
}

/// AMT Message
#[derive(Debug, Clone, PartialEq)]
pub enum AmtMessage {
    /// Relay Discovery (Gateway → Discovery Address)
    /// Length: 8 bytes
    RelayDiscovery { nonce: u32 },

    /// Relay Advertisement (Relay → Gateway)
    /// Length: 12 bytes (IPv4) or 24 bytes (IPv6)
    RelayAdvertisement { nonce: u32, relay_address: IpAddr },

    /// Request (Gateway → Relay)
    /// Length: 8 bytes
    Request {
        request_nonce: u32,
        p_flag: bool, // Pseudo-header checksum flag
    },

    /// Membership Query (Relay → Gateway)
    /// Length: 14+ bytes, plus the 18 bytes of Gateway Address fields when the
    /// G flag is set
    MembershipQuery {
        request_nonce: u32,
        response_mac: [u8; 6],
        query_data: Vec<u8>, // IGMP/MLD Query
        /// Present if, and only if, the relay set the G flag (§5.1.4.9).
        gateway_address: Option<GatewayAddress>,
    },

    /// Membership Update (Gateway → Relay)
    /// Length: 14+ bytes
    MembershipUpdate {
        request_nonce: u32,
        response_mac: [u8; 6],
        report_data: Vec<u8>, // IGMPv3/MLDv2 Report
    },

    /// Multicast Data (Relay → Gateway)
    /// Length: 2+ bytes
    MulticastData {
        ip_packet: Vec<u8>, // Encapsulated IP packet
    },

    /// Teardown (Gateway → Relay), RFC 7450 §5.1.7
    /// Length: 30 bytes
    Teardown {
        request_nonce: u32,
        response_mac: [u8; 6],
        /// The tunnel endpoint to tear down, copied from the Membership Query
        /// that supplied `request_nonce` and `response_mac` (§5.2.3.7.2).
        gateway_address: GatewayAddress,
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

            AmtMessage::RelayAdvertisement {
                nonce,
                relay_address,
            } => {
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

            AmtMessage::Request {
                request_nonce,
                p_flag,
            } => {
                // Type (1) | P-flag (1) | Reserved (2) | Request Nonce (4)
                let mut buf = Vec::with_capacity(8);
                buf.push(MessageType::Request as u8);
                buf.push(if *p_flag { 0x80 } else { 0x00 });
                buf.extend_from_slice(&[0, 0]); // Reserved
                buf.extend_from_slice(&request_nonce.to_be_bytes());
                buf
            }

            AmtMessage::MembershipQuery {
                request_nonce,
                response_mac,
                query_data,
                gateway_address,
            } => {
                // RFC 7450 §5.1.4: Type (1) | Reserved, L, G (1) | Response MAC (6) |
                // Request Nonce (4) | Query (...) | [Gateway Port (2) | Gateway IP (16)]
                let gateway_fields_len = gateway_address.map_or(0, |_| GATEWAY_ADDRESS_FIELDS_LEN);
                let mut buf = Vec::with_capacity(
                    NONCE_MAC_HEADER_LEN + query_data.len() + gateway_fields_len,
                );
                buf.push(MessageType::MembershipQuery as u8);
                buf.push(if gateway_address.is_some() {
                    QUERY_G_FLAG
                } else {
                    0
                });
                buf.extend_from_slice(response_mac); // MAC at bytes 2-7
                buf.extend_from_slice(&request_nonce.to_be_bytes()); // Nonce at bytes 8-11
                buf.extend_from_slice(query_data);
                if let Some(gateway_address) = gateway_address {
                    gateway_address.encode_into(&mut buf);
                }
                buf
            }

            AmtMessage::MembershipUpdate {
                request_nonce,
                response_mac,
                report_data,
            } => {
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

            AmtMessage::Teardown {
                request_nonce,
                response_mac,
                gateway_address,
            } => {
                // RFC 7450 §5.1.7: Type (1) | Reserved (1) | Response MAC (6) |
                // Request Nonce (4) | Gateway Port (2) | Gateway IP (16)
                let mut buf = Vec::with_capacity(TEARDOWN_LEN);
                buf.push(MessageType::Teardown as u8);
                buf.push(0); // Reserved
                buf.extend_from_slice(response_mac); // MAC at bytes 2-7
                buf.extend_from_slice(&request_nonce.to_be_bytes()); // Nonce at bytes 8-11
                gateway_address.encode_into(&mut buf); // bytes 12-29
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
                    return Err(AmtError::InvalidMessage(
                        "RelayAdvertisement too short".into(),
                    ));
                }

                let nonce = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);

                // Determine IPv4 or IPv6 by length
                let relay_address = if buf.len() == 12 {
                    // IPv4
                    IpAddr::V4(Ipv4Addr::new(buf[8], buf[9], buf[10], buf[11]))
                } else if buf.len() == 24 {
                    // IPv6
                    let octets: [u8; 16] = buf[8..24]
                        .try_into()
                        .map_err(|_| AmtError::InvalidMessage("Invalid IPv6 address".into()))?;
                    IpAddr::V6(Ipv6Addr::from(octets))
                } else {
                    return Err(AmtError::InvalidMessage(format!(
                        "Invalid advertisement length: {}",
                        buf.len()
                    )));
                };

                Ok(AmtMessage::RelayAdvertisement {
                    nonce,
                    relay_address,
                })
            }

            MessageType::Request => {
                if buf.len() < 8 {
                    return Err(AmtError::InvalidMessage("Request too short".into()));
                }
                let p_flag = (buf[1] & 0x80) != 0;
                let request_nonce = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
                Ok(AmtMessage::Request {
                    request_nonce,
                    p_flag,
                })
            }

            MessageType::MembershipQuery => {
                if buf.len() < MEMBERSHIP_QUERY_MIN_LEN {
                    return Err(AmtError::InvalidMessage("MembershipQuery too short".into()));
                }
                // RFC 7450: Bytes 2-7 are Response MAC, bytes 8-11 are Request Nonce
                let response_mac: [u8; 6] = buf[2..8]
                    .try_into()
                    .map_err(|_| AmtError::InvalidMessage("Invalid MAC".into()))?;
                let request_nonce = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
                // §5.1.4.9: with the G flag set, the Gateway Address fields are
                // the datagram's last 18 bytes, after the encapsulated query.
                let (query_end, gateway_address) = if buf[1] & QUERY_G_FLAG != 0 {
                    if buf.len() < MEMBERSHIP_QUERY_MIN_LEN + GATEWAY_ADDRESS_FIELDS_LEN {
                        return Err(AmtError::InvalidMessage(
                            "MembershipQuery with the G flag set is too short for its Gateway Address fields"
                                .into(),
                        ));
                    }
                    let at = buf.len() - GATEWAY_ADDRESS_FIELDS_LEN;
                    (at, Some(GatewayAddress::decode(&buf[at..])?))
                } else {
                    (buf.len(), None)
                };
                let query_data = buf[NONCE_MAC_HEADER_LEN..query_end].to_vec();
                Ok(AmtMessage::MembershipQuery {
                    request_nonce,
                    response_mac,
                    query_data,
                    gateway_address,
                })
            }

            MessageType::MembershipUpdate => {
                if buf.len() < 12 {
                    return Err(AmtError::InvalidMessage(
                        "MembershipUpdate too short".into(),
                    ));
                }
                // RFC 7450: Bytes 2-7 are Response MAC, bytes 8-11 are Request Nonce
                let response_mac: [u8; 6] = buf[2..8]
                    .try_into()
                    .map_err(|_| AmtError::InvalidMessage("Invalid MAC".into()))?;
                let request_nonce = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
                let report_data = buf[12..].to_vec();
                Ok(AmtMessage::MembershipUpdate {
                    request_nonce,
                    response_mac,
                    report_data,
                })
            }

            MessageType::MulticastData => {
                if buf.len() < 2 {
                    return Err(AmtError::InvalidMessage("MulticastData too short".into()));
                }
                let ip_packet = buf[2..].to_vec();
                Ok(AmtMessage::MulticastData { ip_packet })
            }

            MessageType::Teardown => {
                // Fixed-length (§5.1.7). A shorter one lacks the endpoint the
                // relay has to authenticate, so it is not a Teardown at all.
                if buf.len() != TEARDOWN_LEN {
                    return Err(AmtError::InvalidMessage(format!(
                        "Teardown must be {TEARDOWN_LEN} bytes, got {}",
                        buf.len()
                    )));
                }
                // Same Response MAC / Request Nonce offsets as the Membership
                // Query it copies them from (Figures 14 and 17).
                let response_mac: [u8; 6] = buf[2..8]
                    .try_into()
                    .map_err(|_| AmtError::InvalidMessage("Invalid MAC".into()))?;
                let request_nonce = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
                let gateway_address = GatewayAddress::decode(&buf[NONCE_MAC_HEADER_LEN..])?;
                Ok(AmtMessage::Teardown {
                    request_nonce,
                    response_mac,
                    gateway_address,
                })
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
            0x02, 0x00, 0x00, 0x00, // Type + Reserved
            0x12, 0x34, 0x56, 0x78, // Nonce
            192, 0, 2, 1, // IPv4
        ];
        let msg = AmtMessage::decode(&data).unwrap();

        match msg {
            AmtMessage::RelayAdvertisement {
                nonce,
                relay_address,
            } => {
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
            0x03, 0x80, 0x00, 0x00, // Type + P-flag + Reserved
            0xAB, 0xCD, 0xEF, 0x01, // Request Nonce
        ];
        let msg = AmtMessage::decode(&data).unwrap();

        match msg {
            AmtMessage::Request {
                request_nonce,
                p_flag,
            } => {
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
        let msg = AmtMessage::MulticastData {
            ip_packet: ip_packet.clone(),
        };

        let encoded = msg.encode();
        let decoded = AmtMessage::decode(&encoded).unwrap();

        match decoded {
            AmtMessage::MulticastData {
                ip_packet: decoded_packet,
            } => {
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

    // The vectors below are laid out by hand from RFC 7450's figures, so the
    // codec is checked against the RFC rather than against itself. A round
    // trip alone could not have caught the Teardown this replaces: its encoder
    // and decoder were both wrong, in different ways.

    const MAC: [u8; 6] = [0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6];
    const NONCE: u32 = 0xdead_beef;
    const NONCE_BYTES: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
    /// Gateway Port Number 40001.
    const PORT_BYTES: [u8; 2] = [0x9c, 0x41];

    /// 198.51.100.7 as an IPv4-compatible IPv6 address: 96 zero bits, then the
    /// IPv4 address (§5.1.4.9.2).
    fn ipv4_compatible_bytes() -> Vec<u8> {
        let mut bytes = vec![0; 12];
        bytes.extend_from_slice(&[198, 51, 100, 7]);
        bytes
    }

    /// 2001:db8::7
    fn ipv6_bytes() -> Vec<u8> {
        let mut bytes = vec![0x20, 0x01, 0x0d, 0xb8];
        bytes.extend_from_slice(&[0; 11]);
        bytes.push(0x07);
        bytes
    }

    /// Figure 14 with the G flag set: header, a 20-byte stand-in for the
    /// encapsulated query, then Gateway Port Number and Gateway IP Address.
    fn query_with_gateway_address(address: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0x04, 0x01]; // V=0 Type=4 | Reserved=0 L=0 G=1
        bytes.extend_from_slice(&MAC);
        bytes.extend_from_slice(&NONCE_BYTES);
        bytes.extend_from_slice(&[0x45; 20]);
        bytes.extend_from_slice(&PORT_BYTES);
        bytes.extend_from_slice(address);
        bytes
    }

    /// Figure 17.
    fn teardown(address: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0x07, 0x00]; // V=0 Type=7 | Reserved
        bytes.extend_from_slice(&MAC);
        bytes.extend_from_slice(&NONCE_BYTES);
        bytes.extend_from_slice(&PORT_BYTES);
        bytes.extend_from_slice(address);
        bytes
    }

    fn observed(endpoint: &str) -> GatewayAddress {
        GatewayAddress::from(endpoint.parse::<SocketAddr>().unwrap())
    }

    #[test]
    fn membership_query_g_flag_splits_off_the_gateway_address() {
        let wire = query_with_gateway_address(&ipv4_compatible_bytes());
        let query = AmtMessage::decode(&wire).unwrap();

        assert_eq!(
            query,
            AmtMessage::MembershipQuery {
                request_nonce: NONCE,
                response_mac: MAC,
                query_data: vec![0x45; 20],
                gateway_address: Some(observed("198.51.100.7:40001")),
            }
        );
        assert_eq!(query.encode(), wire);
    }

    #[test]
    fn membership_query_without_g_flag_keeps_every_trailing_byte_as_query() {
        let mut wire = query_with_gateway_address(&ipv4_compatible_bytes());
        // Every flag bit except G: L and the reserved bits must not read as G.
        wire[1] = 0xfe;
        match AmtMessage::decode(&wire).unwrap() {
            AmtMessage::MembershipQuery {
                query_data,
                gateway_address,
                ..
            } => {
                assert_eq!(gateway_address, None);
                assert_eq!(query_data, wire[12..]);
            }
            other => panic!("expected MembershipQuery, got {other:?}"),
        }
    }

    #[test]
    fn membership_query_g_flag_without_room_for_the_fields_is_rejected() {
        // The 14-byte floor, plus one byte short of the 18 the G flag promises.
        let mut wire = vec![0x04, 0x01];
        wire.extend_from_slice(&MAC);
        wire.extend_from_slice(&NONCE_BYTES);
        wire.extend_from_slice(&[0x45; 2 + 17]);
        assert!(matches!(
            AmtMessage::decode(&wire),
            Err(AmtError::InvalidMessage(_))
        ));
    }

    #[test]
    fn teardown_matches_rfc7450_figure_17_for_an_ipv4_gateway() {
        let message = AmtMessage::Teardown {
            request_nonce: NONCE,
            response_mac: MAC,
            gateway_address: observed("198.51.100.7:40001"),
        };
        let wire = teardown(&ipv4_compatible_bytes());

        assert_eq!(wire.len(), 30);
        assert_eq!(message.encode(), wire);
        assert_eq!(AmtMessage::decode(&wire).unwrap(), message);
    }

    #[test]
    fn teardown_matches_rfc7450_figure_17_for_an_ipv6_gateway() {
        let message = AmtMessage::Teardown {
            request_nonce: NONCE,
            response_mac: MAC,
            gateway_address: observed("[2001:db8::7]:40001"),
        };
        let wire = teardown(&ipv6_bytes());

        assert_eq!(wire.len(), 30);
        assert_eq!(message.encode(), wire);
        assert_eq!(AmtMessage::decode(&wire).unwrap(), message);
    }

    /// The relay's MAC covers the exact bytes it sent, so the Teardown must
    /// echo them verbatim -- including a relay's choice of the IPv4-mapped
    /// form over the IPv4-compatible one §5.1.4.9.2 specifies.
    #[test]
    fn teardown_echoes_the_query_gateway_fields_byte_for_byte() {
        let mut mapped = vec![0; 10];
        mapped.extend_from_slice(&[0xff, 0xff, 198, 51, 100, 7]);
        let query = query_with_gateway_address(&mapped);
        let gateway_address = match AmtMessage::decode(&query).unwrap() {
            AmtMessage::MembershipQuery {
                gateway_address: Some(gateway_address),
                ..
            } => gateway_address,
            other => panic!("expected MembershipQuery with G set, got {other:?}"),
        };

        let wire = AmtMessage::Teardown {
            request_nonce: NONCE,
            response_mac: MAC,
            gateway_address,
        }
        .encode();

        assert_eq!(wire[12..], query[query.len() - 18..]);
        assert_eq!(wire, teardown(&mapped));
    }

    #[test]
    fn teardown_of_any_other_length_is_rejected() {
        let wire = teardown(&ipv4_compatible_bytes());
        // 12: what this crate's encoder used to emit. 14: its old decoder's
        // floor. 29 and 31: one byte either side of the real length.
        for len in [12, 14, 29] {
            assert!(
                AmtMessage::decode(&wire[..len]).is_err(),
                "{len}-byte Teardown decoded"
            );
        }
        let mut long = wire.clone();
        long.push(0);
        assert!(
            AmtMessage::decode(&long).is_err(),
            "31-byte Teardown decoded"
        );
    }
}
