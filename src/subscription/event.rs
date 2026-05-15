//! Output events emitted by SubscriptionManager.

use std::net::IpAddr;
use crate::error::AmtError;

#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    Transmit { dst: IpAddr, port: u16, payload: Vec<u8> },
    Data {
        src: IpAddr,
        group: IpAddr,
        src_port: u16,
        dst_port: u16,
        payload: Vec<u8>,
    },
    HandshakeComplete,
    Warning(AmtError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_variants_construct() {
        let _ = Event::Transmit {
            dst: "192.0.2.1".parse().unwrap(),
            port: 2268,
            payload: vec![1, 2, 3],
        };
        let _ = Event::Data {
            src: "10.0.0.1".parse().unwrap(),
            group: "232.0.0.1".parse().unwrap(),
            src_port: 5004,
            dst_port: 5004,
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let _ = Event::HandshakeComplete;
        let _ = Event::Warning(AmtError::MalformedInner);
    }
}
