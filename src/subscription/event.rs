//! Output events emitted by SubscriptionManager.

use crate::error::AmtError;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Event {
    /// `#[non_exhaustive]` on the *variant* (not just the enum) is what makes a
    /// future field addition here a non-breaking change. The enum-level
    /// attribute only forces a `_` arm for unknown *variants*; it does nothing
    /// for the fields of a struct variant, so without this a downstream
    /// `Event::Transmit { dst, port, payload }` pattern or literal would break
    /// on every field added. `Event` is emitted by `SubscriptionManager` and
    /// only ever consumed out-of-crate, so forbidding downstream construction
    /// costs nothing and buys field-addition freedom.
    #[non_exhaustive]
    Transmit {
        dst: IpAddr,
        port: u16,
        payload: Vec<u8>,
        /// True only for a *keep-alive* current-state Membership Update — one
        /// emitted while the tunnel was already Active. False for everything
        /// else the manager transmits, including the initial current-state
        /// Update that completes the handshake, Discovery, Request,
        /// incremental ALLOW/BLOCK and Teardown.
        ///
        /// The emitting side is the only place that knows this. A consumer
        /// counting keep-alives reads this flag; it must NOT infer the answer
        /// from where `HandshakeComplete` sits in the drain order.
        keepalive: bool,
    },
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
            keepalive: false,
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
