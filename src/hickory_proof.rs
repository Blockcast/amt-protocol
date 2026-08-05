//! Feature-gated AMT-01 feasibility proof. This is not used by production DRIAD.

use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use std::net::IpAddr;

const AMTRELAY_TYPE: RecordType = RecordType::Unknown(260);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofRelay {
    Ip(IpAddr),
    DnsName(String),
}

pub fn build_query(qname: &str, transaction_id: u16) -> Option<Vec<u8>> {
    let name = canonical_name(qname)?;
    let mut message = Message::new();
    message
        .set_id(transaction_id)
        .set_message_type(MessageType::Query)
        .set_recursion_desired(true)
        .add_query(Query::query(name, AMTRELAY_TYPE));
    message.to_vec().ok()
}

pub fn select_relay(data: &[u8], transaction_id: u16, qname: &str) -> Option<ProofRelay> {
    let expected_name = canonical_name(qname)?;
    let message = Message::from_vec(data).ok()?;
    if message.id() != transaction_id
        || message.message_type() != MessageType::Response
        || message.response_code() != ResponseCode::NoError
        || message.queries().len() != 1
    {
        return None;
    }

    let query = &message.queries()[0];
    if query.name() != &expected_name
        || query.query_type() != AMTRELAY_TYPE
        || query.query_class() != DNSClass::IN
    {
        return None;
    }

    message
        .answers()
        .iter()
        .filter(|answer| {
            answer.name() == &expected_name
                && answer.dns_class() == DNSClass::IN
                && answer.record_type() == AMTRELAY_TYPE
        })
        .filter_map(|answer| match answer.data() {
            RData::Unknown { rdata, .. } => {
                parse_amtrelay(rdata.anything()).map(|(precedence, relay)| (precedence, relay))
            }
            _ => None,
        })
        .min_by_key(|(precedence, _)| *precedence)
        .map(|(_, relay)| relay)
}

fn canonical_name(name: &str) -> Option<Name> {
    Name::from_ascii(format!("{}.", name.trim_end_matches('.'))).ok()
}

fn parse_amtrelay(rdata: &[u8]) -> Option<(u8, ProofRelay)> {
    let (&precedence, payload) = rdata.split_first()?;
    let (&relay_type, relay) = payload.split_first()?;
    let relay = match relay_type & 0x7f {
        1 if relay.len() == 4 => {
            ProofRelay::Ip(IpAddr::from([relay[0], relay[1], relay[2], relay[3]]))
        }
        2 if relay.len() == 16 => {
            let mut octets = [0; 16];
            octets.copy_from_slice(relay);
            ProofRelay::Ip(IpAddr::from(octets))
        }
        3 => ProofRelay::DnsName(parse_uncompressed_name(relay)?),
        _ => return None,
    };
    Some((precedence, relay))
}

fn parse_uncompressed_name(data: &[u8]) -> Option<String> {
    let mut labels = Vec::new();
    let mut offset = 0;
    loop {
        let len = *data.get(offset)? as usize;
        offset += 1;
        if len == 0 {
            return (offset == data.len() && !labels.is_empty()).then(|| labels.join("."));
        }
        if len > 63 || offset + len > data.len() {
            return None;
        }
        labels.push(std::str::from_utf8(&data[offset..offset + len]).ok()?);
        offset += len;
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hickory_proof_accepts(data: &[u8], transaction_id: u16, qname: &str) -> bool {
    select_relay(data, transaction_id, qname).is_some()
}
