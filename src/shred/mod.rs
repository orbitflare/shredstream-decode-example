pub mod coding_header;
pub mod common_header;
pub mod data_header;
pub mod payload;

use coding_header::{parse_coding_header, CodingHeader};
use common_header::{parse_common_header, CommonHeader};
use data_header::{parse_data_header, DataHeader};
use payload::{extract_coding_payload, extract_data_payload};

use crate::types::ShredInfo;

#[derive(Debug, Clone)]
pub enum ParsedShred {
    Data {
        common: CommonHeader,
        data: DataHeader,
        payload: Vec<u8>,
        raw: Vec<u8>,
    },
    Coding {
        common: CommonHeader,
        coding: CodingHeader,
        payload: Vec<u8>,
        raw: Vec<u8>,
    },
}

impl ParsedShred {
    pub fn common(&self) -> &CommonHeader {
        match self {
            ParsedShred::Data { common, .. } => common,
            ParsedShred::Coding { common, .. } => common,
        }
    }

    pub fn slot(&self) -> u64 {
        self.common().slot
    }

    pub fn index(&self) -> u32 {
        self.common().index
    }

    pub fn fec_set_index(&self) -> u32 {
        self.common().fec_set_index
    }

    pub fn is_data(&self) -> bool {
        matches!(self, ParsedShred::Data { .. })
    }

    pub fn is_last_in_slot(&self) -> bool {
        match self {
            ParsedShred::Data { data, .. } => data_header::is_last_in_slot(data.flags),
            _ => false,
        }
    }

    pub fn payload(&self) -> &[u8] {
        match self {
            ParsedShred::Data { payload, .. } => payload,
            ParsedShred::Coding { payload, .. } => payload,
        }
    }

    pub fn info(&self) -> ShredInfo {
        let common = self.common();
        ShredInfo {
            slot: common.slot,
            index: common.index,
            version: common.version,
            fec_set_index: common.fec_set_index,
            is_data: self.is_data(),
            payload_size: self.payload().len(),
        }
    }
}

pub fn parse_shred(raw: &[u8]) -> Option<ParsedShred> {
    let common = parse_common_header(raw)?;

    if common.variant.is_data() {
        let data = parse_data_header(raw)?;
        let payload = extract_data_payload(raw, &data, &common.variant).to_vec();
        tracing::trace!(
            slot = common.slot,
            index = common.index,
            raw_len = raw.len(),
            header_size = data.size,
            payload_len = payload.len(),
            proof_bytes = common.variant.merkle_proof_bytes(),
            first_payload = ?&payload[..payload.len().min(16)],
            "Data shred payload extracted"
        );
        Some(ParsedShred::Data {
            common,
            data,
            payload,
            raw: raw.to_vec(),
        })
    } else if common.variant.is_coding() {
        let coding = parse_coding_header(raw)?;
        let payload = extract_coding_payload(raw, &common.variant).to_vec();
        Some(ParsedShred::Coding {
            common,
            coding,
            payload,
            raw: raw.to_vec(),
        })
    } else {
        None
    }
}
