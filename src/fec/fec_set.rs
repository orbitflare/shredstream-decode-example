use super::reed_solomon::recover_shards;
use crate::shred::coding_header::CodingHeader;
use crate::shred::coding_header::CODING_PAYLOAD_OFFSET;
use crate::shred::common_header::{ShredVariant, SIGNATURE_SIZE};
use crate::shred::data_header::DATA_PAYLOAD_OFFSET;

const DATA_ERASURE_OFFSET: usize = SIGNATURE_SIZE; // 64
const CODING_ERASURE_OFFSET: usize = CODING_PAYLOAD_OFFSET; // 89

#[derive(Debug)]
pub struct RecoveredShred {
    pub index: u32,
    pub flags: u8,
    pub payload: Vec<u8>,
}

#[derive(Debug)]
pub struct FecSet {
    pub slot: u64,
    pub fec_set_index: u32,
    num_data: Option<u16>,
    num_coding: Option<u16>,
    variant: Option<ShredVariant>,
    data_raws: Vec<Option<Vec<u8>>>,
    coding_raws: Vec<Option<Vec<u8>>>,
    data_count: usize,
    coding_count: usize,
}

impl FecSet {
    pub fn new(slot: u64, fec_set_index: u32) -> Self {
        Self {
            slot,
            fec_set_index,
            num_data: None,
            num_coding: None,
            variant: None,
            data_raws: Vec::new(),
            coding_raws: Vec::new(),
            data_count: 0,
            coding_count: 0,
        }
    }

    pub fn insert_data(&mut self, variant: ShredVariant, index: u32, raw: Vec<u8>) -> bool {
        if self.variant.is_none() {
            self.variant = Some(variant);
        }

        let local_idx = index.saturating_sub(self.fec_set_index) as usize;

        if local_idx >= self.data_raws.len() {
            self.data_raws.resize_with(local_idx + 1, || None);
        }

        if self.data_raws[local_idx].is_none() {
            self.data_raws[local_idx] = Some(raw);
            self.data_count += 1;
        }

        self.is_complete()
    }

    pub fn insert_coding(&mut self, variant: ShredVariant, coding: &CodingHeader, raw: Vec<u8>) -> bool {
        if self.variant.is_none() {
            self.variant = Some(variant);
        }

        self.set_fec_params(coding);
        let position = coding.position as usize;

        if position >= self.coding_raws.len() {
            self.coding_raws.resize_with(position + 1, || None);
        }

        if self.coding_raws[position].is_none() {
            self.coding_raws[position] = Some(raw);
            self.coding_count += 1;
        }

        self.is_complete()
    }

    fn is_complete(&self) -> bool {
        let Some(num_data) = self.num_data else {
            return false;
        };

        if self.data_count >= num_data as usize {
            return true;
        }

        let total_present = self.data_count + self.coding_count;
        total_present >= num_data as usize
    }

    fn set_fec_params(&mut self, coding: &CodingHeader) {
        if self.num_data.is_none() {
            self.num_data = Some(coding.num_data_shreds);
            self.num_coding = Some(coding.num_coding_shreds);

            if self.data_raws.len() < coding.num_data_shreds as usize {
                self.data_raws
                    .resize_with(coding.num_data_shreds as usize, || None);
            }
            if self.coding_raws.len() < coding.num_coding_shreds as usize {
                self.coding_raws
                    .resize_with(coding.num_coding_shreds as usize, || None);
            }
        }
    }

    fn compute_erasure_shard_size(&self) -> usize {
        let proof_bytes = self.variant.map(|v| v.merkle_proof_bytes()).unwrap_or(0);

        for raw in self.coding_raws.iter().flatten() {
            let size = raw
                .len()
                .saturating_sub(CODING_ERASURE_OFFSET + proof_bytes);
            if size > 0 {
                return size;
            }
        }

        for raw in self.data_raws.iter().flatten() {
            let size = raw.len().saturating_sub(DATA_ERASURE_OFFSET + proof_bytes);
            if size > 0 {
                return size;
            }
        }

        0
    }

    fn extract_erasure_shard(raw: &[u8], offset: usize, shard_size: usize) -> Vec<u8> {
        let mut shard = vec![0u8; shard_size];
        let avail = (offset + shard_size).min(raw.len()).saturating_sub(offset);
        if avail > 0 {
            shard[..avail].copy_from_slice(&raw[offset..offset + avail]);
        }
        shard
    }

    const SHARD_FLAGS_FIELD: usize = 21;

    fn extract_flags_from_erasure_shard(shard: &[u8]) -> u8 {
        shard.get(Self::SHARD_FLAGS_FIELD).copied().unwrap_or(0)
    }

    fn extract_payload_from_erasure_shard(shard: &[u8]) -> Vec<u8> {
        const PAYLOAD_START: usize = DATA_PAYLOAD_OFFSET - DATA_ERASURE_OFFSET; // 24
        const SIZE_FIELD: usize = PAYLOAD_START - 2; // 22

        if shard.len() < PAYLOAD_START {
            return Vec::new();
        }

        if shard.len() < SIZE_FIELD + 2 {
            return shard[PAYLOAD_START..].to_vec();
        }
        let size = u16::from_le_bytes([shard[SIZE_FIELD], shard[SIZE_FIELD + 1]]) as usize;

        let end_in_shard = size.saturating_sub(DATA_ERASURE_OFFSET).min(shard.len());
        if end_in_shard <= PAYLOAD_START {
            return Vec::new();
        }

        shard[PAYLOAD_START..end_in_shard].to_vec()
    }

    pub fn reassemble(&mut self) -> anyhow::Result<Vec<RecoveredShred>> {
        let num_data = self.num_data.unwrap_or(self.data_raws.len() as u16) as usize;
        let num_coding = self.num_coding.unwrap_or(self.coding_raws.len() as u16) as usize;

        self.data_raws.resize_with(num_data, || None);
        self.coding_raws.resize_with(num_coding, || None);

        let all_data_present = self.data_raws.iter().take(num_data).all(|s| s.is_some());

        if all_data_present {
            return Ok(Vec::new());
        }

        let shard_size = self.compute_erasure_shard_size();
        if shard_size == 0 {
            anyhow::bail!("Cannot determine erasure shard size for RS recovery");
        }

        tracing::debug!(
            slot = self.slot,
            fec_idx = self.fec_set_index,
            num_data,
            num_coding,
            shard_size,
            data_present = self.data_count,
            coding_present = self.coding_count,
            "Starting RS recovery"
        );

        let mut shards: Vec<Option<Vec<u8>>> = Vec::with_capacity(num_data + num_coding);
        for raw in self.data_raws.iter() {
            shards.push(
                raw.as_ref()
                    .map(|r| Self::extract_erasure_shard(r, DATA_ERASURE_OFFSET, shard_size)),
            );
        }
        for raw in self.coding_raws.iter() {
            shards.push(
                raw.as_ref()
                    .map(|r| Self::extract_erasure_shard(r, CODING_ERASURE_OFFSET, shard_size)),
            );
        }

        recover_shards(num_data, num_coding, &mut shards)?;

        let mut result = Vec::with_capacity(num_data - self.data_count);
        for (i, shard) in shards.iter().enumerate().take(num_data) {
            if self.data_raws[i].is_some() {
                continue;
            }
            match shard {
                Some(data) => {
                    result.push(RecoveredShred {
                        index: self.fec_set_index + i as u32,
                        flags: Self::extract_flags_from_erasure_shard(data),
                        payload: Self::extract_payload_from_erasure_shard(data),
                    });
                }
                None => anyhow::bail!("Data shard {i} still missing after recovery"),
            }
        }

        tracing::debug!(
            slot = self.slot,
            fec_idx = self.fec_set_index,
            recovered = num_data - self.data_count,
            "FEC reassembly (RS recovery)"
        );

        Ok(result)
    }
}
