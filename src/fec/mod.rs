pub mod fec_set;
pub mod reed_solomon;
pub mod slot_assembler;

use crate::shred::ParsedShred;
use fec_set::{FecSet, RecoveredShred};
use slot_assembler::SlotAssembler;
use std::collections::{HashMap, HashSet};

pub struct FecTracker {
    sets: HashMap<(u64, u32), FecSet>,
    completed: HashSet<(u64, u32)>,
    slots: HashMap<u64, SlotAssembler>,
    completed_slots: HashSet<u64>,
    max_slot: u64,
    eviction_threshold: u64,
}

pub enum IngestResult {
    Pending,
    Batches {
        slot: u64,
        batches: Vec<Vec<u8>>,
        slot_complete: bool,
    },
}

impl FecTracker {
    pub fn new(eviction_threshold: u64) -> Self {
        Self {
            sets: HashMap::new(),
            completed: HashSet::new(),
            slots: HashMap::new(),
            completed_slots: HashSet::new(),
            max_slot: 0,
            eviction_threshold,
        }
    }

    pub fn ingest(&mut self, shred: ParsedShred) -> IngestResult {
        let slot = shred.slot();
        let fec_idx = shred.fec_set_index();
        let key = (slot, fec_idx);

        if slot > self.max_slot {
            self.max_slot = slot;
            self.evict_stale();
        }

        if self.completed_slots.contains(&slot) {
            return IngestResult::Pending;
        }

        let variant = shred.common().variant;
        let mut inserted = false;

        match shred {
            ParsedShred::Data {
                common,
                data,
                payload,
                raw,
            } => {
                let asm = self
                    .slots
                    .entry(slot)
                    .or_insert_with(|| SlotAssembler::new(slot));
                asm.insert(RecoveredShred {
                    index: common.index,
                    flags: data.flags,
                    payload,
                });
                inserted = true;

                if !self.completed.contains(&key) {
                    let set = self
                        .sets
                        .entry(key)
                        .or_insert_with(|| FecSet::new(slot, fec_idx));
                    if set.insert_data(variant, common.index, raw) {
                        self.backfill_completed_set(key);
                    }
                }
            }
            ParsedShred::Coding { coding, raw, .. } => {
                if !self.completed.contains(&key) {
                    let set = self
                        .sets
                        .entry(key)
                        .or_insert_with(|| FecSet::new(slot, fec_idx));
                    if set.insert_coding(variant, &coding, raw) {
                        inserted |= self.backfill_completed_set(key);
                    }
                }
            }
        }

        if !inserted {
            return IngestResult::Pending;
        }

        let Some(asm) = self.slots.get_mut(&slot) else {
            return IngestResult::Pending;
        };

        let batches = asm.drain_batches();
        let slot_complete = asm.is_complete();

        if slot_complete {
            let asm = self.slots.remove(&slot).unwrap();
            self.completed_slots.insert(slot);
            tracing::debug!(
                slot,
                batches = asm.batches_emitted(),
                "Slot complete"
            );
        } else if !batches.is_empty() {
            tracing::debug!(
                slot,
                fec_idx,
                new_batches = batches.len(),
                "Entry batches complete, slot incomplete"
            );
        }

        if batches.is_empty() {
            IngestResult::Pending
        } else {
            IngestResult::Batches {
                slot,
                batches,
                slot_complete,
            }
        }
    }

    fn backfill_completed_set(&mut self, key: (u64, u32)) -> bool {
        self.completed.insert(key);
        let Some(mut set) = self.sets.remove(&key) else {
            return false;
        };
        match set.reassemble() {
            Ok(shreds) => {
                if shreds.is_empty() {
                    return false;
                }
                let asm = self
                    .slots
                    .entry(key.0)
                    .or_insert_with(|| SlotAssembler::new(key.0));
                for s in shreds {
                    asm.insert(s);
                }
                true
            }
            Err(e) => {
                tracing::warn!(slot = key.0, fec_idx = key.1, error = %e, "FEC reassembly failed");
                false
            }
        }
    }

    fn evict_stale(&mut self) {
        if self.max_slot < self.eviction_threshold {
            return;
        }
        let cutoff = self.max_slot - self.eviction_threshold;
        self.sets.retain(|&(slot, _), _| slot >= cutoff);
        self.completed.retain(|&(slot, _)| slot >= cutoff);
        self.slots.retain(|&slot, _| slot >= cutoff);
        self.completed_slots.retain(|&slot| slot >= cutoff);
    }

    pub fn active_sets(&self) -> usize {
        self.sets.len()
    }

    pub fn active_slots(&self) -> usize {
        self.slots.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shred::common_header::{CommonHeader, ShredVariant};
    use crate::shred::data_header::{DataHeader, FLAG_DATA_COMPLETE_SHRED, FLAG_LAST_SHRED_IN_SLOT};

    fn data_shred(slot: u64, index: u32, fec_set_index: u32, flags: u8, byte: u8) -> ParsedShred {
        ParsedShred::Data {
            common: CommonHeader {
                signature: [0; 64],
                variant: ShredVariant::MerkleData {
                    proof_size: 0,
                    chained: false,
                    resigned: false,
                },
                slot,
                index,
                version: 0,
                fec_set_index,
            },
            data: DataHeader {
                parent_offset: 0,
                flags,
                size: 0,
            },
            payload: vec![byte],
            raw: Vec::new(),
        }
    }

    #[test]
    fn batch_emits_before_fec_set_completes() {
        let mut tracker = FecTracker::new(100);

        assert!(matches!(
            tracker.ingest(data_shred(5, 0, 0, 0, 0xa)),
            IngestResult::Pending
        ));

        match tracker.ingest(data_shred(5, 1, 0, FLAG_DATA_COMPLETE_SHRED, 0xb)) {
            IngestResult::Batches {
                slot,
                batches,
                slot_complete,
            } => {
                assert_eq!(slot, 5);
                assert_eq!(batches, vec![vec![0xa, 0xb]]);
                assert!(!slot_complete);
            }
            IngestResult::Pending => panic!("batch held back until FEC set completion"),
        }

        assert_eq!(tracker.active_sets(), 1);
    }

    #[test]
    fn last_shred_completes_slot() {
        let mut tracker = FecTracker::new(100);

        tracker.ingest(data_shred(5, 0, 0, FLAG_DATA_COMPLETE_SHRED, 0xa));

        match tracker.ingest(data_shred(5, 1, 0, FLAG_LAST_SHRED_IN_SLOT, 0xb)) {
            IngestResult::Batches {
                batches,
                slot_complete,
                ..
            } => {
                assert_eq!(batches, vec![vec![0xb]]);
                assert!(slot_complete);
            }
            IngestResult::Pending => panic!("expected batch"),
        }

        assert!(matches!(
            tracker.ingest(data_shred(5, 1, 0, FLAG_LAST_SHRED_IN_SLOT, 0xb)),
            IngestResult::Pending
        ));
    }
}
