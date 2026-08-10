pub mod fec_set;
pub mod reed_solomon;
pub mod slot_assembler;

use crate::shred::ParsedShred;
use fec_set::FecSet;
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

    pub fn ingest(&mut self, shred: &ParsedShred) -> IngestResult {
        let slot = shred.slot();
        let fec_idx = shred.fec_set_index();
        let key = (slot, fec_idx);

        if slot > self.max_slot {
            self.max_slot = slot;
            self.evict_stale();
        }

        if self.completed.contains(&key) || self.completed_slots.contains(&slot) {
            return IngestResult::Pending;
        }

        let set = self
            .sets
            .entry(key)
            .or_insert_with(|| FecSet::new(slot, fec_idx));

        if !set.insert(shred) {
            return IngestResult::Pending;
        }

        self.completed.insert(key);
        let mut set = match self.sets.remove(&key) {
            Some(s) => s,
            None => return IngestResult::Pending,
        };

        let shreds = match set.reassemble() {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(slot, fec_idx, error = %e, "FEC reassembly failed");
                return IngestResult::Pending;
            }
        };

        let asm = self
            .slots
            .entry(slot)
            .or_insert_with(|| SlotAssembler::new(slot));

        for s in shreds {
            asm.insert(s);
        }

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
