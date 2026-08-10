use super::fec_set::RecoveredShred;
use crate::shred::data_header::{is_data_complete, is_last_in_slot};
use std::collections::BTreeMap;

#[derive(Debug)]
pub struct SlotAssembler {
    pub slot: u64,
    shreds: BTreeMap<u32, RecoveredShred>,
    cursor: u32,
    last_index: Option<u32>,
    batches_emitted: usize,
}

impl SlotAssembler {
    pub fn new(slot: u64) -> Self {
        Self {
            slot,
            shreds: BTreeMap::new(),
            cursor: 0,
            last_index: None,
            batches_emitted: 0,
        }
    }

    pub fn insert(&mut self, shred: RecoveredShred) {
        if shred.index < self.cursor {
            return;
        }
        if is_last_in_slot(shred.flags) {
            self.last_index = Some(shred.index);
        }
        self.shreds.entry(shred.index).or_insert(shred);
    }

    pub fn drain_batches(&mut self) -> Vec<Vec<u8>> {
        let mut batches = Vec::new();
        loop {
            let mut end = None;
            let mut idx = self.cursor;
            while let Some(shred) = self.shreds.get(&idx) {
                if is_data_complete(shred.flags) {
                    end = Some(idx);
                    break;
                }
                idx += 1;
            }
            let Some(end) = end else { break };

            let mut batch = Vec::new();
            for i in self.cursor..=end {
                batch.extend_from_slice(&self.shreds.remove(&i).unwrap().payload);
            }
            self.cursor = end + 1;
            self.batches_emitted += 1;
            batches.push(batch);
        }
        batches
    }

    pub fn is_complete(&self) -> bool {
        matches!(self.last_index, Some(last) if self.cursor > last)
    }

    pub fn batches_emitted(&self) -> usize {
        self.batches_emitted
    }

    pub fn pending_shreds(&self) -> usize {
        self.shreds.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shred::data_header::{FLAG_DATA_COMPLETE_SHRED, FLAG_LAST_SHRED_IN_SLOT};

    fn shred(index: u32, flags: u8, byte: u8) -> RecoveredShred {
        RecoveredShred {
            index,
            flags,
            payload: vec![byte],
        }
    }

    #[test]
    fn batch_spanning_out_of_order_shreds() {
        let mut asm = SlotAssembler::new(1);
        asm.insert(shred(1, FLAG_DATA_COMPLETE_SHRED, 0xb));
        assert!(asm.drain_batches().is_empty());

        asm.insert(shred(0, 0, 0xa));
        let batches = asm.drain_batches();
        assert_eq!(batches, vec![vec![0xa, 0xb]]);
        assert!(!asm.is_complete());
    }

    #[test]
    fn multiple_batches_and_slot_completion() {
        let mut asm = SlotAssembler::new(1);
        asm.insert(shred(0, FLAG_DATA_COMPLETE_SHRED, 0xa));
        asm.insert(shred(1, 0, 0xb));
        asm.insert(shred(2, FLAG_LAST_SHRED_IN_SLOT, 0xc));
        let batches = asm.drain_batches();
        assert_eq!(batches, vec![vec![0xa], vec![0xb, 0xc]]);
        assert!(asm.is_complete());
        assert_eq!(asm.batches_emitted(), 2);
    }

    #[test]
    fn tick_reference_bits_are_not_boundaries() {
        let mut asm = SlotAssembler::new(1);
        asm.insert(shred(0, 0x02, 0xa));
        assert!(asm.drain_batches().is_empty());
        assert!(!asm.is_complete());

        asm.insert(shred(1, 0x02 | FLAG_LAST_SHRED_IN_SLOT, 0xb));
        assert_eq!(asm.drain_batches(), vec![vec![0xa, 0xb]]);
        assert!(asm.is_complete());
    }

    #[test]
    fn duplicate_and_stale_inserts_ignored() {
        let mut asm = SlotAssembler::new(1);
        asm.insert(shred(0, FLAG_DATA_COMPLETE_SHRED, 0xa));
        asm.insert(shred(0, FLAG_DATA_COMPLETE_SHRED, 0xff));
        assert_eq!(asm.drain_batches(), vec![vec![0xa]]);

        asm.insert(shred(0, FLAG_DATA_COMPLETE_SHRED, 0xff));
        assert!(asm.drain_batches().is_empty());
    }
}
