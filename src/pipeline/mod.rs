pub mod udp_listener;

use crate::decoder::DecoderRegistry;
use crate::entry::deserialize_entries;
use crate::fec::{FecTracker, IngestResult};
use crate::shred::{parse_shred, ParsedShred};
use crate::types::{DecodedInstruction, Dex, InstructionKind, ShredInfo};
use udp_listener::UdpShredListener;

pub type ShredCallback = Box<dyn Fn(&ParsedShred) + Send + Sync>;
pub type InstructionCallback = Box<dyn Fn(&DecodedInstruction) + Send + Sync>;

pub struct ShredPipeline {
    bind_addr: String,
    decoder_registry: DecoderRegistry,
    fec_tracker: FecTracker,
    dex_filter: Option<Vec<Dex>>,
    kind_filter: Option<Vec<InstructionKind>>,
    on_shred: Option<ShredCallback>,
    on_instruction: Option<InstructionCallback>,
}

impl ShredPipeline {
    pub fn new(bind_addr: String) -> Self {
        Self {
            bind_addr,
            decoder_registry: DecoderRegistry::new(),
            fec_tracker: FecTracker::new(100),
            dex_filter: None,
            kind_filter: None,
            on_shred: None,
            on_instruction: None,
        }
    }

    pub fn with_dex_filter(mut self, dexes: Vec<Dex>) -> Self {
        self.dex_filter = Some(dexes);
        self
    }

    pub fn with_kind_filter(mut self, kinds: Vec<InstructionKind>) -> Self {
        self.kind_filter = Some(kinds);
        self
    }

    pub fn on_shred(mut self, cb: ShredCallback) -> Self {
        self.on_shred = Some(cb);
        self
    }

    pub fn on_instruction(mut self, cb: InstructionCallback) -> Self {
        self.on_instruction = Some(cb);
        self
    }

    fn decode_entries(&mut self, slot: u64, data: &[u8]) -> Vec<DecodedInstruction> {
        let entries = deserialize_entries(data);
        if entries.is_empty() {
            return Vec::new();
        }

        let tx_count: usize = entries.iter().map(|e| e.transactions.len()).sum();
        tracing::debug!(
            slot,
            entry_count = entries.len(),
            tx_count,
            "Deserialized entries"
        );

        let mut results = Vec::new();
        for entry in &entries {
            for tx in &entry.transactions {
                if tx.signatures.is_empty() {
                    continue;
                }
                let signature = bs58::encode(&tx.signatures[0]).into_string();
                let accounts = tx.message.static_account_keys();

                let instructions: Vec<(u8, Vec<u8>, Vec<u8>)> = tx
                    .message
                    .instructions()
                    .iter()
                    .map(|ix| (ix.program_id_index, ix.accounts.clone(), ix.data.clone()))
                    .collect();

                results.extend(self.decoder_registry.decode_transaction(
                    accounts,
                    &instructions,
                    &signature,
                    slot,
                ));
            }
        }
        results
    }

    fn matches_filters(&self, inst: &DecodedInstruction) -> bool {
        if let Some(ref f) = self.dex_filter {
            if !f.contains(&inst.dex) {
                return false;
            }
        }
        if let Some(ref f) = self.kind_filter {
            if !f.contains(&inst.kind) {
                return false;
            }
        }
        true
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        let listener = UdpShredListener::bind(&self.bind_addr).await?;
        tracing::info!(bind = %self.bind_addr, "ShredPipeline started");

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                match listener.recv().await {
                    Ok(raw) => {
                        if tx.send(raw).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "UDP recv failed");
                        break;
                    }
                }
            }
        });

        let mut shred_count: u64 = 0;
        let mut instruction_count: u64 = 0;

        while let Some(raw) = rx.recv().await {
            shred_count += 1;

            tracing::debug!(shred_count, len = raw.len(), "Received UDP packet");

            let Some(parsed) = parse_shred(&raw) else {
                tracing::debug!(shred_count, "Failed to parse shred");
                continue;
            };

            tracing::debug!(
                slot = parsed.slot(), index = parsed.index(),
                is_data = parsed.is_data(), fec_set = parsed.fec_set_index(),
                variant = ?parsed.common().variant,
                "Parsed shred"
            );

            if let Some(cb) = &self.on_shred {
                cb(&parsed);
            }

            let (slot, batches) = match self.fec_tracker.ingest(parsed) {
                IngestResult::Pending => continue,
                IngestResult::Batches { slot, batches, .. } => (slot, batches),
            };

            for batch in &batches {
                for inst in self.decode_entries(slot, batch) {
                    if !self.matches_filters(&inst) {
                        continue;
                    }

                    instruction_count += 1;
                    if let Some(cb) = &self.on_instruction {
                        cb(&inst);
                    }
                }
            }

            if shred_count.is_multiple_of(10_000) {
                tracing::info!(
                    shreds = shred_count,
                    instructions = instruction_count,
                    active_fec_sets = self.fec_tracker.active_sets(),
                    active_slots = self.fec_tracker.active_slots(),
                    "Pipeline stats"
                );
            }
        }

        anyhow::bail!("UDP listener stopped")
    }

    pub fn process_raw(&mut self, raw: &[u8]) -> Vec<DecodedInstruction> {
        let Some(parsed) = parse_shred(raw) else {
            return Vec::new();
        };

        let (slot, batches) = match self.fec_tracker.ingest(parsed) {
            IngestResult::Batches { slot, batches, .. } => (slot, batches),
            IngestResult::Pending => return Vec::new(),
        };

        batches
            .iter()
            .flat_map(|batch| self.decode_entries(slot, batch))
            .collect()
    }

    pub fn parse_shred_info(raw: &[u8]) -> Option<ShredInfo> {
        parse_shred(raw).map(|s| s.info())
    }
}
