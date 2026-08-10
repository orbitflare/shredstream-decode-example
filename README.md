# Shredstream Decoder

Decode raw Solana turbine shreds into transaction data. Receives UDP shred packets from [OrbitFlare Shredstream](https://orbitflare.com/products/shredstream), reconstructs them via FEC, and pulls out instructions for PumpFun, Jupiter, Raydium, and SPL Token.

Shred parsing is done from scratch (no `solana-ledger`) so you can see exactly how the binary protocol works.

> New to shreds? Read our [introductory article](https://orbitflare.com/blog/fundamentals/shredstream) about how Solana shreds work and where OrbitFlare Shredstream stands.

## Pipeline

```
UDP packets → parse shred headers → collect FEC sets → Reed-Solomon recovery → assemble entry batches → deserialize entries → decode instructions
```

Entry batches are decoded incrementally: each batch is emitted as soon as its shreds are contiguous (marked by the `DATA_COMPLETE_SHRED` flag), without waiting for the rest of the slot to arrive.

## Supported Examples

| Example | Instructions |
|-----|-------------|
| Pump.fun | Buy, BuyExactSolIn, Sell, Create, CreateV2 |
| Jupiter v6 | Route, RouteV2, SharedAccountsRoute, ExactOut (+ token ledger variants) |
| Raydium AMM | SwapBaseIn, SwapBaseOut, Initialize2 |
| Raydium CPMM | SwapBaseInput, SwapBaseOutput, Initialize |
| SPL Token | Transfer, TransferChecked, MintTo, Burn |

## Setup

You need an [OrbitFlare Shredstream](https://orbitflare.com/products/shredstream) subscription that sends UDP shred packets to your machine.

```bash
cp .env.example .env
```

## Endpoints

We currently offer 9 regions. All regions receive shreds from top-of-turbine validators.

**Premium**

- 🇳🇱 Amsterdam
- 🇩🇪 Frankfurt
- 🇬🇧 London
- 🇺🇸 New York

**Standard**

- 🇮🇪 Dublin
- 🇱🇹 Siauliai
- 🇺🇸 Utah
- 🇯🇵 Tokyo
- 🇸🇬 Singapore

## Usage

```bash
# decode everything
cargo run -- --bind 0.0.0.0:8001

# json output
cargo run -- --bind 0.0.0.0:8001 --format json

# filter by dex
cargo run -- --bind 0.0.0.0:8001 --dex pumpfun,jupiter

# filter by instruction type
cargo run -- --bind 0.0.0.0:8001 --kind buy,sell

# verbose logging
cargo run -- --bind 0.0.0.0:8001 -vv
```

## Examples

All examples bind to `0.0.0.0:8001` by default. Pass `--bind` to override.

```bash
cargo run --example listen_and_decode       # all instructions, human-readable
cargo run --example shred_to_json           # all instructions, JSON
cargo run --example pumpfun_trades          # pump.fun buys and sells
cargo run --example pumpfun_new_tokens      # new pump.fun token creates
cargo run --example jupiter_swaps           # jupiter swaps
cargo run --example jupiter_whale_swaps     # jupiter buys > 10 SOL (--min-sol to adjust)
cargo run --example raydium_swaps           # direct raydium swaps (rare - most go through jupiter)
cargo run --example raydium_new_pools       # new raydium pool creation
cargo run --example token_transfers         # SPL token transfers
cargo run --example token_mints             # SPL token mints
```

## Project structure

```
src/
├── shred/           # binary shred parsing (headers, payload extraction)
├── fec/             # FEC set tracking, Reed-Solomon recovery, entry batch assembly
├── entry/           # bincode deserialization of entries into transactions
├── decoder/         # instruction decoders (pumpfun, jupiter, raydium, spl_token)
├── pipeline/        # ties it all together -UDP listener → decode → callback
├── types.rs         # Dex, InstructionKind, DecodedInstruction, ShredInfo
├── lib.rs           # public exports
└── main.rs          # CLI
```

## Adding a decoder

Implement `InstructionDecoder` and register it in `DecoderRegistry::new()`:

```rust
pub struct MyDecoder { program_id: Pubkey }

impl InstructionDecoder for MyDecoder {
    fn program_id(&self) -> Pubkey { self.program_id }
    fn dex(&self) -> Dex { Dex::PumpFun }

    fn decode(
        &self,
        accounts: &[Pubkey],
        instruction_accounts: &[u8],
        data: &[u8],
        signature: &str,
        slot: u64,
    ) -> Option<DecodedInstruction> {
        // check discriminator, parse amounts, resolve accounts
        todo!()
    }
}
```

## Limitations

Shreds contain the raw transaction message *before* execution -you only get top-level instructions. CPI / inner instructions aren't available. If a swap goes through Jupiter, you'll see the Jupiter instruction but not the underlying Raydium/Orca calls it makes. This is why `raydium_swaps` shows little output -almost all Raydium volume is routed through Jupiter nowadays.

For CPI-level data you'd need post-execution sources (RPC, Geyser, etc).
