# LaunchProof

LaunchProof checks who really bought a Pump.fun token at launch and lets a buyer, or an AI agent, purchase only if the token stays within the buyer's limits. The check runs inside the purchase transaction on Solana: if the token fails the check, Solana cancels the whole purchase.

Built for the MLH Solana Hackathon (November 2026). Everything runs on devnet; the investigator also works on mainnet tokens.

## Live

- Web client: https://launchproof-1.onrender.com
- API: https://launchproof-vd4a.onrender.com/health
- Try it: open the web client and click "Demo: bundled launch (devnet)", or paste any Pump.fun mainnet token address.

## The problem

The most common Pump.fun scam is not a malicious contract. The creator funds several wallets, those wallets buy most of the supply in the first seconds, and they sell when other people arrive. This leaves a public trail: the same SOL source, buys in the same slots as the creation.

## How it works

1. **Investigation** (`crates/lp-investigate`). From a mint, LaunchProof finds the creation transaction and the real creator, every wallet that bought in the first 150 slots, where each wallet got its SOL (up to two hops), the creator's earlier launches, and the mint and freeze authorities. Wallets funded by the creator, or by the creator's own funding source, form the creator's network.
2. **Findings.** The report is turned into plain sentences, each with the transactions that prove it. No language model is involved, so nothing is invented.
3. **Signed attestation** (`crates/lp-attest`). The numbers go into a 97-byte message signed with Ed25519, including a SHA-256 hash of the evidence.
4. **Check inside the purchase** (`programs/launchproof`). A guarded purchase transaction has three parts: the native Ed25519 instruction with the attestation, `assert_launch_policy` with the buyer's limits, and the Pump.fun buy. If the signature, the limits, the age or the mint do not match, the transaction fails and nothing is bought.

The same attestation code (`lp-attest`) runs inside the on-chain program and in the services, so both sides cannot disagree.

## Proof on devnet

| What | Result | Transaction |
|---|---|---|
| CLI, clean launch (3.36% by the creator's network) | executed | [JWVv...xkzH](https://explorer.solana.com/tx/JWVv2kB1PRiwjrzcJbKtLbwauyYRk6xwZmEzkzkLaszLoiZwwHi6Lga48UgSWPF1qi8Jdz1DRUeE6BMpevDkxzH?cluster=devnet) |
| CLI, bundled launch (78.67%: creator plus 5 wallets it funded) | cancelled by the guard (`LinkedInitialTooHigh`) | [4sw6...TFadm](https://explorer.solana.com/tx/4sw6kTVP88qMvT3nnamT5mq997VDSYDwFfCbGWUATWuKeEvknXfr3bY4SKNHjXW88pMhgV7P5CyhF2FH1hFMTadm?cluster=devnet) |
| Web client with Phantom, clean launch | executed | [4igq...yiyZ](https://explorer.solana.com/tx/4igqvdUP3HwUXLsurvWJjSvTXBdnkhU1x9wH7Sxw8dMFnwpXEeZqmsYaQEPqtvjYEXMmu8EtjTqwsF5oi4kSyiyZ?cluster=devnet) |
| AI agent through MCP, clean launch | executed | [4H6r...uFPf](https://explorer.solana.com/tx/4H6rovWHD9oCVtnp81PJoccbp7RPcNFt9Q8QN9G7iRdZckYtRSBin2e2PrXGaRTSXGq882tLezy4yVryGg6QuFPf?cluster=devnet) |
| AI agent through MCP, bundled launch | cancelled by the guard | [5FtF...T5ZmU](https://explorer.solana.com/tx/5FtF7yjNjpiB2XUDHH6c8HuGmivCSzeNJoQAcBu9T5ZmUtWdwcXoDfRyS4WdaTkhk7oxaTSxozMdVyUVwsbMTh2X?cluster=devnet) |

- Program: `BjK5qpT8rzR1XLJKtX1MxmXBVD1NM3T19rFV6Vd1r89W` (devnet)
- Config: `4gz8aTPM4hJumsjM1xDLdebjPRiws3zrwuRYmCUd2M12`
- Demo mints: see `web/demo-mints.json`

## Components

| Path | What it is |
|---|---|
| `programs/launchproof` | Anchor program: config, upgrade-authority-gated init, `assert_launch_policy` |
| `crates/lp-attest` | Attestation format, buyer policy, Ed25519 instruction parsing (no dependencies, used on-chain and off-chain) |
| `crates/lp-investigate` | Launch investigator and findings |
| `crates/lp-tx` | Pump.fun `create_v2`/`buy` and guard instruction builders |
| `crates/lp-server` | HTTP API (axum) with Postgres cache and rate limits |
| `crates/lp-mcp` | MCP server so AI agents can investigate and buy through the guard |
| `crates/lp-cli` | Devnet CLI: config, demo launches, guarded buys |
| `web/` | Static web client (HTML, CSS, one TypeScript file) using Wallet Standard |

## API

| Method | Path | Returns |
|---|---|---|
| GET | `/health` | `ok` |
| GET | `/v1/investigate/{devnet\|mainnet}/{mint}` | Report, findings and evidence |
| GET | `/v1/attestation/{mint}` | Signed attestation (devnet) |
| POST | `/v1/guarded-buy` | Unsigned guarded purchase transaction (devnet) |

`POST /v1/guarded-buy` body: `{"mint": "...", "buyer": "...", "sol": 0.01, "policy": {"max_linked_initial_bps": 1000, "max_linked_now_bps": 1000, "max_creator_dead": 1, "deny_flags": 3, "max_age_secs": 600}}`

## Attestation format (97 bytes, little-endian)

| Bytes | Field |
|---|---|
| 0..11 | `LAUNCHPROOF` |
| 11 | version (1) |
| 12 | network (0 mainnet, 1 devnet) |
| 13..45 | mint |
| 45..47 | share bought at launch by the creator's network, basis points |
| 47..49 | share they still hold, basis points |
| 49..51 | creator's earlier launches |
| 51..53 | earlier launches older than 24 hours whose bonding curve never completed |
| 53..57 | flags: 1 mint authority active, 2 freeze authority active, 4 partial analysis |
| 57..65 | issued at, unix seconds |
| 65..97 | SHA-256 of the evidence JSON |

## AI agents (MCP)

`lp-mcp` speaks MCP over stdio and exposes `investigate_token`, `get_attestation`, `build_guarded_buy` and, with an agent wallet configured, `guarded_buy`. Even if an agent decides badly, the purchase cannot go through a token outside its limits: Solana enforces it.

```json
{
  "mcpServers": {
    "launchproof": {
      "command": "/path/to/lp-mcp",
      "env": {
        "LP_API_URL": "https://your-launchproof-api",
        "LP_AGENT_KEYPAIR": "/path/to/agent-devnet.json",
        "LP_RPC_URL": "https://api.devnet.solana.com",
        "LP_AGENT_MAX_SOL": "0.1"
      }
    }
  }
}
```

## Running locally

Requirements: Rust stable, Solana CLI 3.1.10, Anchor CLI 1.2, Node 22, a Postgres database and a Helius API key.

```bash
# Program: build for SBPF v0 (devnet does not have SBPFv3 enabled) and test on a local validator
scripts/test-program.sh

# Shared crates
cargo +stable test -p lp-attest -p lp-investigate -p lp-server -p lp-mcp

# API (reads .env: HELIUS_API_KEY, DATABASE_URL, ATTESTER_KEYPAIR_PATH)
cargo +stable run --release -p lp-server

# Web client
LP_API_URL=http://localhost:8080 web/build.sh && python3 -m http.server 5173 -d web/dist
```

See `SECURITY.md` for the threat model and known limitations.
