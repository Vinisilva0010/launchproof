# Security

LaunchProof handles purchase transactions, so this document lists what is protected, how, and what is not.

## Trust model

- The on-chain program trusts one attester public key, stored in the config account. An attestation is only as good as that key and the investigation behind it.
- Every number in an attestation comes from public on-chain data, and the attestation carries a SHA-256 hash of the evidence. Anyone can rerun the investigation and compare.
- The program never holds funds. It only checks and, if a check fails, makes the whole purchase transaction fail.

## On-chain checks (`assert_launch_policy`)

| Attack | Protection |
|---|---|
| Fake attestation | The Ed25519 signature is verified by the native Ed25519 program; the program requires the signing key to equal the configured attester. |
| Signature for something else accepted as an attestation | Fixed `LAUNCHPROOF` prefix and version byte in the signed message. |
| Offset redirection in the Ed25519 instruction | Exactly one signature, and signature, key and message must all live inside the Ed25519 instruction itself. |
| Reusing an Ed25519 instruction from elsewhere in the transaction | The Ed25519 instruction must be the one immediately before `assert_launch_policy` (relative index). |
| Devnet attestation used on mainnet or the reverse | Network byte in the message, compared with the config. |
| Stale attestation | Buyer-chosen maximum age; attestations dated in the future are rejected. |
| Valid attestation for token A attached to a purchase of token B | A later instruction in the same transaction must belong to an accepted buy program and reference the attested mint. |
| Front-running config initialization after deploy | Only the program's upgrade authority, read from the ProgramData account, can initialize the config. |
| Admin actions by anyone else | `has_one = admin` on every admin instruction. |
| Emergency | `set_paused` makes every guarded purchase fail; nothing passes unchecked. |

All of these cases are covered by tests in `tests/` (run `scripts/test-program.sh`).

## Off-chain service

- The attester key is loaded from an environment variable on the server and never sent to clients. Rotate it with `set_attester` if it leaks.
- The Helius key and database URL live only in server environment variables; the web client and MCP server never see them.
- The API validates every input (addresses, amount up to 5 SOL, limits in range), rate limits per client IP, and returns generic messages for internal errors.
- The API builds unsigned transactions. Users and agents sign with their own wallets; LaunchProof never handles user keys.
- The web client inserts API data as text only, never as HTML.
- The MCP agent wallet is optional, devnet only, and capped per purchase (`LP_AGENT_MAX_SOL`).

## Known limitations

- Funding links follow up to two hops. Laundering through more hops or through high-activity wallets is not detected; high-activity wallets are treated as neutral to avoid false links through exchanges and faucets.
- "Launch" means the first 150 slots (about one minute) after creation.
- Earlier launches are found in the creator's last 100 transactions; when there are more, the report is marked partial.
- The investigation trusts the RPC provider's data.
- The client IP for rate limiting is taken from the last `X-Forwarded-For` entry added by the hosting proxy.

## Reporting

Open a private security advisory on the GitHub repository.
