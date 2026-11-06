#!/usr/bin/env bash
# Runs the program tests against a fresh local validator from the installed Solana CLI.
set -euo pipefail
cd "$(dirname "$0")/.."

# Devnet does not have SBPFv3 enabled; build for v0, which devnet and the local validator both run.
cargo build-sbf --arch v0 --manifest-path programs/launchproof/Cargo.toml --sbf-out-dir target/deploy

mkdir -p target/test
[ -f target/test/admin.json ] || solana-keygen new --no-bip39-passphrase --silent -o target/test/admin.json
[ -f target/test/attester.json ] || solana-keygen new --no-bip39-passphrase --silent -o target/test/attester.json

PROGRAM_ID=$(solana-keygen pubkey target/deploy/launchproof-keypair.json)
ADMIN=$(solana-keygen pubkey target/test/admin.json)

solana-test-validator --reset --quiet --ledger target/test/ledger \
  --upgradeable-program "$PROGRAM_ID" target/deploy/launchproof.so "$ADMIN" \
  > target/test/validator.log 2>&1 &
VALIDATOR=$!
trap 'kill $VALIDATOR 2>/dev/null || true' EXIT

for _ in $(seq 1 60); do
  solana -u http://127.0.0.1:8899 cluster-version >/dev/null 2>&1 && break
  sleep 1
done

ADMIN_KEYPAIR="$PWD/target/test/admin.json" ATTESTER_KEYPAIR="$PWD/target/test/attester.json" \
  cargo +stable test -p launchproof-tests -- --test-threads=1 "$@"
