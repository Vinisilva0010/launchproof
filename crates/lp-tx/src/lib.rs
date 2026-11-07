//! Instruction builders shared by the CLI, the API server and the MCP server.
//! Pump.fun layouts follow pump-fun/pump-public-docs; discriminators are read
//! from idls/pump.json.

use std::str::FromStr;

use anchor_lang::prelude::Pubkey;
use anchor_lang::{InstructionData, ToAccountMetas};
use anyhow::{anyhow, bail, Context, Result};
use launchproof::PolicyArgs;
use lp_attest::{build_ed25519_instruction_data, Attestation};
use serde_json::Value;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_rpc_client::rpc_client::RpcClient;
use solana_signer::Signer;

pub const PUMP: &str = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P";
pub const PUMP_FEES: &str = "pfeeUxB6jkeY1Hxd7CsFCAjcbHA9rWtchMGdZ6VojVZ";
pub const MAYHEM: &str = "MAyhSmzXzV1pTf7LsNkrNwkWKTo4ougAJ1PPg47MD4e";
pub const TOKEN_2022: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
pub const ATA_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
/// One of the fee recipients that buys must append (docs/BREAKING_FEE_RECIPIENT.md).
pub const EXTRA_FEE_RECIPIENT: &str = "5YxQFdt3Tr9zJLvkFccqXVUwhdTWJQc1fFg2YPbxvxeD";
/// Second seed of the fee_config PDA, taken from idls/pump.json.
const FEE_CONFIG_SEED: [u8; 32] = [
    0x01, 0x56, 0xe0, 0xf6, 0x93, 0x66, 0x5a, 0xcf, 0x44, 0xdb, 0x15, 0x68, 0xbf, 0x17, 0x5b, 0xaa,
    0x51, 0x89, 0xcb, 0x97, 0xf5, 0xd2, 0xff, 0x3b, 0x65, 0x5d, 0x2b, 0xb6, 0xfd, 0x6d, 0x18, 0xb0,
];
const PUMP_IDL: &str = include_str!("../../../idls/pump.json");
const LAMPORTS_PER_SOL: f64 = 1_000_000_000.0;

pub fn pk(s: &str) -> Pubkey {
    Pubkey::from_str(s).expect("valid constant address")
}

pub fn pda(seeds: &[&[u8]], program: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(seeds, program).0
}

/// Token-2022 associated token account (Pump.fun create_v2 coins use Token-2022).
pub fn ata(owner: &Pubkey, mint: &Pubkey) -> Pubkey {
    pda(&[owner.as_ref(), pk(TOKEN_2022).as_ref(), mint.as_ref()], &pk(ATA_PROGRAM))
}

pub fn w(key: Pubkey) -> AccountMeta {
    AccountMeta::new(key, false)
}

pub fn r(key: Pubkey) -> AccountMeta {
    AccountMeta::new_readonly(key, false)
}

pub fn lamports(sol: f64) -> u64 {
    (sol * LAMPORTS_PER_SOL).round() as u64
}

pub fn bonding_curve(mint: &Pubkey) -> Pubkey {
    pda(&[b"bonding-curve", mint.as_ref()], &pk(PUMP))
}

pub const METAPLEX: &str = "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s";

/// Accounts used by a token's creation but never by its trades, so their
/// oldest transaction is the creation even when the token has a long history:
/// the Mayhem state PDA (create_v2) and the Metaplex metadata PDA (create).
pub fn creation_hints(mint: &Pubkey) -> Vec<String> {
    let metaplex = pk(METAPLEX);
    vec![
        pda(&[b"mayhem-state", mint.as_ref()], &pk(MAYHEM)).to_string(),
        pda(&[b"metadata", metaplex.as_ref(), mint.as_ref()], &metaplex).to_string(),
    ]
}

pub fn config_address() -> Pubkey {
    pda(&[b"config"], &launchproof::ID)
}

fn discriminator(name: &str) -> Result<Vec<u8>> {
    let idl: Value = serde_json::from_str(PUMP_IDL)?;
    let ix = idl["instructions"]
        .as_array()
        .and_then(|list| list.iter().find(|i| i["name"] == name))
        .ok_or_else(|| anyhow!("instruction {name} not in idls/pump.json"))?;
    ix["discriminator"]
        .as_array()
        .ok_or_else(|| anyhow!("{name} has no discriminator"))?
        .iter()
        .map(|b| b.as_u64().map(|v| v as u8).ok_or_else(|| anyhow!("bad discriminator byte")))
        .collect()
}

fn put_str(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(&(s.len() as u32).to_le_bytes());
    buf.extend_from_slice(s.as_bytes());
}

fn read_u64(data: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(data[at..at + 8].try_into().expect("8 bytes"))
}

fn read_pubkey(data: &[u8], at: usize) -> Pubkey {
    Pubkey::new_from_array(data[at..at + 32].try_into().expect("32 bytes"))
}

pub struct Curve {
    pub virtual_token: u64,
    pub virtual_quote: u64,
    pub real_token: u64,
    pub complete: bool,
    pub creator: Pubkey,
}

/// BondingCurve layout from idls/pump.json, after the 8-byte discriminator.
pub fn read_curve(rpc: &RpcClient, mint: &Pubkey) -> Result<Curve> {
    let data = rpc.get_account_data(&bonding_curve(mint)).context("bonding curve not found")?;
    if data.len() < 81 {
        bail!("bonding curve account too small");
    }
    Ok(Curve {
        virtual_token: read_u64(&data, 8),
        virtual_quote: read_u64(&data, 16),
        real_token: read_u64(&data, 24),
        complete: data[48] != 0,
        creator: read_pubkey(&data, 49),
    })
}

/// Global.fee_recipient: discriminator(8) + initialized(1) + authority(32).
pub fn read_fee_recipient(rpc: &RpcClient) -> Result<Pubkey> {
    let data = rpc.get_account_data(&pda(&[b"global"], &pk(PUMP)))?;
    if data.len() < 73 {
        bail!("pump global account too small");
    }
    Ok(read_pubkey(&data, 41))
}

pub fn create_v2_ix(mint: &Pubkey, user: &Pubkey, name: &str, symbol: &str, uri: &str) -> Result<Instruction> {
    let (pump, mayhem) = (pk(PUMP), pk(MAYHEM));
    let curve = bonding_curve(mint);
    let sol_vault = pda(&[b"sol-vault"], &mayhem);
    let mut data = discriminator("create_v2")?;
    put_str(&mut data, name);
    put_str(&mut data, symbol);
    put_str(&mut data, uri);
    data.extend_from_slice(user.as_ref()); // creator
    data.push(0); // is_mayhem_mode = false; trailing optional args omitted
    Ok(Instruction {
        program_id: pump,
        accounts: vec![
            AccountMeta::new(*mint, true),
            r(pda(&[b"mint-authority"], &pump)),
            w(curve),
            w(ata(&curve, mint)),
            r(pda(&[b"global"], &pump)),
            AccountMeta::new(*user, true),
            r(solana_sdk_ids::system_program::ID),
            r(pk(TOKEN_2022)),
            r(pk(ATA_PROGRAM)),
            w(mayhem),
            r(pda(&[b"global-params"], &mayhem)),
            w(sol_vault),
            w(pda(&[b"mayhem-state", mint.as_ref()], &mayhem)),
            w(ata(&sol_vault, mint)),
            r(pda(&[b"__event_authority"], &pump)),
            r(pump),
        ],
        data,
    })
}

/// Idempotent creation of the buyer's Token-2022 associated token account.
pub fn create_ata_ix(payer: &Pubkey, owner: &Pubkey, mint: &Pubkey) -> Instruction {
    Instruction {
        program_id: pk(ATA_PROGRAM),
        accounts: vec![
            AccountMeta::new(*payer, true),
            w(ata(owner, mint)),
            r(*owner),
            r(*mint),
            r(solana_sdk_ids::system_program::ID),
            r(pk(TOKEN_2022)),
        ],
        data: vec![1],
    }
}

/// Pump.fun `buy` spending at most `sol_in` lamports. 16 IDL accounts plus
/// bonding-curve-v2 and one extra fee recipient (18 total).
pub fn buy_ixs(rpc: &RpcClient, mint: &Pubkey, user: &Pubkey, sol_in: u64) -> Result<Vec<Instruction>> {
    let (pump, fees) = (pk(PUMP), pk(PUMP_FEES));
    let curve = read_curve(rpc, mint)?;
    if curve.complete {
        bail!("bonding curve is complete; token has migrated");
    }
    // Leave 3% of the SOL for fees so max_sol_cost covers the real cost.
    let net = u128::from(sol_in) * 97 / 100;
    let (vt, vq) = (u128::from(curve.virtual_token), u128::from(curve.virtual_quote));
    let tokens_out = vt - (vq * vt) / (vq + net);
    // Never ask for more than the curve still holds (devnet curves are small).
    let tokens_out = u64::try_from(tokens_out)?.min(curve.real_token / 100 * 95);
    if tokens_out == 0 {
        bail!("purchase too small");
    }

    let curve_address = bonding_curve(mint);
    let mut data = discriminator("buy")?;
    data.extend_from_slice(&tokens_out.to_le_bytes());
    data.extend_from_slice(&sol_in.to_le_bytes()); // max_sol_cost
    let buy = Instruction {
        program_id: pump,
        accounts: vec![
            r(pda(&[b"global"], &pump)),
            w(read_fee_recipient(rpc)?),
            r(*mint),
            w(curve_address),
            w(ata(&curve_address, mint)),
            w(ata(user, mint)),
            AccountMeta::new(*user, true),
            r(solana_sdk_ids::system_program::ID),
            r(pk(TOKEN_2022)),
            w(pda(&[b"creator-vault", curve.creator.as_ref()], &pump)),
            r(pda(&[b"__event_authority"], &pump)),
            r(pump),
            r(pda(&[b"global_volume_accumulator"], &pump)),
            w(pda(&[b"user_volume_accumulator", user.as_ref()], &pump)),
            r(pda(&[b"fee_config", &FEE_CONFIG_SEED], &fees)),
            r(fees),
            w(pda(&[b"bonding-curve-v2", mint.as_ref()], &pump)),
            w(pk(EXTRA_FEE_RECIPIENT)),
        ],
        data,
    };
    Ok(vec![create_ata_ix(user, user, mint), buy])
}

/// Ed25519 attestation instruction followed by assert_launch_policy.
pub fn guard_ixs(attester: &Keypair, attestation: &Attestation, policy: PolicyArgs) -> Result<Vec<Instruction>> {
    let message = attestation.encode().map_err(|e| anyhow!("invalid attestation: {e:?}"))?;
    let mut signature = [0u8; 64];
    signature.copy_from_slice(attester.sign_message(&message).as_ref());
    let ed25519 = Instruction {
        program_id: solana_sdk_ids::ed25519_program::ID,
        accounts: vec![],
        data: build_ed25519_instruction_data(&attester.pubkey().to_bytes(), &signature, &message),
    };
    let assert = Instruction {
        program_id: launchproof::ID,
        accounts: launchproof::accounts::AssertLaunchPolicy {
            config: config_address(),
            mint: Pubkey::new_from_array(attestation.mint),
            instructions: solana_sdk_ids::sysvar::instructions::ID,
        }
        .to_account_metas(None),
        data: launchproof::instruction::AssertLaunchPolicy { policy }.data(),
    };
    Ok(vec![ed25519, assert])
}

/// Full guarded purchase: guard instructions, then the Pump.fun buy.
pub fn guarded_buy_ixs(
    rpc: &RpcClient,
    attester: &Keypair,
    buyer: &Pubkey,
    sol_in: u64,
    attestation: &Attestation,
    policy: PolicyArgs,
) -> Result<Vec<Instruction>> {
    let mint = Pubkey::new_from_array(attestation.mint);
    let mut ixs = guard_ixs(attester, attestation, policy)?;
    ixs.extend(buy_ixs(rpc, &mint, buyer, sol_in)?);
    Ok(ixs)
}
