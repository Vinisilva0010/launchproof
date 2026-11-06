//! LaunchProof devnet CLI: program configuration, demo launches on Pump.fun
//! and guarded purchases. Pump.fun instructions follow docs/instructions in
//! pump-fun/pump-public-docs; discriminators are read from idls/pump.json.

use std::path::PathBuf;
use std::str::FromStr;
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anchor_lang::prelude::Pubkey;
use anchor_lang::{InstructionData, ToAccountMetas};
use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use launchproof::PolicyArgs;
use lp_attest::{build_ed25519_instruction_data, network, Attestation};
use serde_json::{json, Value};
use solana_commitment_config::CommitmentConfig;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::{read_keypair_file, Keypair};
use solana_rpc_client::rpc_client::RpcClient;
use solana_rpc_client_api::config::RpcSendTransactionConfig;
use solana_signer::Signer;
use solana_transaction::Transaction;

const PUMP: &str = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P";
const PUMP_FEES: &str = "pfeeUxB6jkeY1Hxd7CsFCAjcbHA9rWtchMGdZ6VojVZ";
const MAYHEM: &str = "MAyhSmzXzV1pTf7LsNkrNwkWKTo4ougAJ1PPg47MD4e";
const TOKEN_2022: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const ATA_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
/// One of the fee recipients that buys must append (docs/BREAKING_FEE_RECIPIENT.md).
const EXTRA_FEE_RECIPIENT: &str = "5YxQFdt3Tr9zJLvkFccqXVUwhdTWJQc1fFg2YPbxvxeD";
/// Second seed of the fee_config PDA, taken from idls/pump.json.
const FEE_CONFIG_SEED: [u8; 32] = [
    0x01, 0x56, 0xe0, 0xf6, 0x93, 0x66, 0x5a, 0xcf, 0x44, 0xdb, 0x15, 0x68, 0xbf, 0x17, 0x5b, 0xaa,
    0x51, 0x89, 0xcb, 0x97, 0xf5, 0xd2, 0xff, 0x3b, 0x65, 0x5d, 0x2b, 0xb6, 0xfd, 0x6d, 0x18, 0xb0,
];
const PUMP_IDL: &str = include_str!("../../../idls/pump.json");
const LAMPORTS_PER_SOL: f64 = 1_000_000_000.0;
const BUNDLE_WALLETS: usize = 5;
const BUNDLE_BUY_SOL: f64 = 0.15;

#[derive(Parser)]
#[command(about = "LaunchProof devnet CLI")]
struct Cli {
    #[arg(long, env = "LP_RPC_URL", default_value = "https://api.devnet.solana.com")]
    rpc: String,
    /// Fee payer and program upgrade authority. Defaults to ~/.config/solana/id.json.
    #[arg(long, env = "LP_PAYER")]
    payer: Option<PathBuf>,
    /// Attester keypair. Defaults to ~/.config/launchproof/attester-devnet.json.
    #[arg(long, env = "LP_ATTESTER")]
    attester: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
enum LaunchKind {
    Clean,
    Bundled,
}

impl LaunchKind {
    fn name(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Bundled => "bundled",
        }
    }
}

#[derive(Subcommand)]
enum Command {
    /// Create the config (devnet network, attester key) and accept Pump.fun as a buy program.
    InitConfig,
    /// Launch a demo token on Pump.fun devnet and save details to target/demo/<kind>.json.
    Launch {
        #[arg(value_enum)]
        kind: LaunchKind,
    },
    /// Investigate a Pump.fun launch and print the risk report as JSON.
    Investigate {
        #[arg(long)]
        mint: Option<String>,
        #[arg(long, value_enum)]
        demo: Option<LaunchKind>,
    },
    /// Buy a token with the on-chain guard: Ed25519 attestation + assert_launch_policy + Pump.fun buy.
    GuardedBuy {
        /// Token mint. Alternatively use --demo.
        #[arg(long)]
        mint: Option<String>,
        /// Read the mint from target/demo/<kind>.json.
        #[arg(long, value_enum)]
        demo: Option<LaunchKind>,
        #[arg(long, default_value_t = 0.05)]
        sol: f64,
        /// Fill the attestation from a live investigation instead of the manual numbers below.
        #[arg(long)]
        auto: bool,
        /// Buying wallet. Defaults to ~/.config/launchproof/buyer-devnet.json (not the creator).
        #[arg(long)]
        buyer: Option<PathBuf>,
        #[arg(long, default_value_t = 0)]
        linked_initial_bps: u16,
        #[arg(long, default_value_t = 0)]
        linked_now_bps: u16,
        #[arg(long, default_value_t = 0)]
        creator_prior: u16,
        #[arg(long, default_value_t = 0)]
        creator_dead: u16,
        #[arg(long, default_value_t = 0)]
        flags: u32,
        #[arg(long, default_value_t = 3_000)]
        max_linked_initial_bps: u16,
        #[arg(long, default_value_t = 3_000)]
        max_linked_now_bps: u16,
        #[arg(long, default_value_t = 2)]
        max_creator_dead: u16,
        #[arg(long, default_value_t = 0)]
        deny_flags: u32,
        #[arg(long, default_value_t = 600)]
        max_age_secs: u32,
    },
}

fn pk(s: &str) -> Pubkey {
    Pubkey::from_str(s).expect("valid constant address")
}

fn pda(seeds: &[&[u8]], program: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(seeds, program).0
}

/// Token-2022 associated token account (Pump.fun create_v2 coins use Token-2022).
fn ata(owner: &Pubkey, mint: &Pubkey) -> Pubkey {
    pda(&[owner.as_ref(), pk(TOKEN_2022).as_ref(), mint.as_ref()], &pk(ATA_PROGRAM))
}

fn w(key: Pubkey) -> AccountMeta {
    AccountMeta::new(key, false)
}

fn r(key: Pubkey) -> AccountMeta {
    AccountMeta::new_readonly(key, false)
}

fn lamports(sol: f64) -> u64 {
    (sol * LAMPORTS_PER_SOL).round() as u64
}

fn home_path(rel: &str) -> PathBuf {
    PathBuf::from(std::env::var("HOME").expect("HOME is set")).join(rel)
}

fn load_keypair(path: &PathBuf) -> Result<Keypair> {
    read_keypair_file(path).map_err(|e| anyhow!("cannot read keypair {}: {e}", path.display()))
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

struct Curve {
    virtual_token: u64,
    virtual_quote: u64,
    real_token: u64,
    complete: bool,
    creator: Pubkey,
}

/// BondingCurve layout from idls/pump.json, after the 8-byte discriminator.
fn read_curve(rpc: &RpcClient, mint: &Pubkey) -> Result<Curve> {
    let address = pda(&[b"bonding-curve", mint.as_ref()], &pk(PUMP));
    let data = rpc.get_account_data(&address).context("bonding curve not found")?;
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
fn read_fee_recipient(rpc: &RpcClient) -> Result<Pubkey> {
    let data = rpc.get_account_data(&pda(&[b"global"], &pk(PUMP)))?;
    if data.len() < 73 {
        bail!("pump global account too small");
    }
    Ok(read_pubkey(&data, 41))
}

fn create_v2_ix(mint: &Pubkey, user: &Pubkey, name: &str, symbol: &str, uri: &str) -> Result<Instruction> {
    let (pump, mayhem) = (pk(PUMP), pk(MAYHEM));
    let bonding_curve = pda(&[b"bonding-curve", mint.as_ref()], &pump);
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
            w(bonding_curve),
            w(ata(&bonding_curve, mint)),
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
fn create_ata_ix(payer: &Pubkey, owner: &Pubkey, mint: &Pubkey) -> Instruction {
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
fn buy_ixs(rpc: &RpcClient, mint: &Pubkey, user: &Pubkey, sol_in: u64) -> Result<Vec<Instruction>> {
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

    let bonding_curve = pda(&[b"bonding-curve", mint.as_ref()], &pump);
    let mut data = discriminator("buy")?;
    data.extend_from_slice(&tokens_out.to_le_bytes());
    data.extend_from_slice(&sol_in.to_le_bytes()); // max_sol_cost
    let buy = Instruction {
        program_id: pump,
        accounts: vec![
            r(pda(&[b"global"], &pump)),
            w(read_fee_recipient(rpc)?),
            r(*mint),
            w(bonding_curve),
            w(ata(&bonding_curve, mint)),
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

fn transaction(rpc: &RpcClient, ixs: &[Instruction], payer: &Keypair, extra: &[&Keypair]) -> Result<Transaction> {
    let mut signers: Vec<&Keypair> = vec![payer];
    signers.extend_from_slice(extra);
    let blockhash = rpc.get_latest_blockhash()?;
    Ok(Transaction::new_signed_with_payer(ixs, Some(&payer.pubkey()), &signers, blockhash))
}

/// Simulates first so failures show program logs, then sends and confirms.
fn submit(rpc: &RpcClient, label: &str, ixs: &[Instruction], payer: &Keypair, extra: &[&Keypair]) -> Result<String> {
    let tx = transaction(rpc, ixs, payer, extra)?;
    let sim = rpc.simulate_transaction(&tx)?.value;
    if let Some(err) = sim.err {
        for line in sim.logs.unwrap_or_default() {
            eprintln!("  {line}");
        }
        bail!("{label}: simulation failed: {err:?}");
    }
    let sig = rpc.send_and_confirm_transaction(&tx)?.to_string();
    println!("{label}: {sig}");
    Ok(sig)
}

fn config_address() -> Pubkey {
    pda(&[b"config"], &launchproof::ID)
}

fn init_config(rpc: &RpcClient, payer: &Keypair, attester: &Pubkey) -> Result<()> {
    let program_data = pda(&[launchproof::ID.as_ref()], &solana_sdk_ids::bpf_loader_upgradeable::ID);
    let init = Instruction {
        program_id: launchproof::ID,
        accounts: launchproof::accounts::InitializeConfig {
            admin: payer.pubkey(),
            config: config_address(),
            program_data,
            system_program: solana_sdk_ids::system_program::ID,
        }
        .to_account_metas(None),
        data: launchproof::instruction::InitializeConfig { network: network::DEVNET, attester: *attester }.data(),
    };
    let buy_programs = Instruction {
        program_id: launchproof::ID,
        accounts: launchproof::accounts::AdminOnly { admin: payer.pubkey(), config: config_address() }
            .to_account_metas(None),
        data: launchproof::instruction::SetBuyPrograms { programs: vec![pk(PUMP)] }.data(),
    };
    submit(rpc, "init-config", &[init, buy_programs], payer, &[])?;
    println!("config: {}", config_address());
    Ok(())
}

fn launch(rpc: &RpcClient, payer: &Keypair, kind: LaunchKind) -> Result<()> {
    let mint = Keypair::new();
    let mint_key = mint.pubkey();
    let creator = payer.pubkey();
    let mut record = json!({ "kind": kind.name(), "mint": mint_key.to_string(), "creator": creator.to_string() });

    let wallets: Vec<Keypair> = match kind {
        LaunchKind::Clean => vec![],
        LaunchKind::Bundled => (0..BUNDLE_WALLETS).map(|_| Keypair::new()).collect(),
    };
    if !wallets.is_empty() {
        // The creator funds the bundle wallets: the on-chain link the investigator looks for.
        let funding: Vec<Instruction> = wallets
            .iter()
            .map(|wlt| {
                let mut data = vec![2, 0, 0, 0];
                data.extend_from_slice(&lamports(1.1).to_le_bytes());
                Instruction {
                    program_id: solana_sdk_ids::system_program::ID,
                    accounts: vec![AccountMeta::new(creator, true), w(wlt.pubkey())],
                    data,
                }
            })
            .collect();
        record["funding_tx"] = json!(submit(rpc, "fund bundle wallets", &funding, payer, &[])?);
    }

    let (name, symbol) = match kind {
        LaunchKind::Clean => ("LaunchProof Clean Demo", "LPCLEAN"),
        LaunchKind::Bundled => ("LaunchProof Bundle Demo", "LPBUND"),
    };
    let create = create_v2_ix(&mint_key, &creator, name, symbol, "https://launchproof.invalid/demo.json")?;
    record["create_tx"] = json!(submit(rpc, "create_v2", &[create], payer, &[&mint])?);

    let creator_sol = match kind {
        LaunchKind::Clean => 0.01,
        LaunchKind::Bundled => 0.1,
    };
    let ixs = buy_ixs(rpc, &mint_key, &creator, lamports(creator_sol))?;
    record["creator_buy_tx"] = json!(submit(rpc, "creator buy", &ixs, payer, &[])?);

    if !wallets.is_empty() {
        // Buy one after another right after creation; each buy reads the fresh curve price.
        let mut sigs = Vec::new();
        for (i, wlt) in wallets.iter().enumerate() {
            let ixs = buy_ixs(rpc, &mint_key, &wlt.pubkey(), lamports(BUNDLE_BUY_SOL))?;
            sigs.push(submit(rpc, &format!("bundle buy {}", i + 1), &ixs, wlt, &[])?);
        }
        record["bundle_wallets"] = json!(wallets.iter().map(|k| k.pubkey().to_string()).collect::<Vec<_>>());
        record["bundle_buy_txs"] = json!(sigs);
    }

    let path = PathBuf::from(format!("target/demo/{}.json", kind.name()));
    std::fs::write(&path, serde_json::to_string_pretty(&record)?)?;
    println!("mint: {mint_key}\nsaved: {}", path.display());
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn guarded_buy(rpc: &RpcClient, payer: &Keypair, attester: &Keypair, mint: Pubkey, sol: f64, attestation: Attestation, policy: PolicyArgs) -> Result<()> {
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
            mint,
            instructions: solana_sdk_ids::sysvar::instructions::ID,
        }
        .to_account_metas(None),
        data: launchproof::instruction::AssertLaunchPolicy { policy }.data(),
    };
    let mut ixs = vec![ed25519, assert];
    ixs.extend(buy_ixs(rpc, &mint, &payer.pubkey(), lamports(sol))?);

    // Sent without preflight so a rejected purchase is recorded on-chain as a failed transaction.
    let tx = transaction(rpc, &ixs, payer, &[])?;
    let config = RpcSendTransactionConfig { skip_preflight: true, ..Default::default() };
    let sig = rpc.send_transaction_with_config(&tx, config)?;
    let link = format!("https://explorer.solana.com/tx/{sig}?cluster=devnet");
    for _ in 0..60 {
        if let Some(status) = rpc.get_signature_status(&sig)? {
            match status {
                Ok(()) => println!("PURCHASE EXECUTED: guard passed\n{link}"),
                Err(e) => println!("PURCHASE REVERTED by the guard: {e:?}\n{link}"),
            }
            return Ok(());
        }
        sleep(Duration::from_millis(500));
    }
    bail!("transaction not confirmed in time: {link}")
}

fn demo_mint(kind: LaunchKind) -> Result<Pubkey> {
    let path = format!("target/demo/{}.json", kind.name());
    let record: Value = serde_json::from_str(&std::fs::read_to_string(&path).with_context(|| format!("missing {path}"))?)?;
    Ok(pk(record["mint"].as_str().ok_or_else(|| anyhow!("no mint in {path}"))?))
}

fn resolve_mint(mint: Option<String>, demo: Option<LaunchKind>) -> Result<Pubkey> {
    match (mint, demo) {
        (Some(m), _) => Ok(Pubkey::from_str(&m)?),
        (None, Some(kind)) => demo_mint(kind),
        (None, None) => bail!("pass --mint or --demo"),
    }
}

fn run_investigation(rpc: &RpcClient, mint: &Pubkey) -> Result<lp_investigate::Report> {
    let curve = pda(&[b"bonding-curve", mint.as_ref()], &pk(PUMP));
    let report = lp_investigate::investigate(rpc, &mint.to_string(), &curve.to_string())?;
    eprintln!(
        "investigation: linked wallets {}, bought at launch {:.2}%, holding now {:.2}%, earlier launches {} ({} dead), partial: {:?}",
        report.linked_wallets.len(),
        f64::from(report.linked_initial_bps) / 100.0,
        f64::from(report.linked_now_bps) / 100.0,
        report.creator_prior_launches.len(),
        report.creator_dead_launches.len(),
        report.partial_reasons,
    );
    Ok(report)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let rpc = RpcClient::new_with_commitment(cli.rpc.clone(), CommitmentConfig::confirmed());
    let payer = load_keypair(&cli.payer.clone().unwrap_or_else(|| home_path(".config/solana/id.json")))?;
    let attester_path = cli.attester.clone().unwrap_or_else(|| home_path(".config/launchproof/attester-devnet.json"));

    match cli.command {
        Command::InitConfig => init_config(&rpc, &payer, &load_keypair(&attester_path)?.pubkey()),
        Command::Launch { kind } => launch(&rpc, &payer, kind),
        Command::Investigate { mint, demo } => {
            let mint = resolve_mint(mint, demo)?;
            let report = run_investigation(&rpc, &mint)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        Command::GuardedBuy {
            mint, demo, sol, auto, buyer, linked_initial_bps, linked_now_bps, creator_prior, creator_dead, flags,
            max_linked_initial_bps, max_linked_now_bps, max_creator_dead, deny_flags, max_age_secs,
        } => {
            let mint = resolve_mint(mint, demo)?;
            let issued_at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
            let attestation = if auto {
                run_investigation(&rpc, &mint)?.attestation(network::DEVNET, issued_at)?
            } else {
                Attestation {
                    network: network::DEVNET,
                    mint: mint.to_bytes(),
                    linked_initial_bps,
                    linked_now_bps,
                    creator_prior,
                    creator_dead,
                    flags,
                    issued_at,
                    evidence_hash: [0; 32],
                }
            };
            let policy = PolicyArgs { max_linked_initial_bps, max_linked_now_bps, max_creator_dead, deny_flags, max_age_secs };
            let buyer = load_keypair(&buyer.unwrap_or_else(|| home_path(".config/launchproof/buyer-devnet.json")))?;
            guarded_buy(&rpc, &buyer, &load_keypair(&attester_path)?, mint, sol, attestation, policy)
        }
    }
}
