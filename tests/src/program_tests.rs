//! Program tests against a local validator. Run with scripts/test-program.sh.
//! The "purchase" is a system transfer to the mint address, so a failed check
//! must leave the mint balance at zero (whole transaction reverted).

use std::rc::Rc;
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anchor_client::{Client, Cluster, CommitmentConfig, Program};
use anchor_lang::prelude::Pubkey;
use anchor_lang::{InstructionData, ToAccountMetas};
use launchproof::error::LaunchProofError;
use launchproof::PolicyArgs;
use lp_attest::{build_ed25519_instruction_data, flags, network, Attestation};
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::{read_keypair_file, Keypair};
use solana_signer::Signer;

const SOL: u64 = 1_000_000_000;
const BUY_LAMPORTS: u64 = SOL;

fn keypair_from_env(var: &str) -> Keypair {
    let path = std::env::var(var).unwrap_or_else(|_| panic!("{var} not set; run scripts/test-program.sh"));
    read_keypair_file(&path).unwrap()
}

fn program_for(payer: Rc<Keypair>) -> Program<Rc<Keypair>> {
    Client::new_with_options(Cluster::Localnet, payer, CommitmentConfig::confirmed())
        .program(launchproof::ID)
        .unwrap()
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

fn fund(program: &Program<Rc<Keypair>>, who: &Pubkey, lamports: u64) {
    let rpc = program.rpc();
    if rpc.get_balance(who).unwrap() >= lamports {
        return;
    }
    rpc.request_airdrop(who, lamports).unwrap();
    for _ in 0..60 {
        if rpc.get_balance(who).unwrap() >= lamports {
            return;
        }
        sleep(Duration::from_millis(500));
    }
    panic!("airdrop did not land");
}

fn config_address() -> Pubkey {
    Pubkey::find_program_address(&[b"config"], &launchproof::ID).0
}

fn program_data_address() -> Pubkey {
    Pubkey::find_program_address(&[launchproof::ID.as_ref()], &solana_sdk_ids::bpf_loader_upgradeable::ID).0
}

/// Sends the instructions with the program's payer as the only signer.
fn send(program: &Program<Rc<Keypair>>, ixs: Vec<Instruction>) -> Result<(), String> {
    let mut request = program.request();
    for ix in ixs {
        request = request.instruction(ix);
    }
    request.send().map(|_| ()).map_err(|e| format!("{e:?}"))
}

fn is_custom(err: &str, code: LaunchProofError) -> bool {
    let n = u32::from(code);
    err.contains(&format!("Custom({n})")) || err.contains(&format!("0x{n:x}"))
}

fn init_ix(admin: &Pubkey, attester: &Pubkey) -> Instruction {
    Instruction {
        program_id: launchproof::ID,
        accounts: launchproof::accounts::InitializeConfig {
            admin: *admin,
            config: config_address(),
            program_data: program_data_address(),
            system_program: solana_sdk_ids::system_program::ID,
        }
        .to_account_metas(None),
        data: launchproof::instruction::InitializeConfig { network: network::DEVNET, attester: *attester }.data(),
    }
}

fn admin_ix(signer: &Pubkey, data: Vec<u8>) -> Instruction {
    Instruction {
        program_id: launchproof::ID,
        accounts: launchproof::accounts::AdminOnly { admin: *signer, config: config_address() }.to_account_metas(None),
        data,
    }
}

fn set_buy_programs_ix(admin: &Pubkey, programs: Vec<Pubkey>) -> Instruction {
    admin_ix(admin, launchproof::instruction::SetBuyPrograms { programs }.data())
}

struct Env {
    admin: Program<Rc<Keypair>>,
    admin_key: Pubkey,
    attester: Keypair,
    buyer: Program<Rc<Keypair>>,
    buyer_key: Pubkey,
    mint: Pubkey,
}

/// Creates the config once per validator run. The first time, it also proves
/// that a wallet other than the upgrade authority cannot initialize it.
fn env() -> Env {
    let admin_kp = Rc::new(keypair_from_env("ADMIN_KEYPAIR"));
    let attester = keypair_from_env("ATTESTER_KEYPAIR");
    let admin_key = admin_kp.pubkey();
    let admin = program_for(admin_kp);
    fund(&admin, &admin_key, 10 * SOL);

    if admin.rpc().get_account(&config_address()).is_err() {
        let intruder = Rc::new(Keypair::new());
        let intruder_key = intruder.pubkey();
        let intruder_program = program_for(intruder);
        fund(&intruder_program, &intruder_key, SOL);
        let err = send(&intruder_program, vec![init_ix(&intruder_key, &intruder_key)]).expect_err("intruder init must fail");
        assert!(is_custom(&err, LaunchProofError::Unauthorized), "intruder init: {err}");

        send(&admin, vec![init_ix(&admin_key, &attester.pubkey())]).unwrap();
        // The system program stands in for a launchpad buy program.
        send(&admin, vec![set_buy_programs_ix(&admin_key, vec![solana_sdk_ids::system_program::ID])]).unwrap();
    }

    let buyer_kp = Rc::new(Keypair::new());
    let buyer_key = buyer_kp.pubkey();
    let buyer = program_for(buyer_kp);
    fund(&buyer, &buyer_key, 10 * SOL);
    Env { admin, admin_key, attester, buyer, buyer_key, mint: Pubkey::new_unique() }
}

fn attestation(env: &Env) -> Attestation {
    Attestation {
        network: network::DEVNET,
        mint: env.mint.to_bytes(),
        linked_initial_bps: 1_000,
        linked_now_bps: 500,
        creator_prior: 1,
        creator_dead: 0,
        flags: 0,
        issued_at: now() - 10,
        evidence_hash: [7; 32],
    }
}

fn policy() -> PolicyArgs {
    PolicyArgs { max_linked_initial_bps: 3_000, max_linked_now_bps: 3_000, max_creator_dead: 2, deny_flags: 0, max_age_secs: 600 }
}

fn ed25519_ix(signer: &Keypair, message: &[u8]) -> Instruction {
    let mut signature = [0u8; 64];
    signature.copy_from_slice(signer.sign_message(message).as_ref());
    Instruction {
        program_id: solana_sdk_ids::ed25519_program::ID,
        accounts: vec![],
        data: build_ed25519_instruction_data(&signer.pubkey().to_bytes(), &signature, message),
    }
}

fn assert_ix(mint: Pubkey, policy: PolicyArgs) -> Instruction {
    Instruction {
        program_id: launchproof::ID,
        accounts: launchproof::accounts::AssertLaunchPolicy {
            config: config_address(),
            mint,
            instructions: solana_sdk_ids::sysvar::instructions::ID,
        }
        .to_account_metas(None),
        data: launchproof::instruction::AssertLaunchPolicy { policy }.data(),
    }
}

/// System transfer from the buyer to `to`; stands in for a launchpad purchase.
fn buy_ix(env: &Env, to: Pubkey) -> Instruction {
    let mut data = vec![2, 0, 0, 0];
    data.extend_from_slice(&BUY_LAMPORTS.to_le_bytes());
    Instruction {
        program_id: solana_sdk_ids::system_program::ID,
        accounts: vec![AccountMeta::new(env.buyer_key, true), AccountMeta::new(to, false)],
        data,
    }
}

fn guarded(env: &Env, a: Attestation, signer: &Keypair, p: PolicyArgs) -> Vec<Instruction> {
    let message = a.encode().unwrap();
    vec![ed25519_ix(signer, &message), assert_ix(env.mint, p), buy_ix(env, env.mint)]
}

fn mint_balance(env: &Env) -> u64 {
    env.buyer.rpc().get_balance(&env.mint).unwrap()
}

fn expect_rejected(env: &Env, ixs: Vec<Instruction>, code: Option<LaunchProofError>) {
    let err = send(&env.buyer, ixs).expect_err("transaction must fail");
    if let Some(code) = code {
        assert!(is_custom(&err, code), "expected {code:?}, got {err}");
    }
    assert_eq!(mint_balance(env), 0, "purchase must be reverted");
}

#[test]
fn valid_attestation_lets_purchase_through() {
    let env = env();
    send(&env.buyer, guarded(&env, attestation(&env), &env.attester, policy())).unwrap();
    assert_eq!(mint_balance(&env), BUY_LAMPORTS);
}

#[test]
fn rejects_wrong_attester() {
    let env = env();
    let impostor = Keypair::new();
    expect_rejected(&env, guarded(&env, attestation(&env), &impostor, policy()), Some(LaunchProofError::WrongAttester));
}

#[test]
fn rejects_tampered_message() {
    let env = env();
    let mut ixs = guarded(&env, attestation(&env), &env.attester, policy());
    let last = ixs[0].data.len() - 1;
    ixs[0].data[last] ^= 1;
    expect_rejected(&env, ixs, None);
}

#[test]
fn rejects_missing_ed25519() {
    let env = env();
    let ixs = vec![assert_ix(env.mint, policy()), buy_ix(&env, env.mint)];
    expect_rejected(&env, ixs, Some(LaunchProofError::MissingEd25519Instruction));
}

#[test]
fn rejects_non_adjacent_ed25519() {
    let env = env();
    let message = attestation(&env).encode().unwrap();
    let filler = buy_ix(&env, Pubkey::new_unique());
    let ixs = vec![ed25519_ix(&env.attester, &message), filler, assert_ix(env.mint, policy()), buy_ix(&env, env.mint)];
    expect_rejected(&env, ixs, Some(LaunchProofError::NotEd25519Program));
}

#[test]
fn rejects_wrong_network_and_stale_or_future_timestamps() {
    let changes: [(fn(Attestation) -> Attestation, LaunchProofError); 3] = [
        (|a| Attestation { network: network::MAINNET, ..a }, LaunchProofError::WrongNetwork),
        (|a| Attestation { issued_at: a.issued_at - 3_600, ..a }, LaunchProofError::Expired),
        (|a| Attestation { issued_at: a.issued_at + 3_600, ..a }, LaunchProofError::IssuedInFuture),
    ];
    for (change, code) in changes {
        let env = env();
        expect_rejected(&env, guarded(&env, change(attestation(&env)), &env.attester, policy()), Some(code));
    }
}

#[test]
fn rejects_each_policy_limit() {
    let cases: [(fn(Attestation) -> Attestation, PolicyArgs, LaunchProofError); 4] = [
        (|a| Attestation { linked_initial_bps: 3_001, ..a }, policy(), LaunchProofError::LinkedInitialTooHigh),
        (|a| Attestation { linked_now_bps: 3_001, ..a }, policy(), LaunchProofError::LinkedNowTooHigh),
        (|a| Attestation { creator_prior: 5, creator_dead: 3, ..a }, policy(), LaunchProofError::TooManyDeadLaunches),
        (
            |a| Attestation { flags: flags::MINT_AUTHORITY_ACTIVE, ..a },
            PolicyArgs { deny_flags: flags::MINT_AUTHORITY_ACTIVE, ..policy() },
            LaunchProofError::DeniedFlag,
        ),
    ];
    for (change, p, code) in cases {
        let env = env();
        expect_rejected(&env, guarded(&env, change(attestation(&env)), &env.attester, p), Some(code));
    }
}

#[test]
fn rejects_attestation_for_other_mint() {
    let env = env();
    let a = Attestation { mint: Pubkey::new_unique().to_bytes(), ..attestation(&env) };
    expect_rejected(&env, guarded(&env, a, &env.attester, policy()), Some(LaunchProofError::MintMismatch));
}

#[test]
fn rejects_when_no_purchase_is_bound_to_the_mint() {
    let env = env();
    let message = attestation(&env).encode().unwrap();
    let no_buy = vec![ed25519_ix(&env.attester, &message), assert_ix(env.mint, policy())];
    expect_rejected(&env, no_buy, Some(LaunchProofError::NoBoundBuyInstruction));
    let other = vec![ed25519_ix(&env.attester, &message), assert_ix(env.mint, policy()), buy_ix(&env, Pubkey::new_unique())];
    expect_rejected(&env, other, Some(LaunchProofError::NoBoundBuyInstruction));
}

#[test]
fn rejects_purchase_through_unlisted_program() {
    let env = env();
    send(&env.admin, vec![set_buy_programs_ix(&env.admin_key, vec![Pubkey::new_unique()])]).unwrap();
    let result = send(&env.buyer, guarded(&env, attestation(&env), &env.attester, policy()));
    send(&env.admin, vec![set_buy_programs_ix(&env.admin_key, vec![solana_sdk_ids::system_program::ID])]).unwrap();
    let err = result.expect_err("must fail");
    assert!(is_custom(&err, LaunchProofError::NoBoundBuyInstruction), "got {err}");
    assert_eq!(mint_balance(&env), 0);
}

#[test]
fn rejects_everything_when_paused() {
    let env = env();
    let pause = |paused| admin_ix(&env.admin_key, launchproof::instruction::SetPaused { paused }.data());
    send(&env.admin, vec![pause(true)]).unwrap();
    let result = send(&env.buyer, guarded(&env, attestation(&env), &env.attester, policy()));
    send(&env.admin, vec![pause(false)]).unwrap();
    let err = result.expect_err("must fail");
    assert!(is_custom(&err, LaunchProofError::Paused), "got {err}");
    assert_eq!(mint_balance(&env), 0);
}

#[test]
fn admin_actions_require_admin() {
    let env = env();
    let intruder = Rc::new(Keypair::new());
    let intruder_key = intruder.pubkey();
    let intruder_program = program_for(intruder);
    fund(&intruder_program, &intruder_key, SOL);
    let datas = [
        launchproof::instruction::SetAttester { attester: intruder_key }.data(),
        launchproof::instruction::SetPaused { paused: true }.data(),
        launchproof::instruction::SetBuyPrograms { programs: vec![] }.data(),
    ];
    for data in datas {
        let err = send(&intruder_program, vec![admin_ix(&intruder_key, data)]).expect_err("must fail");
        assert!(is_custom(&err, LaunchProofError::Unauthorized), "got {err}");
    }
}
