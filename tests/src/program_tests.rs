//! LiteSVM tests for the launchproof program. Run `anchor build` first.
//! The "purchase" is a system transfer to the mint address, so a failed
//! check must leave the mint balance untouched (whole transaction reverted).

use anchor_lang::prelude::Pubkey;
use anchor_lang::{InstructionData, ToAccountMetas};
use launchproof::error::LaunchProofError;
use launchproof::PolicyArgs;
use litesvm::LiteSVM;
use lp_attest::{build_ed25519_instruction_data, flags, network, Attestation};
use solana_account::Account;
use solana_clock::Clock;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;

const NOW: i64 = 1_790_000_000;
const BUY_LAMPORTS: u64 = 1_000_000_000;
const PROGRAM_SO: &[u8] = include_bytes!("../../target/deploy/launchproof.so");

struct Env {
    svm: LiteSVM,
    admin: Keypair,
    attester: Keypair,
    buyer: Keypair,
    config: Pubkey,
    mint: Pubkey,
}

fn program_data_address() -> Pubkey {
    Pubkey::find_program_address(&[launchproof::ID.as_ref()], &solana_sdk_ids::bpf_loader_upgradeable::ID).0
}

/// Makes `authority` the upgrade authority in the ProgramData header, keeping any ELF bytes.
fn set_upgrade_authority(svm: &mut LiteSVM, authority: &Pubkey) {
    let loader = solana_sdk_ids::bpf_loader_upgradeable::ID;
    let address = program_data_address();
    let mut data = match svm.get_account(&address) {
        Some(acc) if acc.owner == loader && acc.data.len() >= 45 => acc.data,
        _ => vec![0u8; 45],
    };
    data[0..4].copy_from_slice(&[3, 0, 0, 0]);
    data[12] = 1;
    data[13..45].copy_from_slice(authority.as_ref());
    let lamports = svm.minimum_balance_for_rent_exemption(data.len());
    svm.set_account(address, Account { lamports, data, owner: loader, executable: false, rent_epoch: 0 })
        .unwrap();
}

fn send(svm: &mut LiteSVM, ixs: &[Instruction], signers: &[&Keypair]) -> Result<(), String> {
    svm.expire_blockhash();
    let payer = signers[0].pubkey();
    let tx = Transaction::new(signers, Message::new(ixs, Some(&payer)), svm.latest_blockhash());
    svm.send_transaction(tx).map(|_| ()).map_err(|e| format!("{e:?}"))
}

fn custom(code: LaunchProofError) -> String {
    format!("Custom({})", u32::from(code))
}

fn admin_ix(env: &Env, signer: &Pubkey, data: Vec<u8>) -> Instruction {
    Instruction {
        program_id: launchproof::ID,
        accounts: launchproof::accounts::AdminOnly { admin: *signer, config: env.config }.to_account_metas(None),
        data,
    }
}

fn setup() -> Env {
    let mut svm = LiteSVM::new();
    svm.add_program(launchproof::ID, PROGRAM_SO).unwrap();
    let (admin, attester, buyer) = (Keypair::new(), Keypair::new(), Keypair::new());
    svm.airdrop(&admin.pubkey(), 10 * BUY_LAMPORTS).unwrap();
    svm.airdrop(&buyer.pubkey(), 10 * BUY_LAMPORTS).unwrap();
    set_upgrade_authority(&mut svm, &admin.pubkey());

    let mut clock = svm.get_sysvar::<Clock>();
    clock.unix_timestamp = NOW;
    svm.set_sysvar::<Clock>(&clock);

    let config = Pubkey::find_program_address(&[b"config"], &launchproof::ID).0;
    let mut env = Env { svm, admin, attester, buyer, config, mint: Pubkey::new_unique() };

    let init = Instruction {
        program_id: launchproof::ID,
        accounts: launchproof::accounts::InitializeConfig {
            admin: env.admin.pubkey(),
            config,
            program_data: program_data_address(),
            system_program: solana_sdk_ids::system_program::ID,
        }
        .to_account_metas(None),
        data: launchproof::instruction::InitializeConfig { network: network::DEVNET, attester: env.attester.pubkey() }
            .data(),
    };
    send(&mut env.svm, &[init], &[&env.admin]).unwrap();

    // The system program stands in for a launchpad buy program.
    let data = launchproof::instruction::SetBuyPrograms { programs: vec![solana_sdk_ids::system_program::ID] }.data();
    let ix = admin_ix(&env, &env.admin.pubkey(), data);
    send(&mut env.svm, &[ix], &[&env.admin]).unwrap();
    env
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
        issued_at: NOW - 10,
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

fn assert_ix(env: &Env, mint: Pubkey, policy: PolicyArgs) -> Instruction {
    Instruction {
        program_id: launchproof::ID,
        accounts: launchproof::accounts::AssertLaunchPolicy {
            config: env.config,
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
        accounts: vec![AccountMeta::new(env.buyer.pubkey(), true), AccountMeta::new(to, false)],
        data,
    }
}

fn guarded(env: &Env, a: Attestation, signer: &Keypair, p: PolicyArgs) -> Vec<Instruction> {
    let message = a.encode().unwrap();
    vec![ed25519_ix(signer, &message), assert_ix(env, env.mint, p), buy_ix(env, env.mint)]
}

fn mint_balance(env: &Env) -> u64 {
    env.svm.get_account(&env.mint).map(|a| a.lamports).unwrap_or(0)
}

fn expect_rejected(env: &mut Env, ixs: Vec<Instruction>, code: Option<LaunchProofError>) {
    let buyer = env.buyer.insecure_clone();
    let err = send(&mut env.svm, &ixs, &[&buyer]).expect_err("transaction must fail");
    if let Some(code) = code {
        assert!(err.contains(&custom(code)), "expected {code:?}, got {err}");
    }
    assert_eq!(mint_balance(env), 0, "purchase must be reverted");
}

#[test]
fn valid_attestation_lets_purchase_through() {
    let mut env = setup();
    let ixs = guarded(&env, attestation(&env), &env.attester, policy());
    let buyer = env.buyer.insecure_clone();
    send(&mut env.svm, &ixs, &[&buyer]).unwrap();
    assert_eq!(mint_balance(&env), BUY_LAMPORTS);
}

#[test]
fn rejects_wrong_attester() {
    let mut env = setup();
    let impostor = Keypair::new();
    let ixs = guarded(&env, attestation(&env), &impostor, policy());
    expect_rejected(&mut env, ixs, Some(LaunchProofError::WrongAttester));
}

#[test]
fn rejects_tampered_message() {
    let mut env = setup();
    let mut ixs = guarded(&env, attestation(&env), &env.attester, policy());
    let last = ixs[0].data.len() - 1;
    ixs[0].data[last] ^= 1;
    expect_rejected(&mut env, ixs, None);
}

#[test]
fn rejects_missing_ed25519() {
    let mut env = setup();
    let ixs = vec![assert_ix(&env, env.mint, policy()), buy_ix(&env, env.mint)];
    expect_rejected(&mut env, ixs, Some(LaunchProofError::MissingEd25519Instruction));
}

#[test]
fn rejects_non_adjacent_ed25519() {
    let mut env = setup();
    let message = attestation(&env).encode().unwrap();
    let filler = buy_ix(&env, Pubkey::new_unique());
    let ixs = vec![ed25519_ix(&env.attester, &message), filler, assert_ix(&env, env.mint, policy()), buy_ix(&env, env.mint)];
    expect_rejected(&mut env, ixs, Some(LaunchProofError::NotEd25519Program));
}

#[test]
fn rejects_wrong_network_and_stale_or_future_timestamps() {
    let cases = [
        (Attestation { network: network::MAINNET, ..attestation(&setup()) }, LaunchProofError::WrongNetwork),
        (Attestation { issued_at: NOW - 601, ..attestation(&setup()) }, LaunchProofError::Expired),
        (Attestation { issued_at: NOW + 61, ..attestation(&setup()) }, LaunchProofError::IssuedInFuture),
    ];
    for (a, code) in cases {
        let mut env = setup();
        let a = Attestation { mint: env.mint.to_bytes(), ..a };
        let ixs = guarded(&env, a, &env.attester, policy());
        expect_rejected(&mut env, ixs, Some(code));
    }
}

#[test]
fn rejects_each_policy_limit() {
    let cases = [
        (|a: Attestation| Attestation { linked_initial_bps: 3_001, ..a }, policy(), LaunchProofError::LinkedInitialTooHigh),
        (|a: Attestation| Attestation { linked_now_bps: 3_001, ..a }, policy(), LaunchProofError::LinkedNowTooHigh),
        (|a: Attestation| Attestation { creator_prior: 5, creator_dead: 3, ..a }, policy(), LaunchProofError::TooManyDeadLaunches),
        (
            |a: Attestation| Attestation { flags: flags::MINT_AUTHORITY_ACTIVE, ..a },
            PolicyArgs { deny_flags: flags::MINT_AUTHORITY_ACTIVE, ..policy() },
            LaunchProofError::DeniedFlag,
        ),
    ];
    for (change, p, code) in cases {
        let mut env = setup();
        let ixs = guarded(&env, change(attestation(&env)), &env.attester, p);
        expect_rejected(&mut env, ixs, Some(code));
    }
}

#[test]
fn rejects_attestation_for_other_mint() {
    let mut env = setup();
    let a = Attestation { mint: Pubkey::new_unique().to_bytes(), ..attestation(&env) };
    let ixs = guarded(&env, a, &env.attester, policy());
    expect_rejected(&mut env, ixs, Some(LaunchProofError::MintMismatch));
}

#[test]
fn rejects_when_no_purchase_is_bound_to_the_mint() {
    let mut env = setup();
    let message = attestation(&env).encode().unwrap();

    let no_buy = vec![ed25519_ix(&env.attester, &message), assert_ix(&env, env.mint, policy())];
    expect_rejected(&mut env, no_buy, Some(LaunchProofError::NoBoundBuyInstruction));

    let other = Pubkey::new_unique();
    let other_mint = vec![ed25519_ix(&env.attester, &message), assert_ix(&env, env.mint, policy()), buy_ix(&env, other)];
    expect_rejected(&mut env, other_mint, Some(LaunchProofError::NoBoundBuyInstruction));
}

#[test]
fn rejects_purchase_through_unlisted_program() {
    let mut env = setup();
    let data = launchproof::instruction::SetBuyPrograms { programs: vec![Pubkey::new_unique()] }.data();
    let ix = admin_ix(&env, &env.admin.pubkey(), data);
    let admin = env.admin.insecure_clone();
    send(&mut env.svm, &[ix], &[&admin]).unwrap();
    let ixs = guarded(&env, attestation(&env), &env.attester, policy());
    expect_rejected(&mut env, ixs, Some(LaunchProofError::NoBoundBuyInstruction));
}

#[test]
fn rejects_everything_when_paused() {
    let mut env = setup();
    let data = launchproof::instruction::SetPaused { paused: true }.data();
    let ix = admin_ix(&env, &env.admin.pubkey(), data);
    let admin = env.admin.insecure_clone();
    send(&mut env.svm, &[ix], &[&admin]).unwrap();
    let ixs = guarded(&env, attestation(&env), &env.attester, policy());
    expect_rejected(&mut env, ixs, Some(LaunchProofError::Paused));
}

#[test]
fn admin_actions_require_admin() {
    let mut env = setup();
    let intruder = Keypair::new();
    env.svm.airdrop(&intruder.pubkey(), BUY_LAMPORTS).unwrap();
    let datas = [
        launchproof::instruction::SetAttester { attester: intruder.pubkey() }.data(),
        launchproof::instruction::SetPaused { paused: true }.data(),
        launchproof::instruction::SetBuyPrograms { programs: vec![] }.data(),
    ];
    for data in datas {
        let ix = admin_ix(&env, &intruder.pubkey(), data);
        let err = send(&mut env.svm, &[ix], &[&intruder]).expect_err("must fail");
        assert!(err.contains(&custom(LaunchProofError::Unauthorized)), "got {err}");
    }
}

#[test]
fn only_upgrade_authority_can_initialize() {
    let mut svm = LiteSVM::new();
    svm.add_program(launchproof::ID, PROGRAM_SO).unwrap();
    let (authority, intruder) = (Keypair::new(), Keypair::new());
    svm.airdrop(&intruder.pubkey(), BUY_LAMPORTS).unwrap();
    set_upgrade_authority(&mut svm, &authority.pubkey());
    let config = Pubkey::find_program_address(&[b"config"], &launchproof::ID).0;
    let init = Instruction {
        program_id: launchproof::ID,
        accounts: launchproof::accounts::InitializeConfig {
            admin: intruder.pubkey(),
            config,
            program_data: program_data_address(),
            system_program: solana_sdk_ids::system_program::ID,
        }
        .to_account_metas(None),
        data: launchproof::instruction::InitializeConfig { network: network::DEVNET, attester: intruder.pubkey() }.data(),
    };
    let err = send(&mut svm, &[init], &[&intruder]).expect_err("must fail");
    assert!(err.contains(&custom(LaunchProofError::Unauthorized)), "got {err}");
}
