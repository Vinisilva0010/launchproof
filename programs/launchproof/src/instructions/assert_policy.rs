use anchor_lang::prelude::*;
use lp_attest::{parse_ed25519_instruction, Attestation, Policy};
use solana_instructions_sysvar::{load_current_index_checked, load_instruction_at_checked};
use solana_sdk_ids::{ed25519_program, sysvar::instructions as instructions_sysvar};

use crate::error::LaunchProofError;
use crate::state::*;

/// Upper bound on instructions scanned after this one when looking for the purchase.
const MAX_SCANNED_INSTRUCTIONS: usize = 32;

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug)]
pub struct PolicyArgs {
    pub max_linked_initial_bps: u16,
    pub max_linked_now_bps: u16,
    pub max_creator_dead: u16,
    pub deny_flags: u32,
    pub max_age_secs: u32,
}

#[derive(Accounts)]
pub struct AssertLaunchPolicy<'info> {
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
    /// CHECK: only the address is used; it must equal the attested mint.
    pub mint: UncheckedAccount<'info>,
    /// CHECK: constrained to the instructions sysvar address.
    #[account(address = instructions_sysvar::ID)]
    pub instructions: UncheckedAccount<'info>,
}

#[event]
pub struct LaunchPolicyPassed {
    pub mint: Pubkey,
    pub issued_at: i64,
    pub linked_initial_bps: u16,
    pub linked_now_bps: u16,
}

pub fn handle_assert_launch_policy(ctx: Context<AssertLaunchPolicy>, policy: PolicyArgs) -> Result<()> {
    let config = &ctx.accounts.config;
    require!(!config.paused, LaunchProofError::Paused);

    let ix_sysvar = ctx.accounts.instructions.to_account_info();
    let current = usize::from(load_current_index_checked(&ix_sysvar)?);
    require!(current > 0, LaunchProofError::MissingEd25519Instruction);

    // The signature must be in the instruction right before this one (relative index).
    let ed_ix = load_instruction_at_checked(current - 1, &ix_sysvar)?;
    require_keys_eq!(ed_ix.program_id, ed25519_program::ID, LaunchProofError::NotEd25519Program);

    let payload = parse_ed25519_instruction(&ed_ix.data).map_err(LaunchProofError::from)?;
    require!(payload.pubkey == config.attester.to_bytes(), LaunchProofError::WrongAttester);

    let attestation = Attestation::decode(payload.message).map_err(LaunchProofError::from)?;
    let mint = ctx.accounts.mint.key();
    require!(attestation.mint == mint.to_bytes(), LaunchProofError::MintMismatch);

    let rules = Policy {
        max_linked_initial_bps: policy.max_linked_initial_bps,
        max_linked_now_bps: policy.max_linked_now_bps,
        max_creator_dead: policy.max_creator_dead,
        deny_flags: policy.deny_flags,
        max_age_secs: policy.max_age_secs,
    };
    let now = Clock::get()?.unix_timestamp;
    rules.check(&attestation, now, config.network).map_err(LaunchProofError::from)?;

    require!(
        has_bound_purchase(&ix_sysvar, current, &mint, config.active_buy_programs()),
        LaunchProofError::NoBoundBuyInstruction
    );

    emit!(LaunchPolicyPassed {
        mint,
        issued_at: attestation.issued_at,
        linked_initial_bps: attestation.linked_initial_bps,
        linked_now_bps: attestation.linked_now_bps,
    });
    Ok(())
}

/// True when a later instruction in the same transaction belongs to an accepted
/// buy program and references the attested mint. Prevents attaching a valid
/// attestation for token A to a purchase of token B.
fn has_bound_purchase(ix_sysvar: &AccountInfo, current: usize, mint: &Pubkey, buy_programs: &[Pubkey]) -> bool {
    for index in (current + 1)..(current + 1 + MAX_SCANNED_INSTRUCTIONS) {
        let Ok(ix) = load_instruction_at_checked(index, ix_sysvar) else {
            break;
        };
        if buy_programs.contains(&ix.program_id) && ix.accounts.iter().any(|meta| meta.pubkey == *mint) {
            return true;
        }
    }
    false
}
