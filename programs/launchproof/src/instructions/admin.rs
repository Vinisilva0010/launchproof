use anchor_lang::prelude::*;
use solana_sdk_ids::bpf_loader_upgradeable;

use crate::error::LaunchProofError;
use crate::state::*;

/// Size of the upgradeable loader ProgramData header (tag + slot + option + authority).
const PROGRAM_DATA_HEADER: usize = 45;
const PROGRAM_DATA_TAG: [u8; 4] = [3, 0, 0, 0];

#[derive(Accounts)]
pub struct InitializeConfig<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,
    #[account(init, payer = admin, space = 8 + Config::INIT_SPACE, seeds = [CONFIG_SEED], bump)]
    pub config: Account<'info, Config>,
    /// CHECK: address, owner and layout are verified in the handler.
    pub program_data: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AdminOnly<'info> {
    pub admin: Signer<'info>,
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump, has_one = admin @ LaunchProofError::Unauthorized)]
    pub config: Account<'info, Config>,
}

/// Only the program's upgrade authority may create the config, so nobody can
/// front-run initialization after deploy.
pub fn handle_initialize_config(ctx: Context<InitializeConfig>, network: u8, attester: Pubkey) -> Result<()> {
    require!(lp_attest::network::is_valid(network), LaunchProofError::InvalidNetwork);

    let program_data = &ctx.accounts.program_data;
    let (expected, _) = Pubkey::find_program_address(&[crate::ID.as_ref()], &bpf_loader_upgradeable::ID);
    require_keys_eq!(program_data.key(), expected, LaunchProofError::InvalidProgramData);
    require_keys_eq!(*program_data.owner, bpf_loader_upgradeable::ID, LaunchProofError::InvalidProgramData);
    {
        let data = program_data.try_borrow_data()?;
        require!(
            data.len() >= PROGRAM_DATA_HEADER && data[0..4] == PROGRAM_DATA_TAG && data[12] == 1,
            LaunchProofError::InvalidProgramData
        );
        require!(data[13..45] == ctx.accounts.admin.key().to_bytes(), LaunchProofError::Unauthorized);
    }

    let config = &mut ctx.accounts.config;
    config.admin = ctx.accounts.admin.key();
    config.attester = attester;
    config.network = network;
    config.paused = false;
    config.buy_programs_len = 0;
    config.buy_programs = [Pubkey::default(); MAX_BUY_PROGRAMS];
    config.bump = ctx.bumps.config;
    Ok(())
}

pub fn handle_set_attester(ctx: Context<AdminOnly>, attester: Pubkey) -> Result<()> {
    ctx.accounts.config.attester = attester;
    Ok(())
}

pub fn handle_set_buy_programs(ctx: Context<AdminOnly>, programs: Vec<Pubkey>) -> Result<()> {
    require!(programs.len() <= MAX_BUY_PROGRAMS, LaunchProofError::TooManyBuyPrograms);
    for (i, program) in programs.iter().enumerate() {
        require!(*program != Pubkey::default(), LaunchProofError::InvalidBuyProgram);
        require!(!programs[..i].contains(program), LaunchProofError::InvalidBuyProgram);
    }
    let config = &mut ctx.accounts.config;
    config.buy_programs = [Pubkey::default(); MAX_BUY_PROGRAMS];
    config.buy_programs[..programs.len()].copy_from_slice(&programs);
    config.buy_programs_len = programs.len() as u8;
    Ok(())
}

pub fn handle_set_paused(ctx: Context<AdminOnly>, paused: bool) -> Result<()> {
    ctx.accounts.config.paused = paused;
    Ok(())
}
