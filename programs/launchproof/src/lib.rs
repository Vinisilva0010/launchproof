use anchor_lang::prelude::*;

pub mod error;
pub mod instructions;
pub mod state;

pub use instructions::*;
pub use state::*;

declare_id!("BjK5qpT8rzR1XLJKtX1MxmXBVD1NM3T19rFV6Vd1r89W");

#[program]
pub mod launchproof {
    use super::*;

    pub fn initialize_config(ctx: Context<InitializeConfig>, network: u8, attester: Pubkey) -> Result<()> {
        crate::instructions::admin::handle_initialize_config(ctx, network, attester)
    }

    pub fn set_attester(ctx: Context<AdminOnly>, attester: Pubkey) -> Result<()> {
        crate::instructions::admin::handle_set_attester(ctx, attester)
    }

    pub fn set_buy_programs(ctx: Context<AdminOnly>, programs: Vec<Pubkey>) -> Result<()> {
        crate::instructions::admin::handle_set_buy_programs(ctx, programs)
    }

    pub fn set_paused(ctx: Context<AdminOnly>, paused: bool) -> Result<()> {
        crate::instructions::admin::handle_set_paused(ctx, paused)
    }

    pub fn assert_launch_policy(ctx: Context<AssertLaunchPolicy>, policy: PolicyArgs) -> Result<()> {
        crate::instructions::assert_policy::handle_assert_launch_policy(ctx, policy)
    }
}
