use anchor_lang::prelude::*;

pub const CONFIG_SEED: &[u8] = b"config";
pub const MAX_BUY_PROGRAMS: usize = 8;

#[account]
#[derive(InitSpace)]
pub struct Config {
    pub admin: Pubkey,
    /// Public key whose Ed25519 signature makes an attestation valid.
    pub attester: Pubkey,
    /// Network tag that attestations must carry (lp_attest::network).
    pub network: u8,
    /// When paused every guarded purchase fails; nothing passes unchecked.
    pub paused: bool,
    pub buy_programs_len: u8,
    /// Programs whose instructions count as a purchase bound to the mint.
    pub buy_programs: [Pubkey; 8],
    pub bump: u8,
}

impl Config {
    pub fn active_buy_programs(&self) -> &[Pubkey] {
        &self.buy_programs[..usize::from(self.buy_programs_len)]
    }
}
