//! LaunchProof attestation format, risk policy and Ed25519 instruction parsing.
//!
//! Shared by the on-chain program and the off-chain services so both sides
//! encode, decode and evaluate attestations with identical code.
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
use std::vec::Vec;

/// Domain separator: signatures made for any other purpose are rejected.
pub const PREFIX: [u8; 11] = *b"LAUNCHPROOF";
pub const VERSION: u8 = 1;
/// Exact size of an encoded attestation in bytes.
pub const MESSAGE_LEN: usize = 97;
/// 100% in basis points.
pub const MAX_BPS: u16 = 10_000;
/// Tolerated clock difference between the attester and the cluster.
pub const MAX_FUTURE_SKEW_SECS: i64 = 60;

pub mod network {
    pub const MAINNET: u8 = 0;
    pub const DEVNET: u8 = 1;

    pub fn is_valid(value: u8) -> bool {
        value == MAINNET || value == DEVNET
    }
}

pub mod flags {
    pub const MINT_AUTHORITY_ACTIVE: u32 = 1 << 0;
    pub const FREEZE_AUTHORITY_ACTIVE: u32 = 1 << 1;
    pub const ANALYSIS_PARTIAL: u32 = 1 << 2;
    pub const CREATOR_EARLY_FEE_CLAIM: u32 = 1 << 3;
    pub const KNOWN: u32 =
        MINT_AUTHORITY_ACTIVE | FREEZE_AUTHORITY_ACTIVE | ANALYSIS_PARTIAL | CREATOR_EARLY_FEE_CLAIM;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attestation {
    pub network: u8,
    pub mint: [u8; 32],
    /// Share of supply bought at launch by wallets linked to the creator.
    pub linked_initial_bps: u16,
    /// Share of supply those linked wallets still hold.
    pub linked_now_bps: u16,
    /// Earlier launches by the creator and its funding source.
    pub creator_prior: u16,
    /// How many of those earlier launches died.
    pub creator_dead: u16,
    pub flags: u32,
    /// Unix timestamp (seconds) when the attestation was issued.
    pub issued_at: i64,
    /// SHA-256 of the canonical evidence JSON.
    pub evidence_hash: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    BadLength,
    BadPrefix,
    BadVersion,
    BadNetwork,
    BpsOutOfRange,
    DeadExceedsPrior,
    UnknownFlags,
}

fn read<const N: usize>(bytes: &[u8], start: usize) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[start..start + N]);
    out
}

impl Attestation {
    pub fn validate(&self) -> Result<(), DecodeError> {
        if !network::is_valid(self.network) {
            return Err(DecodeError::BadNetwork);
        }
        if self.linked_initial_bps > MAX_BPS || self.linked_now_bps > MAX_BPS {
            return Err(DecodeError::BpsOutOfRange);
        }
        if self.creator_dead > self.creator_prior {
            return Err(DecodeError::DeadExceedsPrior);
        }
        if self.flags & !flags::KNOWN != 0 {
            return Err(DecodeError::UnknownFlags);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<[u8; MESSAGE_LEN], DecodeError> {
        self.validate()?;
        let mut out = [0u8; MESSAGE_LEN];
        out[0..11].copy_from_slice(&PREFIX);
        out[11] = VERSION;
        out[12] = self.network;
        out[13..45].copy_from_slice(&self.mint);
        out[45..47].copy_from_slice(&self.linked_initial_bps.to_le_bytes());
        out[47..49].copy_from_slice(&self.linked_now_bps.to_le_bytes());
        out[49..51].copy_from_slice(&self.creator_prior.to_le_bytes());
        out[51..53].copy_from_slice(&self.creator_dead.to_le_bytes());
        out[53..57].copy_from_slice(&self.flags.to_le_bytes());
        out[57..65].copy_from_slice(&self.issued_at.to_le_bytes());
        out[65..97].copy_from_slice(&self.evidence_hash);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != MESSAGE_LEN {
            return Err(DecodeError::BadLength);
        }
        if bytes[0..11] != PREFIX {
            return Err(DecodeError::BadPrefix);
        }
        if bytes[11] != VERSION {
            return Err(DecodeError::BadVersion);
        }
        let attestation = Self {
            network: bytes[12],
            mint: read(bytes, 13),
            linked_initial_bps: u16::from_le_bytes(read(bytes, 45)),
            linked_now_bps: u16::from_le_bytes(read(bytes, 47)),
            creator_prior: u16::from_le_bytes(read(bytes, 49)),
            creator_dead: u16::from_le_bytes(read(bytes, 51)),
            flags: u32::from_le_bytes(read(bytes, 53)),
            issued_at: i64::from_le_bytes(read(bytes, 57)),
            evidence_hash: read(bytes, 65),
        };
        attestation.validate()?;
        Ok(attestation)
    }
}

/// Limits chosen by the buyer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    pub max_linked_initial_bps: u16,
    pub max_linked_now_bps: u16,
    pub max_creator_dead: u16,
    pub deny_flags: u32,
    pub max_age_secs: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyError {
    WrongNetwork,
    IssuedInFuture,
    Expired,
    LinkedInitialTooHigh,
    LinkedNowTooHigh,
    TooManyDeadLaunches,
    DeniedFlag,
}

impl Policy {
    pub fn check(&self, a: &Attestation, now: i64, expected_network: u8) -> Result<(), PolicyError> {
        if a.network != expected_network {
            return Err(PolicyError::WrongNetwork);
        }
        if a.issued_at > now.saturating_add(MAX_FUTURE_SKEW_SECS) {
            return Err(PolicyError::IssuedInFuture);
        }
        if now.saturating_sub(a.issued_at) > i64::from(self.max_age_secs) {
            return Err(PolicyError::Expired);
        }
        if a.linked_initial_bps > self.max_linked_initial_bps {
            return Err(PolicyError::LinkedInitialTooHigh);
        }
        if a.linked_now_bps > self.max_linked_now_bps {
            return Err(PolicyError::LinkedNowTooHigh);
        }
        if a.creator_dead > self.max_creator_dead {
            return Err(PolicyError::TooManyDeadLaunches);
        }
        if a.flags & self.deny_flags != 0 {
            return Err(PolicyError::DeniedFlag);
        }
        Ok(())
    }
}

// Ed25519 native program instruction layout:
// [num_signatures: u8][padding: u8] then 7 x u16 offsets per signature:
// signature_offset, signature_ix_index, pubkey_offset, pubkey_ix_index,
// message_offset, message_size, message_ix_index.
const OFFSETS_START: usize = 2;
const DATA_START: usize = 16;
/// Instruction index meaning "data lives in this same instruction".
const THIS_INSTRUCTION: u16 = u16::MAX;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ed25519Error {
    NotExactlyOneSignature,
    CrossInstructionReference,
    BadMessageLength,
    OutOfBounds,
}

pub struct Ed25519Payload<'a> {
    pub pubkey: [u8; 32],
    pub message: &'a [u8],
}

fn slice_at(data: &[u8], offset: u16, len: usize) -> Result<&[u8], Ed25519Error> {
    let start = usize::from(offset);
    let end = start.checked_add(len).ok_or(Ed25519Error::OutOfBounds)?;
    data.get(start..end).ok_or(Ed25519Error::OutOfBounds)
}

/// Extracts the verified public key and message from an Ed25519 instruction.
///
/// Accepts only one signature whose signature, key and message all live inside
/// this same instruction, which closes the known offset-redirection attack.
pub fn parse_ed25519_instruction(data: &[u8]) -> Result<Ed25519Payload<'_>, Ed25519Error> {
    if data.len() < DATA_START {
        return Err(Ed25519Error::OutOfBounds);
    }
    if data[0] != 1 {
        return Err(Ed25519Error::NotExactlyOneSignature);
    }
    let field = |i: usize| u16::from_le_bytes([data[OFFSETS_START + i * 2], data[OFFSETS_START + i * 2 + 1]]);
    let (sig_off, sig_ix, pk_off, pk_ix) = (field(0), field(1), field(2), field(3));
    let (msg_off, msg_size, msg_ix) = (field(4), field(5), field(6));
    if sig_ix != THIS_INSTRUCTION || pk_ix != THIS_INSTRUCTION || msg_ix != THIS_INSTRUCTION {
        return Err(Ed25519Error::CrossInstructionReference);
    }
    if usize::from(msg_size) != MESSAGE_LEN {
        return Err(Ed25519Error::BadMessageLength);
    }
    slice_at(data, sig_off, 64)?;
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(slice_at(data, pk_off, 32)?);
    let message = slice_at(data, msg_off, MESSAGE_LEN)?;
    Ok(Ed25519Payload { pubkey, message })
}

/// Builds Ed25519 instruction data with everything inside one instruction.
#[cfg(feature = "std")]
pub fn build_ed25519_instruction_data(pubkey: &[u8; 32], signature: &[u8; 64], message: &[u8]) -> Vec<u8> {
    let pk_off = DATA_START;
    let sig_off = pk_off + 32;
    let msg_off = sig_off + 64;
    let mut data = Vec::with_capacity(msg_off + message.len());
    data.extend_from_slice(&[1, 0]);
    for value in [
        sig_off as u16,
        THIS_INSTRUCTION,
        pk_off as u16,
        THIS_INSTRUCTION,
        msg_off as u16,
        message.len() as u16,
        THIS_INSTRUCTION,
    ] {
        data.extend_from_slice(&value.to_le_bytes());
    }
    data.extend_from_slice(pubkey);
    data.extend_from_slice(signature);
    data.extend_from_slice(message);
    data
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Attestation {
        Attestation {
            network: network::DEVNET,
            mint: [9; 32],
            linked_initial_bps: 1_000,
            linked_now_bps: 500,
            creator_prior: 3,
            creator_dead: 1,
            flags: flags::ANALYSIS_PARTIAL,
            issued_at: 1_790_000_000,
            evidence_hash: [7; 32],
        }
    }

    fn policy() -> Policy {
        Policy { max_linked_initial_bps: 3_000, max_linked_now_bps: 3_000, max_creator_dead: 2, deny_flags: 0, max_age_secs: 600 }
    }

    #[test]
    fn roundtrip() {
        let a = sample();
        assert_eq!(Attestation::decode(&a.encode().unwrap()).unwrap(), a);
    }

    #[test]
    fn decode_rejects_malformed_input() {
        let good = sample().encode().unwrap();
        assert_eq!(Attestation::decode(&good[..96]), Err(DecodeError::BadLength));
        let mut b = good;
        b[0] = b'X';
        assert_eq!(Attestation::decode(&b), Err(DecodeError::BadPrefix));
        let mut b = good;
        b[11] = 2;
        assert_eq!(Attestation::decode(&b), Err(DecodeError::BadVersion));
        let mut b = good;
        b[12] = 9;
        assert_eq!(Attestation::decode(&b), Err(DecodeError::BadNetwork));
        let mut b = good;
        b[45..47].copy_from_slice(&10_001u16.to_le_bytes());
        assert_eq!(Attestation::decode(&b), Err(DecodeError::BpsOutOfRange));
        let mut b = good;
        b[51..53].copy_from_slice(&4u16.to_le_bytes());
        assert_eq!(Attestation::decode(&b), Err(DecodeError::DeadExceedsPrior));
        let mut b = good;
        b[53..57].copy_from_slice(&(1u32 << 31).to_le_bytes());
        assert_eq!(Attestation::decode(&b), Err(DecodeError::UnknownFlags));
    }

    #[test]
    fn policy_checks_every_limit() {
        let now = 1_790_000_100;
        let p = policy();
        assert_eq!(p.check(&sample(), now, network::DEVNET), Ok(()));
        assert_eq!(p.check(&sample(), now, network::MAINNET), Err(PolicyError::WrongNetwork));
        assert_eq!(p.check(&sample(), sample().issued_at - 61, network::DEVNET), Err(PolicyError::IssuedInFuture));
        assert_eq!(p.check(&sample(), sample().issued_at + 601, network::DEVNET), Err(PolicyError::Expired));
        let a = Attestation { linked_initial_bps: 3_001, ..sample() };
        assert_eq!(p.check(&a, now, network::DEVNET), Err(PolicyError::LinkedInitialTooHigh));
        let a = Attestation { linked_now_bps: 3_001, ..sample() };
        assert_eq!(p.check(&a, now, network::DEVNET), Err(PolicyError::LinkedNowTooHigh));
        let a = Attestation { creator_dead: 3, ..sample() };
        assert_eq!(p.check(&a, now, network::DEVNET), Err(PolicyError::TooManyDeadLaunches));
        let p2 = Policy { deny_flags: flags::ANALYSIS_PARTIAL, ..p };
        assert_eq!(p2.check(&sample(), now, network::DEVNET), Err(PolicyError::DeniedFlag));
    }

    #[test]
    fn ed25519_roundtrip_and_attacks() {
        let msg = sample().encode().unwrap();
        let data = build_ed25519_instruction_data(&[5; 32], &[6; 64], &msg);
        let parsed = parse_ed25519_instruction(&data).unwrap();
        assert_eq!(parsed.pubkey, [5; 32]);
        assert_eq!(parsed.message, &msg[..]);

        let mut two = data.clone();
        two[0] = 2;
        assert_eq!(parse_ed25519_instruction(&two).err(), Some(Ed25519Error::NotExactlyOneSignature));

        for field in [1usize, 3, 6] {
            let mut cross = data.clone();
            cross[2 + field * 2..4 + field * 2].copy_from_slice(&0u16.to_le_bytes());
            assert_eq!(parse_ed25519_instruction(&cross).err(), Some(Ed25519Error::CrossInstructionReference));
        }

        let short = build_ed25519_instruction_data(&[5; 32], &[6; 64], &msg[..96]);
        assert_eq!(parse_ed25519_instruction(&short).err(), Some(Ed25519Error::BadMessageLength));

        let mut oob = data.clone();
        oob[10..12].copy_from_slice(&u16::MAX.wrapping_sub(1).to_le_bytes());
        assert_eq!(parse_ed25519_instruction(&oob).err(), Some(Ed25519Error::OutOfBounds));

        assert_eq!(parse_ed25519_instruction(&data[..10]).err(), Some(Ed25519Error::OutOfBounds));
    }
}
