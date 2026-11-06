use anchor_lang::prelude::*;
use lp_attest::{DecodeError, Ed25519Error, PolicyError};

#[error_code]
pub enum LaunchProofError {
    #[msg("Signer is not allowed to perform this action")]
    Unauthorized,
    #[msg("Program data account does not match this program")]
    InvalidProgramData,
    #[msg("Unknown network tag")]
    InvalidNetwork,
    #[msg("Too many buy programs")]
    TooManyBuyPrograms,
    #[msg("Buy program list contains a duplicate or the default key")]
    InvalidBuyProgram,
    #[msg("Verification is paused")]
    Paused,
    #[msg("An Ed25519 instruction must directly precede this instruction")]
    MissingEd25519Instruction,
    #[msg("Preceding instruction is not the Ed25519 program")]
    NotEd25519Program,
    #[msg("Ed25519 instruction must verify exactly one signature")]
    Ed25519NotExactlyOneSignature,
    #[msg("Ed25519 data must live inside its own instruction")]
    Ed25519CrossInstructionReference,
    #[msg("Ed25519 message has the wrong length")]
    Ed25519BadMessageLength,
    #[msg("Ed25519 offsets are out of bounds")]
    Ed25519OutOfBounds,
    #[msg("Attestation was not signed by the configured attester")]
    WrongAttester,
    #[msg("Attestation has the wrong length")]
    BadLength,
    #[msg("Attestation prefix is invalid")]
    BadPrefix,
    #[msg("Attestation version is not supported")]
    BadVersion,
    #[msg("Attestation network tag is invalid")]
    BadNetwork,
    #[msg("Attestation basis points are out of range")]
    BpsOutOfRange,
    #[msg("Attestation reports more dead launches than prior launches")]
    DeadExceedsPrior,
    #[msg("Attestation contains unknown flags")]
    UnknownFlags,
    #[msg("Attestation is for a different mint")]
    MintMismatch,
    #[msg("Attestation is for a different network")]
    WrongNetwork,
    #[msg("Attestation is dated in the future")]
    IssuedInFuture,
    #[msg("Attestation is older than the allowed age")]
    Expired,
    #[msg("Supply bought at launch by linked wallets exceeds the limit")]
    LinkedInitialTooHigh,
    #[msg("Supply still held by linked wallets exceeds the limit")]
    LinkedNowTooHigh,
    #[msg("Creator has too many dead launches")]
    TooManyDeadLaunches,
    #[msg("Attestation carries a flag the buyer refuses")]
    DeniedFlag,
    #[msg("No following purchase instruction uses the attested mint")]
    NoBoundBuyInstruction,
}

impl From<DecodeError> for LaunchProofError {
    fn from(e: DecodeError) -> Self {
        match e {
            DecodeError::BadLength => Self::BadLength,
            DecodeError::BadPrefix => Self::BadPrefix,
            DecodeError::BadVersion => Self::BadVersion,
            DecodeError::BadNetwork => Self::BadNetwork,
            DecodeError::BpsOutOfRange => Self::BpsOutOfRange,
            DecodeError::DeadExceedsPrior => Self::DeadExceedsPrior,
            DecodeError::UnknownFlags => Self::UnknownFlags,
        }
    }
}

impl From<PolicyError> for LaunchProofError {
    fn from(e: PolicyError) -> Self {
        match e {
            PolicyError::WrongNetwork => Self::WrongNetwork,
            PolicyError::IssuedInFuture => Self::IssuedInFuture,
            PolicyError::Expired => Self::Expired,
            PolicyError::LinkedInitialTooHigh => Self::LinkedInitialTooHigh,
            PolicyError::LinkedNowTooHigh => Self::LinkedNowTooHigh,
            PolicyError::TooManyDeadLaunches => Self::TooManyDeadLaunches,
            PolicyError::DeniedFlag => Self::DeniedFlag,
        }
    }
}

impl From<Ed25519Error> for LaunchProofError {
    fn from(e: Ed25519Error) -> Self {
        match e {
            Ed25519Error::NotExactlyOneSignature => Self::Ed25519NotExactlyOneSignature,
            Ed25519Error::CrossInstructionReference => Self::Ed25519CrossInstructionReference,
            Ed25519Error::BadMessageLength => Self::Ed25519BadMessageLength,
            Ed25519Error::OutOfBounds => Self::Ed25519OutOfBounds,
        }
    }
}
