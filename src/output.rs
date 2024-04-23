use crate::{
    message::{ParseError, SiwsMessage, SolError, ValidateError},
    pubkey::SolPubkey,
};
use ed25519_dalek::{PublicKey, Signature};
use thiserror::Error;

pub struct SiwsOutput {
    pub account: SolAccount,
    pub signed_message: Vec<u8>,
    pub signature: Vec<u8>,
}

pub struct SolAccount {
    pub public_key: SolPubkey,
}

impl SiwsOutput {
    pub fn verify(&self) -> Result<bool, VerifyError> {
        let message =
            SiwsMessage::try_from(&self.signed_message).map_err(VerifyError::MessageParse)?;

        // Ensure message is valid
        message.validate()?;

        let pubkey = PublicKey::from_bytes(&self.account.public_key.0)
            .map_err(|_| SolError::InvalidPubkey)?;

        let signature =
            Signature::from_bytes(&self.signature).map_err(|_| SolError::InvalidSignature)?;

        // Verify signature
        pubkey
            .verify_strict(&self.signed_message, &signature)
            .map_err(|_| SolError::VerificationFailure)?;

        Ok(true)
    }
}

#[derive(Error, Debug)]
pub enum VerifyError {
    #[error("Message Parse Error: {0}")]
    MessageParse(#[from] ParseError),

    #[error("Invalid Message: {0}")]
    MessageValidate(#[from] ValidateError),

    #[error("Signature Parse Error: {0}")]
    SignatureParse(&'static str),

    #[error("Solana Error: {0}")]
    Solana(#[from] SolError),
}