use crate::{
    message::{ParseError, SiwsMessage, ValidateError},
    pubkey::SolPubkey,
    signature::SolSignature,
};
use ed25519_dalek::{PublicKey, Signature};
use thiserror::Error;

pub struct SiwsOutput {
    pub account: SolAccount,
    pub signed_message: Vec<u8>,
    pub signature: SolSignature,
}

pub struct SolAccount {
    pub public_key: SolPubkey,
}

impl SiwsOutput {
    pub fn verify(&self) -> Result<bool, VerifyError> {
        let message =
            SiwsMessage::try_from(&self.signed_message).map_err(VerifyError::MessageParse)?;

        // Validate message
        message.validate().map_err(VerifyError::MessageValidate)?;

        let pubkey = PublicKey::from_bytes(&self.account.public_key.0)
            .map_err(|_| SiwsOutputError::InvalidPubkey)?;

        let signature = Signature::from_bytes(&self.signature.0)
            .map_err(|_| SiwsOutputError::InvalidSignature)?;

        // Verify signature
        pubkey
            .verify_strict(&self.signed_message, &signature)
            .map_err(|_| VerifyError::VerificationFailure)?;

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
    SiwsOutput(#[from] SiwsOutputError),

    #[error("Signature verification failed")]
    VerificationFailure,
}

#[derive(Debug, Error)]
pub enum SiwsOutputError {
    #[error("Invalid public key")]
    InvalidPubkey,
    #[error("Invalid signature")]
    InvalidSignature,
}
