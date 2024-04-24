use crate::message::{ParseError, ValidateError};
use ed25519_dalek::{PublicKey, Signature};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SiwsOutput {
    pub account: SolAccount,
    pub signed_message: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SolAccount {
    pub public_key: Vec<u8>,
}

impl SiwsOutput {
    pub fn verify(&self) -> Result<bool, VerifyError> {
        let pubkey = PublicKey::from_bytes(&self.account.public_key)
            .map_err(|_| SiwsOutputError::InvalidPubkey)?;

        let signature = Signature::from_bytes(&self.signature)
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
