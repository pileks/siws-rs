use serde::Serialize;
use std::mem;
use thiserror::Error;

#[derive(Error, Debug, Serialize, Clone, PartialEq, Eq)]
pub enum ParseSolSignatureError {
    #[error("String is the wrong size")]
    WrongSize,
    #[error("Invalid Base58 string")]
    Invalid,
}

pub struct SolSignature(pub(crate) [u8; 64]);

impl TryFrom<Vec<u8>> for SolSignature {
    type Error = ParseSolSignatureError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() != mem::size_of::<SolSignature>() {
            // Ensure the byte array is exactly 64 bytes
            Err(ParseSolSignatureError::WrongSize)
        } else {
            let mut bytes = [0u8; 64];
            bytes.copy_from_slice(&value[0..64]);
            Ok(SolSignature(bytes))
        }
    }
}

impl std::str::FromStr for SolSignature {
    type Err = ParseSolSignatureError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let signature_vec = bs58::decode(s)
            .into_vec()
            .map_err(|_| ParseSolSignatureError::Invalid)?;
        if signature_vec.len() != mem::size_of::<SolSignature>() {
            // Match against the correct size for Solana signatures
            Err(ParseSolSignatureError::WrongSize)
        } else {
            SolSignature::try_from(signature_vec).map_err(|_| ParseSolSignatureError::Invalid)
        }
    }
}