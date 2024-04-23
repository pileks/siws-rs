use std::str::FromStr;
use thiserror::Error;

pub struct SolPubkey(pub [u8; 32]);

impl std::str::FromStr for SolPubkey {
    type Err = ParsePubkeyError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let pub_key_vec = bs58::decode(s)
            .into_vec()
            .map_err(|_| ParsePubkeyError::Invalid)?;

        SolPubkey::try_from(pub_key_vec.as_slice()).map_err(|_| ParsePubkeyError::Invalid)
    }
}

impl From<[u8; 32]> for SolPubkey {
    #[inline]
    fn from(from: [u8; 32]) -> Self {
        Self(from)
    }
}

impl TryFrom<&[u8]> for SolPubkey {
    type Error = std::array::TryFromSliceError;

    #[inline]
    fn try_from(pubkey: &[u8]) -> Result<Self, Self::Error> {
        <[u8; 32]>::try_from(pubkey).map(Self::from)
    }
}

impl TryFrom<Vec<u8>> for SolPubkey {
    type Error = Vec<u8>;

    #[inline]
    fn try_from(pubkey: Vec<u8>) -> Result<Self, Self::Error> {
        <[u8; 32]>::try_from(pubkey).map(Self::from)
    }
}

impl TryFrom<&str> for SolPubkey {
    type Error = ParsePubkeyError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        SolPubkey::from_str(s)
    }
}

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ParsePubkeyError {
    #[error("String is the wrong size")]
    WrongSize,
    #[error("Invalid Base58 string")]
    Invalid,
}
