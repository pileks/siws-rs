use ed25519_dalek::{PublicKey, Signature};
use serde::Serialize;
use std::{fmt, mem, str::FromStr};
use thiserror::Error;

pub struct SiwsMessage {
    // RFC 4501 dnsauthority that is requesting the signing.
    domain: String,

    // Blockchain address, as defined by CAIP-10, performing the signing; should include CAIP-2 chain id namespace
    address: String,

    // RFC 3986 URI referring to the resource that is the subject of the signing i.e. the subject of the claim.
    uri: String,

    // Current version of the message.
    version: String,

    // Signature of the message signed by the wallet.
    signature: String,
    // // Human-readable ASCII assertion that the user will sign. It MUST NOT contain \n.
    // statement: Option<String>,

    // // Randomized token to prevent signature replay attacks.
    // nonce: Option<String>,

    // // RFC 3339 date-time that indicates the issuance time.
    // issued_at: Option<String>,

    // // RFC 3339 date-time that indicates when the signed authentication message is no longer valid.
    // expiration_time: Option<String>,

    // // RFC 3339 date-time that indicates when the signed authentication message starts being valid.
    // not_before: Option<String>,

    // // System-specific identifier used to uniquely refer to the authentication request.
    // request_id: Option<String>,

    // // List of information or references to information the user wishes to have resolved as part of the authentication by the relying party; express as RFC 3986 URIs and separated by \n.
    // resources: Option<String>,
}

impl SiwsMessage {
    pub fn verify(&self) -> Result<bool, SolError> {
        let message_string: String = self.into();
        let signature = match SolSignature::from_str(&self.signature) {
            Err(e) => {
                panic!("{}", e)
            }
            Ok(v) => v,
        };

        let pub_key = SolPubkey::from_str(&self.address).unwrap();

        verify_sol_signature(&message_string, &signature, &pub_key)
    }
}

impl From<&SiwsMessage> for String {
    fn from(value: &SiwsMessage) -> Self {
        format!(
            "{domain} wants you to sign in with your Solana account:\n\
            {address}\n\
            \n\
            \n\
            URI: {uri}\n\
            Version: {version}\n\
            ",
            // {statement}\n
            // Nonce: {nonce}\n
            // Issued At: {issued_at}\n
            // Expiration Time: {expiration_time}\n
            // Not Before: {not_before}\n
            // Request ID: {request_id}\n
            // Resources: {resources}\n
            // statement = value.statement.unwrap_or_default(),
            domain = value.domain,
            address = value.address,
            uri = value.uri,
            version = value.version,
            // nonce = value.nonce.unwrap_or_default(),
            // issued_at = value.issued_at.unwrap_or_default(),
            // expiration_time = value.expiration_time.unwrap_or_default(),
            // not_before = value.not_before.unwrap_or_default(),
            // request_id = value.request_id.unwrap_or_default(),
            // resources = value.resources.unwrap_or_default()
        )
    }
}

pub struct SolPubkey(pub [u8; 32]);

#[derive(Error, Debug, Serialize, Clone, PartialEq, Eq)]
pub enum ParsePubkeyError {
    #[error("String is the wrong size")]
    WrongSize,
    #[error("Invalid Base58 string")]
    Invalid,
}

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

pub enum SolError {
    InvalidPubkey,
    InvalidSignature,
    VerificationFailure,
}

impl fmt::Display for SolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SolError::InvalidPubkey => write!(f, "Invalid public key"),
            SolError::InvalidSignature => write!(f, "Invalid signature"),
            SolError::VerificationFailure => write!(f, "Signature verification failed"),
        }
    }
}

impl From<SolError> for String {
    fn from(error: SolError) -> Self {
        error.to_string()
    }
}

pub fn verify_sol_signature(
    message: &str,
    signature: &SolSignature,
    pubkey: &SolPubkey,
) -> Result<bool, SolError> {
    // Create a PublicKey from the Solana public key
    let pubkey = PublicKey::from_bytes(&pubkey.0).map_err(|_| SolError::InvalidPubkey)?;

    // Create a Signature from the Solana signature
    let signature = Signature::from_bytes(&signature.0).map_err(|_| SolError::InvalidSignature)?;

    // Verify the signature
    pubkey
        .verify_strict(message.as_bytes(), &signature)
        .map(|_| true) // If verification is successful, map to true
        .map_err(|_| SolError::VerificationFailure) // Handle any verification failure
}

#[cfg(test)]
mod tests {
    // use super::*;

    use ed25519_dalek::{ed25519::signature::SignerMut, Keypair, PublicKey};
    use rand::rngs::OsRng;

    use crate::SiwsMessage;

    #[test]
    fn it_works() {
        let mut csprng = OsRng {};
        let mut keypair: Keypair = Keypair::generate(&mut csprng);

        let address = bs58::encode(keypair.public.to_bytes()).into_string();

        let mut siws_message = SiwsMessage {
            address: String::from(&address),
            domain: String::from("localhost"),
            uri: String::from("Hello"),
            version: String::from("1"),
            signature: String::from(""),
        };

        let siws_message_as_string: String = String::from(&siws_message);
        let bytes = &siws_message_as_string.as_bytes();

        println!("{}", siws_message_as_string);

        siws_message.signature = bs58::encode(keypair.sign(bytes).to_bytes()).into_string();

        println!("{}", siws_message.signature);

        let result = match siws_message.verify() {
            Err(_) => {
                println!("Error");
                false
            }
            Ok(v) => {
                println!("OK");
                v
            }
        };

        assert!(result);
    }
}
