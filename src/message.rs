use ed25519_dalek::{PublicKey, Signature};
use std::{fmt, str::FromStr};
use thiserror::Error;

use crate::{pubkey::*, signature::*};

const PREAMBLE: &str = " wants you to sign in with your Solana account:";
const URI_TAG: &str = "URI: ";
const VERSION_TAG: &str = "Version: ";
const CHAIN_TAG: &str = "Chain ID: ";
const NONCE_TAG: &str = "Nonce: ";
const IAT_TAG: &str = "Issued At: ";
const EXP_TAG: &str = "Expiration Time: ";
const NBF_TAG: &str = "Not Before: ";
const RID_TAG: &str = "Request ID: ";
const RES_TAG: &str = "Resources:";

#[derive(Default)]
pub struct SiwsMessage {
    // RFC 4501 dnsauthority that is requesting the signing.
    pub domain: String,

    // Blockchain address, as defined by CAIP-10, performing the signing; should include CAIP-2 chain id namespace
    pub address: String,

    // RFC 3986 URI referring to the resource that is the subject of the signing i.e. the subject of the claim.
    pub uri: Option<String>,

    // Current version of the message. Can only be "1"
    pub version: Option<String>,

    // Human-readable ASCII assertion that the user will sign. It MUST NOT contain \n.
    pub statement: Option<String>,

    // Randomized token to prevent signature replay attacks.
    pub nonce: Option<String>,

    // The chain ID. Can be "mainnet", "testnet", "devnet", "localnet", and "solana"mainnet
    pub chain_id: Option<String>,

    // RFC 3339 date-time that indicates the issuance time.
    pub issued_at: Option<String>,

    // RFC 3339 date-time that indicates when the signed authentication message is no longer valid.
    pub expiration_time: Option<String>,

    // RFC 3339 date-time that indicates when the signed authentication message starts being valid.
    pub not_before: Option<String>,

    // System-specific identifier used to uniquely refer to the authentication request.
    pub request_id: Option<String>,

    // List of information or references to information the user wishes to have resolved as part of the authentication by the relying party; express as RFC 3986 URIs and separated by \n.
    pub resources: Option<Vec<String>>,
}

impl SiwsMessage {
    pub fn verify(&self, signature: &str) -> Result<bool, SolError> {
        let message_string: String = self.into();

        let signature =
            SolSignature::from_str(signature).map_err(|_| SolError::InvalidSignature)?;

        let pub_key = SolPubkey::from_str(&self.address).map_err(|_| SolError::InvalidPubkey)?;

        verify_sol_signature(&message_string, &signature, &pub_key)
    }
}

fn fmt_advanced_field(name: &'static str, value: &Option<String>) -> String {
    match value {
        Some(v) => format!("\n{name}: {v}"),
        None => String::new(),
    }
}

fn fmt_advanced_field_list(name: &'static str, value: &Option<Vec<String>>) -> String {
    match value {
        Some(v) => {
            let field_name: String = format!("\n{name}:");

            let list_values = v
                .iter()
                .map(|x| format!("\n-{x}"))
                .collect::<Vec<String>>()
                .join("");

            format!("{field_name}{list_values}")
        }
        None => String::new(),
    }
}

impl From<&SiwsMessage> for String {
    fn from(value: &SiwsMessage) -> Self {
        let message_required: String = format!(
            "{domain}{preamble}\n\
            {address}",
            domain = value.domain,
            address = value.address,
            preamble = PREAMBLE
        );

        let message_statement: String = match &value.statement {
            Some(s) => format!("\n\n{s}"),
            None => String::new(),
        };

        let uri = fmt_advanced_field(URI_TAG, &value.uri);
        let version = fmt_advanced_field(VERSION_TAG, &value.version);
        let chain_id = fmt_advanced_field(CHAIN_TAG, &value.chain_id);
        let nonce = fmt_advanced_field(NONCE_TAG, &value.nonce);
        let issued_at = fmt_advanced_field(IAT_TAG, &value.issued_at);
        let expiration_time = fmt_advanced_field(EXP_TAG, &value.expiration_time);
        let not_before = fmt_advanced_field(NBF_TAG, &value.not_before);
        let request_id = fmt_advanced_field(RID_TAG, &value.request_id);
        let resources = fmt_advanced_field_list(RES_TAG, &value.resources);

        let advanced_fields: String = format!(
            "\
            {uri}\
            {version}\
            {chain_id}\
            {nonce}\
            {issued_at}\
            {expiration_time}\
            {not_before}\
            {request_id}\
            {resources}\
            "
        );

        let advanced_fields: String = if !advanced_fields.is_empty() {
            // Prefix advanced_fields with newline if any exist
            format!("\n{advanced_fields}")
        } else {
            String::new()
        };

        format!(
            "\
            {message_required}\
            {message_statement}\
            {advanced_fields}\
            "
        )
    }
}

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("Formatting Error: {0}")]
    Format(&'static str),
}

impl TryFrom<&Vec<u8>> for SiwsMessage {
    type Error = ParseError;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        let message_string: String = std::str::from_utf8(value)
            .expect("Message should be valid UTF-8 byte array!")
            .into();

        SiwsMessage::from_str(&message_string)
    }
}

impl FromStr for SiwsMessage {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut lines = s.split('\n');

        // Get domain - no further checks on domain yet
        let domain = lines
            .next()
            .and_then(|preamble| preamble.strip_suffix(PREAMBLE))
            .map(|s| s.to_string())
            .ok_or(ParseError::Format("Missing Preamble Line"))?;

        let address = lines
            .next()
            .map(|s| s.to_string())
            .ok_or(ParseError::Format("Missing Address Line"))?;

        // Skip the new line:
        lines.next();

        Ok(SiwsMessage {
            domain,
            address,
            ..Self::default()
        })
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

fn verify_sol_signature(
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
