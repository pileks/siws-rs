use std::str::FromStr;
use thiserror::Error;
use time::OffsetDateTime;

use crate::timestamp::TimeStamp;

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

#[derive(Debug, Error)]
pub enum ValidateError {
    #[error("Domain mismatch.")]
    Domain,

    #[error("Message is expired.")]
    ExpirationTime,

    #[error("issued_at is before current time.")]
    IssuedAt,

    #[error("not_before is before current time.")]
    NotBefore,
}

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
    pub issued_at: Option<TimeStamp>,

    // RFC 3339 date-time that indicates when the signed authentication message is no longer valid.
    pub expiration_time: Option<TimeStamp>,

    // RFC 3339 date-time that indicates when the signed authentication message starts being valid.
    pub not_before: Option<TimeStamp>,

    // System-specific identifier used to uniquely refer to the authentication request.
    pub request_id: Option<String>,

    // List of information or references to information the user wishes to have resolved as part of the authentication by the relying party; express as RFC 3986 URIs and separated by \n.
    pub resources: Vec<String>,
}

#[derive(Default, Debug)]
pub struct ValidateOptions {
    pub time: Option<OffsetDateTime>,
    pub domain: Option<String>,
}

impl SiwsMessage {
    pub fn validate(&self, options: ValidateOptions) -> Result<(), ValidateError> {
        if let Some(domain) = options.domain {
            if self.domain != domain {
                return Err(ValidateError::ExpirationTime);
            }
        }

        // If options.time is Some, check all times against it
        if let Some(check_time) = options.time {
            if let Some(issued_at) = &self.issued_at {
                if issued_at > &check_time {
                    return Err(ValidateError::IssuedAt);
                }
            }

            if let Some(expiration_time) = &self.expiration_time {
                if expiration_time > &check_time {
                    return Err(ValidateError::ExpirationTime);
                }
            }

            if let Some(not_before) = &self.not_before {
                if not_before < &check_time {
                    return Err(ValidateError::NotBefore);
                }
            }
        }

        Ok(())
    }
}

fn fmt_advanced_field<T: std::fmt::Display>(name: &'static str, value: &Option<T>) -> String {
    match value {
        Some(v) => format!("\n{name}{v}"),
        None => String::new(),
    }
}

fn fmt_advanced_field_list(name: &'static str, value: &[String]) -> String {
    if value.is_empty() {
        return String::from("");
    }

    let field_name: String = format!("\n{name}");

    let list_values = value
        .iter()
        .map(|x| format!("\n- {x}"))
        .collect::<Vec<String>>()
        .join("");

    format!("{field_name}{list_values}")
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

impl TryFrom<&[u8]> for SiwsMessage {
    type Error = ParseError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let message_string: String = std::str::from_utf8(value)
            .expect("Message should be valid UTF-8 byte array!")
            .into();

        SiwsMessage::from_str(&message_string)
    }
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

        // Get domain
        let domain = lines
            .next()
            .and_then(|preamble| preamble.strip_suffix(PREAMBLE))
            .map(|s| s.to_string())
            .ok_or(ParseError::Format("Missing Preamble Line"))?;

        // Get address
        let address = lines
            .next()
            .map(|s| s.to_string())
            .ok_or(ParseError::Format("Missing Address Line"))?;

        // Skip the new line
        lines.next();

        // Get statement or none
        let statement = match lines.next() {
            None => None,
            Some("") => None,
            Some(s) => {
                // Consume empty line after statement (if any)
                lines.next();
                Some(s.to_string())
            }
        };

        let mut line = lines.next();

        let uri = match tag_optional(URI_TAG, line)? {
            Some(exp) => {
                line = lines.next();
                Some(String::from(exp))
            }
            None => None,
        };

        let version = match tag_optional(VERSION_TAG, line)? {
            Some(exp) => {
                line = lines.next();
                Some(String::from(exp))
            }
            None => None,
        };

        let chain_id = match tag_optional(CHAIN_TAG, line)? {
            Some(exp) => {
                line = lines.next();
                Some(String::from(exp))
            }
            None => None,
        };

        let nonce = match tag_optional(NONCE_TAG, line)? {
            Some(exp) => {
                line = lines.next();
                Some(String::from(exp))
            }
            None => None,
        };

        let issued_at = match tag_optional(IAT_TAG, line)? {
            Some(exp) => {
                line = lines.next();
                Some(
                    TimeStamp::from_str(exp)
                        .map_err(|_| ParseError::Format("Invalid timestamp"))?,
                )
            }
            None => None,
        };

        let expiration_time = match tag_optional(EXP_TAG, line)? {
            Some(exp) => {
                line = lines.next();
                Some(
                    TimeStamp::from_str(exp)
                        .map_err(|_| ParseError::Format("Invalid timestamp"))?,
                )
            }
            None => None,
        };

        let not_before = match tag_optional(NBF_TAG, line)? {
            Some(exp) => {
                line = lines.next();
                Some(
                    TimeStamp::from_str(exp)
                        .map_err(|_| ParseError::Format("Invalid timestamp"))?,
                )
            }
            None => None,
        };

        let request_id = match tag_optional(RID_TAG, line)? {
            Some(exp) => {
                line = lines.next();
                Some(String::from(exp))
            }
            None => None,
        };

        let resources = match line {
            Some(RES_TAG) => lines
                .map(|s| {
                    s.strip_prefix("- ")
                        .map(String::from)
                        .ok_or(ParseError::Format("Invalid resource line"))
                })
                .collect(),
            Some(_) => Err(ParseError::Format("Unexpected Content")),
            None => Ok(vec![]),
        }?;

        Ok(SiwsMessage {
            domain,
            address,
            statement,
            uri,
            version,
            chain_id,
            nonce,
            issued_at,
            expiration_time,
            not_before,
            request_id,
            resources,
        })
    }
}

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("Formatting Error: {0}")]
    Format(&'static str),
}

fn tag_optional<'a>(
    tag: &'static str,
    line: Option<&'a str>,
) -> Result<Option<&'a str>, ParseError> {
    match tagged(tag, line).map(Some) {
        Err(ParseError::Format(t)) if t == tag => Ok(None),
        r => r,
    }
}

fn tagged<'a>(tag: &'static str, line: Option<&'a str>) -> Result<&'a str, ParseError> {
    line.and_then(|l| l.strip_prefix(tag))
        .ok_or(ParseError::Format(tag))
}
