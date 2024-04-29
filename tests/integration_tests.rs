use std::str::FromStr;

use ed25519_dalek::{ed25519::signature::SignerMut, Keypair};
use iri_string::types::UriString;
use rand::rngs::OsRng;
use siws::{
    message::SiwsMessage,
    output::{SiwsOutput, SolAccount, VerifyError},
    timestamp::TimeStamp,
};
use time::OffsetDateTime;

#[test]
fn verify_from_hardcoded_message() -> Result<(), VerifyError> {
    let mut csprng = OsRng {};
    let mut keypair: Keypair = Keypair::generate(&mut csprng);

    let address = bs58::encode(keypair.public.to_bytes()).into_string();

    let siws_message = SiwsMessage {
        domain: String::from("www.example.com"),
        address,
        statement: Some("test_statement".into()),
        uri: Some("test_uri".into()),
        version: Some("test_version".into()),
        chain_id: Some("mainnet".into()),
        nonce: Some("test_nonce".into()),
        issued_at: Some(TimeStamp::from(OffsetDateTime::now_utc())),
        expiration_time: Some(TimeStamp::from(OffsetDateTime::now_utc())),
        not_before: Some(TimeStamp::from(OffsetDateTime::now_utc())),
        request_id: Some("test_rid".into()),
        resources: vec![
            UriString::from_str("https://www.example1.com").map_err(|_| VerifyError::Infallible)?,
            UriString::from_str("https://www.example2.com").map_err(|_| VerifyError::Infallible)?,
        ],
    };

    let siws_message_as_string = String::from(&siws_message);
    let message_bytes = siws_message_as_string.as_bytes();

    let signature_bytes = keypair.sign(message_bytes).to_bytes();

    let output = SiwsOutput {
        account: SolAccount {
            public_key: Vec::from(keypair.public.to_bytes()),
        },
        signature: Vec::from(signature_bytes),
        signed_message: Vec::from(message_bytes),
    };

    let result = output.verify()?;

    assert!(result);

    Ok(())
}

#[test]
fn verify_from_json_message() -> Result<(), VerifyError> {
    let json = include_str!("test_message.json");

    let output: SiwsOutput = serde_json::from_str(json).unwrap();

    output.verify()?;

    Ok(())
}
