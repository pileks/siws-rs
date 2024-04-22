use ed25519_dalek::{PublicKey, Signature};
use message::{SiwsMessage, SolError};
use pubkey::SolPubkey;
use thiserror::Error;

pub mod message;
pub mod pubkey;
pub mod signature;
pub mod timestamp;

pub struct SolAccount {
    pub public_key: SolPubkey,
}

pub struct SiwsOutput {
    pub account: SolAccount,
    pub signed_message: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Error, Debug)]
pub enum VerifyError {
    #[error("Message Parse Error: {0}")]
    MessageParse(#[from] message::ParseError),

    #[error("Invalid Message: {0}")]
    MessageValidate(#[from] message::ValidateError),

    #[error("Signature Parse Error: {0}")]
    SignatureParse(&'static str),

    #[error("Solana Error: {0}")]
    Solana(#[from] message::SolError),
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

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::{message::*, timestamp::TimeStamp, SiwsOutput, SolAccount};
    use ed25519_dalek::{ed25519::signature::SignerMut, Keypair};
    use rand::rngs::OsRng;
    use time::OffsetDateTime;

    #[test]
    fn it_works() {
        let mut csprng = OsRng {};
        let mut keypair: Keypair = Keypair::generate(&mut csprng);

        let address = bs58::encode(keypair.public.to_bytes()).into_string();

        let siws_message = SiwsMessage {
            address: String::from(&address),
            domain: String::from("localhost"),
            statement: Some(String::from("Give me all your money!")),
            ..SiwsMessage::default()
        };

        let siws_message_as_string = String::from(&siws_message);
        let message_bytes = siws_message_as_string.as_bytes();

        // println!("{}", siws_message_as_string);
        let signature_bytes = keypair.sign(message_bytes).to_bytes();

        // println!("{}", siws_message.signature);

        let output = SiwsOutput {
            account: SolAccount {
                public_key: crate::pubkey::SolPubkey::from(keypair.public.to_bytes()),
            },
            signature: Vec::from(signature_bytes),
            signed_message: Vec::from(message_bytes)
        };

        let result = output.verify();

        match result {
            Ok(v) => assert!(v),
            Err(_) => panic!("Result"),
        }
    }

    #[test]
    fn works_2() {
        let msg = SiwsMessage {
            domain: String::from("localhost:1337"),
            address: "testaddr".into(),
            statement: Some("test_statement".into()),
            uri: Some("test_uri".into()),
            version: Some("test_version".into()),
            chain_id: Some("mainnet".into()),
            nonce: Some("test_nonce".into()),
            issued_at: Some(TimeStamp::from(OffsetDateTime::now_utc())),
            expiration_time: Some(TimeStamp::from(OffsetDateTime::now_utc())),
            not_before: Some(TimeStamp::from(OffsetDateTime::now_utc())),
            request_id: Some("test_rid".into()),
            resources: vec!["test1".into(), "test2".into()],
        };

        let msg_string = String::from(&msg);
        println!("{}", msg_string);

        let msg2 = match SiwsMessage::from_str(&msg_string) {
            Ok(v) => v,
            Err(_) => todo!(),
        };

        assert_eq!(msg.domain, msg2.domain);
        assert_eq!(msg.address, msg2.address);
        assert_eq!(msg.statement, msg2.statement);
        assert_eq!(msg.uri, msg2.uri);
        assert_eq!(msg.chain_id, msg2.chain_id);
        assert_eq!(msg.issued_at, msg2.issued_at);
        assert_eq!(msg.expiration_time, msg2.expiration_time);
        assert_eq!(msg.not_before, msg2.not_before);
        assert_eq!(msg.request_id, msg2.request_id);
        assert_eq!(msg.resources, msg2.resources);
    }
}
