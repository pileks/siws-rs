pub mod message;
pub mod output;
pub mod pubkey;
pub mod signature;
pub mod timestamp;

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::{
        message::*,
        output::{SiwsOutput, SolAccount},
        pubkey, signature,
        timestamp::TimeStamp,
    };
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
                public_key: pubkey::SolPubkey::from(keypair.public.to_bytes()),
            },
            signature: signature::SolSignature(signature_bytes),
            signed_message: Vec::from(message_bytes),
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
            domain: String::from("www.example.com"),
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
