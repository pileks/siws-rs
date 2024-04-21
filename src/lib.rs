use pubkey::SolPubkey;

pub mod message;
pub mod pubkey;
pub mod signature;

pub struct SolAccount {
    pub public_key: SolPubkey,
}

pub struct SiwsOutput {
    pub account: SolAccount,
    pub signed_message: Vec<u8>,
    pub signature: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::message::*;
    use ed25519_dalek::{ed25519::signature::SignerMut, Keypair};
    use rand::rngs::OsRng;

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

        let siws_message_as_string: String = String::from(&siws_message);
        let bytes = &siws_message_as_string.as_bytes();

        // println!("{}", siws_message_as_string);

        let signature = bs58::encode(keypair.sign(bytes).to_bytes()).into_string();

        // println!("{}", siws_message.signature);

        let result = siws_message.verify(&signature).unwrap_or(false);

        assert!(result);
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
            issued_at: Some("test_iat".into()),
            expiration_time: Some("test_exp".into()),
            not_before: Some("test_nbf".into()),
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
    }
}
