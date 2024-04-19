use message::SiwsMessage;

pub mod message;
pub mod pubkey;
pub mod signature;

pub struct SiwsOutput {
    pub account: String,
    pub signed_message: Vec<u8>,
    pub signature: Vec<u8>,
}

impl From<&SiwsOutput> for SiwsMessage {
    fn from(value: &SiwsOutput) -> Self {
        todo!()
    }
}

#[cfg(test)]
mod tests {
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
            address: "Jure".into(),
            chain_id: Some("mainnet".into()),
            domain: String::from("localhost"),
            resources: None,
            expiration_time: None,
            issued_at: None,
            nonce: Some("Asdf".into()),
            not_before: None,
            request_id: None,
            statement: Some("Test".into()),
            uri: None,
            version: None,
        };

        println!("{}", String::from(&msg));
    }
}
