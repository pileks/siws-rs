# SIWS - Sign in With Solana Rust Library

A simple Rust implementation of [CAIP-122](https://github.com/ChainAgnostic/CAIPs/blob/main/CAIPs/caip-122.md) (Sign in With X) for Solana, following the [Solana Wallet Standard](https://github.com/anza-xyz/wallet-standard?tab=readme-ov-file) and [Phantom Wallet's Sign In With Solana](https://github.com/phantom/sign-in-with-solana) protocol.

## Installation

SIWS can be easily installed by including the `siws` crate as a dependency inside your project's `Cargo.toml`:

```toml
[dependencies]
# ...other dependencies
siws = "0.0.1"
# ...other dependencies
```

## Usage

SIWS exposes two main structs - `SiwsMessage` for message validation, and `SiwsOutput` for sign-in verification.

`SiwsMessage` is analogous to Solana Wallet Standard's `SolanaSignInInput`, while `SiwsOutput` is analogous to `SolanaSignInOutput`.

Using these, you can verify the sign in request, and validate the sign-in message. 

You will mainly want to use the `SiwsOutput` struct, as its primary purpose is to provide you with simple methods to verify its signature.

However, if you wish to validate the SIWS Message (which you should), you can extract it from `SiwsOutput`'s `signed_message` field using `SiwsMessage::try_from`.

### An End-to-end example

The below example code shows a complete Rust program using `actix-web`, `time`, and `siws` to receive a JSON object containing the SIWS Output, creating a SIWS message from it, verifying the signature and validating the message.

`Cargo.toml`:
```toml filename="Cargo.toml"
[package]
name = "siws-server-example"
version = "0.1.0"
edition = "2021"

[dependencies]
actix-web = "4.5.1"
siws = { path = "../../siws-rs" }
time = "0.3.36"
```

`src/main.rs`
```rust filename="src/main.rs"
use actix_web::{error, web, App, HttpServer, Result};
use siws::message::{SiwsMessage, ValidateOptions};
use siws::output::SiwsOutput;
use time::OffsetDateTime;

async fn validate_and_verify(output: web::Json<SiwsOutput>) -> Result<String> {
    // Read the message from output.signed_message
    let message = SiwsMessage::try_from(&output.signed_message).map_err(error::ErrorBadRequest)?;

    // Validate the message
    message
        .validate(ValidateOptions {
            domain: Some("www.exmaple.com".into()), // Ensure domain is www.example.com
            nonce: Some("1337nonce".into()), // Ensure nonce is 1337nonce
            time: Some(OffsetDateTime::now_utc()) // Validate IAT, EXP, and NBF according to current time
        })
        .map_err(error::ErrorBadRequest)?;

    output.verify().map_err(error::ErrorBadRequest)?;

    Ok(String::from("Successfully verified!"))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| App::new().route("/", web::post().to(validate_and_verify)))
        .bind(("127.0.0.1", 8080))?
        .run()
        .await
}

```

`SIWS Output` derives `serde`'s `Serialize` and `Deserialize` traits, and also automatically renames all of its fields as `camelCase` for simpler Solana Wallet support.

### Verify sign-in with SIWS Output

Whenever you have a SIWS Output, all you need to do is call its `verify` method to verify its signature. You can construct a SIWS Output by parsing a JSON string.

See `tests/integration_tests.rs` for details.

```rust
fn verify_from_json_message() -> Result<(), VerifyError> {
    let json = include_str!("test_message.json");

    let output: SiwsOutput = serde_json::from_str(json).unwrap();

    output.verify()?; // Result<(), VerifyError>

    Ok(())
}
```

### Validate SIWS Message from SIWS Output

From the previous example, if you wanted to also validate the SIWS Message against a certain domain, nonce, or time, you can do the following:

```rust
let message = SiwsMessage::try_from(&output.signed_message).map_err(error::ErrorBadRequest)?;

message.validate(ValidateOptions {
  ...
})?; // Result<(), ValidateError>

```

### SIWS Message

The `SiwsMessage` struct is used to serialize/deserialize the SIWS Message from/to its ABNF form.
Additional methods are implemented to support parsing it from a `&Vec<u8>` and `&[u8]`, as Solana Wallet-signed messages usually come as UTF-8 byte arrays.

#### Parse SIWS message from string

You can parse a SIWS message from any string that adheres to its [specified ABNF](https://github.com/phantom/sign-in-with-solana?tab=readme-ov-file#abnf-message-format):

```rust
fn example_from_str() -> Result<(), ParseError> {
    let msg = SiwsMessage::from_str(
        "\
        www.example.com wants you to sign in with your Solana account:\n\
        BSmWDgE9ex6dZYbiTsJGcwMEgFp8q4aWh92hdErQPeVW\n\
        \n\
        This is some test statement\n\
        \n\
        URI: test_uri\n\
        Version: 1\n\
        Chain ID: mainnet\n\
        Nonce: abcdefgh\n\
        Issued At: 2024-04-24T17:19:02.991469647Z\n\
        Expiration Time: 2024-04-24T23:19:02.991482123Z\n\
        Not Before: 2024-04-24T18:19:02.99148447Z\n\
        Request ID: test_rid\n\
        Resources:\n\
        - https://www.example.com/test_one\n\
        - https://www.example.com/test_two\
        ",
    )?;

    // Do something with the message

    Ok(())
}
```

#### Serialize the SIWS message according to its ABNF

You can get the ABNF-compliant string for your SIWS Message by using `String::from`:

```rust
let siws_message = SiwsMessage {
    domain: "www.exmaple.com".into(),
    address: "someaddress".into(),
    ..Default::default()
};

let message_string = String::from(&siws_message);

print!("{}", message_string);
```

## Contributing

This project aims to provide basic functionality of Sign in With Solana to Rust developers. As such, it's intended to be kept small and manageable.

Contributing to this repository is highly encouraged. 

If you find any bugs, please try cloning the repository and fixing them yourself, then opening a PR with your proposed fixes.

The project is also open to new features, however feature requests should be discussed through issues beforehand to align with the minimalist nature of the project.

## Security

This library has not undergone security audits.

If you or anyone you know wants to audit `siws-rs`, please contact the authors directly.
