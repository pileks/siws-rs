# siws-rs - Sign in With Solana Rust Library

A simple Rust implementation of [CAIP-122](https://github.com/ChainAgnostic/CAIPs/blob/main/CAIPs/caip-122.md) (Sign in With X) for Solana, following the [Solana Wallet Standard](https://github.com/anza-xyz/wallet-standard?tab=readme-ov-file) and [Phantom Wallet's Sign In With Solana](https://github.com/phantom/sign-in-with-solana) protocol.

## Installation

Inside `Cargo.toml`, include the `siws` crate as a dependency:

```toml
[dependencies]
# ...other dependencies
siws = "0.1.0"
# ...other dependencies
```

## Usage

`siws-rs` exposes two main structs - `SiwsMessage` for message validation, and `SiwsOutput` for sign-in verification.

`SiwsMessage` is analogous to Solana Wallet Standard's `SolanaSignInInput`, while `SiwsOutput` is analogous to `SolanaSignInOutput`.

Using these, you can verify the sign in request, and validate the sign-in message.

### Verify sign-in with SIWS Output



### Validate SIWS Message from SIWS Output

## Contributing

This project aims to provide basic functionality of Sign in With Solana to Rust developers. As such, it's intended to be kept small and manageable.

Contributing to this repository is highly encouraged. 

If you find any bugs, please try cloning the repository and fixing them yourself, then opening a PR with your proposed fixes.

The project is also open to new features, however feature requests should be discussed through issues beforehand to align with the minimalist nature of the project.

## Security

This library has not undergone security audits.

If you or anyone you know wants to audit `siws-rs`, please contact the authors directly.
