mod keypair;
mod token;

pub use keypair::{KeypairArgs, PubkeyArgs, VerifyArgs};
pub use token::TokenArgs;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Failed decoding public key {0}")]
    B58(#[from] bs58::decode::Error),
    #[error("Failed reading/writing keypair file {0}")]
    Io(#[from] std::io::Error),
    #[error("Failed constructing keypair {0}")]
    Keypair(#[from] jwt_simple::Error),
    #[error("Failed to serialize token {0}")]
    Serde(#[from] serde_json::Error),
}

pub fn print_json<T: ?Sized + serde::Serialize>(value: &T) -> Result<(), Error> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}
