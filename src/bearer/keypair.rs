use super::{print_json, Bearer, Error};
use jwt_simple::{
    algorithms::{Ed25519KeyPair, Ed25519PublicKey, EdDSAPublicKeyLike},
    claims::Audiences,
};
use std::{
    fs::{read, File},
    io::Write,
    path::PathBuf,
};

#[derive(Clone, Debug, clap::Args)]
pub struct KeypairArgs {
    /// Path to the keypair to sign the token
    #[arg(long, short)]
    outfile: PathBuf,
}

impl KeypairArgs {
    pub fn run(&self) -> Result<(), Error> {
        let keypair = Ed25519KeyPair::generate();
        let pubkey = bs58::encode(keypair.public_key().to_bytes()).into_string();

        let mut buf = File::create(&self.outfile)?;
        buf.write_all(&keypair.to_bytes())?;

        print_json(&serde_json::json!({
            "outfile": self.outfile,
            "pubkey": pubkey,
        }))?;

        Ok(())
    }
}

#[derive(Clone, Debug, clap::Args)]
pub struct PubkeyArgs {
    /// Path to the keypair for which to retrieve the pubkey
    #[arg(long, short)]
    keypair: PathBuf,
}

impl PubkeyArgs {
    pub fn run(&self) -> Result<(), Error> {
        let keypair = read(&self.keypair)
            .map_err(|err| err.into())
            .and_then(|bytes| Ed25519KeyPair::from_bytes(&bytes))?;

        print_json(&serde_json::json!({
            "pubkey": bs58::encode(keypair.public_key().to_bytes()).into_string(),
        }))?;

        Ok(())
    }
}

#[derive(Clone, Debug, clap::Args)]
pub struct VerifyArgs {
    /// Token to verify
    #[arg(long, short)]
    token: String,
    /// Base58-encoded Ed25519 public key to verify the token signature
    #[arg(long, short)]
    pubkey: String,
}

impl VerifyArgs {
    pub fn run(&self) -> Result<(), Error> {
        let pubkey = bs58::decode(&self.pubkey)
            .into_vec()
            .map_err(|err| err.into())
            .and_then(|bytes| Ed25519PublicKey::from_bytes(&bytes))?;

        if let Ok(claims) = pubkey.verify_token::<Bearer>(&self.token, None) {
            let audiences = claims.audiences.map(|audiences| match audiences {
                Audiences::AsSet(aud_set) => aud_set,
                Audiences::AsString(aud) => std::collections::HashSet::from([aud]),
            });
            print_json(&serde_json::json!({
                "valid": "true",
                "claims": {
                    "iss": claims.issuer,
                    "aud": audiences,
                    "sub": claims.subject,
                }
            }))?;
        }

        Ok(())
    }
}
