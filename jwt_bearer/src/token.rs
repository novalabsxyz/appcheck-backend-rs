use super::{print_json, Error};
use jwt_simple::{
    algorithms::{Ed25519KeyPair, EdDSAKeyPairLike},
    claims::{Claims, JWTClaims, NoCustomClaims},
    prelude::Duration,
};
use std::{fs::read, path::PathBuf};

#[derive(Clone, Debug, clap::Args)]
pub struct TokenArgs {
    /// Path to the keypair to sign the token
    #[arg(long, short)]
    keypair: PathBuf,
    /// Subject identifier; the authorized user or app
    #[arg(long, short)]
    sub: String,
    /// Optional lifetime for the token in minutes
    #[arg(long, short)]
    expiration: Option<u64>,
    /// Optional issuer identifier
    #[arg(long, short)]
    iss: Option<String>,
    /// Optional audience identifier
    #[arg(long, short)]
    aud: Option<String>,
}

impl TokenArgs {
    pub fn run(&self) -> Result<(), Error> {
        let keypair = read(&self.keypair)
            .map_err(|err| err.into())
            .and_then(|bytes| Ed25519KeyPair::from_bytes(&bytes))?;

        let claims = gen_token(
            &self.sub,
            self.expiration,
            self.aud.as_ref(),
            self.iss.as_ref(),
        );

        let token = keypair.sign(claims)?;

        print_json(&serde_json::json!({
            "token": token,
            "claims": {
                "exp": self.expiration,
                "iss": &self.iss,
                "aud": &self.aud,
                "sub": &self.sub,
            }
        }))?;

        Ok(())
    }
}

fn gen_token(
    sub: &str,
    expiration: Option<u64>,
    audience: Option<&String>,
    issuer: Option<&String>,
) -> JWTClaims<NoCustomClaims> {
    let now = coarsetime::Clock::now_since_epoch();
    let duration = expiration.map(|lifetime| now + Duration::from_mins(lifetime));
    let claims = Claims::create(now).with_subject(sub);

    let claims = if let Some(aud) = audience {
        claims.with_audience(aud)
    } else {
        claims
    };

    let claims = if let Some(iss) = issuer {
        claims.with_issuer(iss)
    } else {
        claims
    };

    let full_claims = JWTClaims {
        invalid_before: None,
        ..claims
    };

    JWTClaims {
        // override the duration that was set by `with_custom_claims` because jwt_simple
        // doesn't let us define a non-expiring token via the method
        expires_at: duration,
        ..full_claims
    }
}
