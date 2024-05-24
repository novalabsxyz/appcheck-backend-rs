use super::{print_json, Error};
use jwt_simple::{
    algorithms::{Ed25519KeyPair, EdDSAKeyPairLike},
    claims::{Claims, JWTClaims},
    prelude::Duration,
};
use serde::{Deserialize, Serialize};
use std::{fs::read, path::PathBuf};

#[derive(Clone, Debug, clap::Args)]
pub struct TokenArgs {
    /// Path to the keypair to sign the token
    #[arg(long, short)]
    keypair: PathBuf,
    /// Optional lifetime for the token in minutes
    #[arg(long, short)]
    expiration: Option<u64>,
    /// Client identifier encoded in a custom claim
    #[arg(long, short)]
    client: String,
    /// Identifies client as one from the internal network
    #[arg(long, short = 'n')]
    internal: Option<bool>,
    /// Optional issuer identifier
    #[arg(long, short)]
    iss: Option<String>,
    /// Optional audience identifier
    #[arg(long, short)]
    aud: Option<String>,
    /// Optional subject identifier
    #[arg(long, short)]
    sub: Option<String>,
}

impl TokenArgs {
    pub fn run(&self) -> Result<(), Error> {
        let keypair = read(&self.keypair)
            .map_err(|err| err.into())
            .and_then(|bytes| Ed25519KeyPair::from_bytes(&bytes))?;

        let claims = gen_token(
            self.internal,
            &self.client,
            self.expiration,
            self.aud.as_ref(),
            self.iss.as_ref(),
            self.sub.as_ref(),
        );

        let token = keypair.sign(claims)?;

        print_json(&serde_json::json!({
            "token": token,
            "claims": {
                "expires": self.expiration,
                "client": &self.client,
                "internal": self.internal,
                "iss": &self.iss,
                "aud": &self.aud,
                "sub": &self.sub,
            }
        }))?;

        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Bearer {
    internal: bool,
    client: String,
}

impl Bearer {
    fn new(internal: Option<bool>, client: &str) -> Self {
        Self {
            internal: internal.unwrap_or_default(),
            client: client.to_owned(),
        }
    }

    pub fn internal(&self) -> bool {
        self.internal
    }

    pub fn client(&self) -> &str {
        &self.client
    }
}

fn gen_token(
    internal: Option<bool>,
    client: &str,
    expiration: Option<u64>,
    audience: Option<&String>,
    issuer: Option<&String>,
    subject: Option<&String>,
) -> JWTClaims<Bearer> {
    let now = coarsetime::Clock::now_since_epoch();
    let duration = expiration.map(|lifetime| now + Duration::from_mins(lifetime));
    let custom_claims = Bearer::new(internal, client);
    let claims = Claims::with_custom_claims(custom_claims, now);

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

    let claims = if let Some(sub) = subject {
        claims.with_subject(sub)
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
