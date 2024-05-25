use jwt_simple::{
    algorithms::{Ed25519PublicKey, EdDSAPublicKeyLike},
    claims::{JWTClaims, NoCustomClaims}
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use super::{BearerSettings, Error};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Bearer {
    subject: String,
}

impl Bearer {
    pub fn new(sub: &str) -> Self {
        Self {
            subject: sub.to_owned(),
        }
    }

    pub fn sub(&self) -> &str {
        &self.subject
    }
}

#[derive(Clone)]
pub struct BearerVerifier {
    pubkey: Ed25519PublicKey,
    authorized_bearers: HashSet<String>,
}

impl BearerVerifier {
    pub fn verify(&self, token: &str) -> Result<JWTClaims<NoCustomClaims>, Error> {
        match (
            self.authorized_bearers.contains(token),
            self.pubkey.verify_token::<NoCustomClaims>(token, None),
        ) {
            (true, Ok(claims)) => Ok(claims),
            (false, _) => Err(Error::UnknownBearer),
            (_, Err(err)) => Err(err.into()),
        }
    }
}

impl TryFrom<BearerSettings> for BearerVerifier {
    type Error = Error;

    fn try_from(value: BearerSettings) -> Result<Self, Self::Error> {
        Ok(Self {
            pubkey: bs58::decode(&value.pubkey)
                .into_vec()
                .map_err(|err| err.into())
                .and_then(|bytes| Ed25519PublicKey::from_bytes(&bytes))?,
            authorized_bearers: HashSet::from_iter(value.authorized_bearers),
        })
    }
}
