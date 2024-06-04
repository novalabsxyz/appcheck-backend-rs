use super::{BearerSettings, Error};
use jwt_simple::{
    algorithms::{Ed25519PublicKey, EdDSAPublicKeyLike},
    claims::{JWTClaims, NoCustomClaims},
};
use std::collections::HashSet;

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
            authorized_bearers: HashSet::from_iter(value.allowlist),
        })
    }
}
