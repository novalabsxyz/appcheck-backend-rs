use crate::bearer::Bearer;

use super::{settings::BearerSettings, Error};
use jwt_simple::{
    algorithms::{Ed25519PublicKey, EdDSAPublicKeyLike, RS256PublicKey, RSAPublicKeyLike},
    claims::{JWTClaims, NoCustomClaims},
    common::VerificationOptions,
};
use std::collections::{HashMap, HashSet};
use tokio::sync::watch;

#[derive(Clone)]
pub struct TokenVerifier {
    jwks: watch::Receiver<HashMap<String, RS256PublicKey>>,
    verify_opts: VerificationOptions,
    app_ids: Option<HashSet<String>>,
    pub bearer_verifier: Option<BearerVerifier>,
}

impl TokenVerifier {
    pub fn new(
        jwks: watch::Receiver<HashMap<String, RS256PublicKey>>,
        verify_opts: VerificationOptions,
        app_ids: Option<HashSet<String>>,
        bearer_settings: Option<BearerSettings>,
    ) -> Result<Self, Error> {
        let bearer_verifier: Option<BearerVerifier> = if let Some(settings) = bearer_settings {
            Some(settings.try_into()?)
        } else {
            None
        };

        Ok(Self {
            jwks,
            verify_opts,
            app_ids,
            bearer_verifier,
        })
    }

    pub fn verify_token(
        &self,
        key_id: &str,
        token: &str,
        options: VerificationOptions,
    ) -> Result<JWTClaims<NoCustomClaims>, Error> {
        self.jwks
            .borrow()
            .get(key_id)
            .map(|pubkey| pubkey.verify_token(token, Some(options)))
            .ok_or_else(|| Error::UnknownJwk(key_id.to_string()))?
            .map_err(|err| err.into())
    }

    pub fn verify_opts(&self) -> VerificationOptions {
        self.verify_opts.clone()
    }

    pub fn verify_app_ids(&self) -> Option<&HashSet<String>> {
        self.app_ids.as_ref()
    }
}

#[derive(Clone)]
pub struct BearerVerifier {
    pubkey: Ed25519PublicKey,
    authorized_bearers: HashSet<String>,
}

impl BearerVerifier {
    pub fn verify(&self, token: &str) -> Result<JWTClaims<Bearer>, Error> {
        match (
            self.authorized_bearers.contains(token),
            self.pubkey.verify_token::<Bearer>(token, None),
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
