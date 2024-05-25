use super::{bearer::BearerVerifier, settings::BearerSettings, Error};
use jwt_simple::{
    algorithms::{RS256PublicKey, RSAPublicKeyLike},
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
