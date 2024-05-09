use super::{AppCheck, Error};
use jwt_simple::{
    algorithms::{RS256PublicKey, RSAPublicKeyLike},
    claims::{JWTClaims, NoCustomClaims},
    common::VerificationOptions,
};
use std::collections::HashMap;
use tokio::sync::watch;

pub struct TokenVerifier {
    jwks: watch::Receiver<HashMap<String, RS256PublicKey>>,
    verify_opts: VerificationOptions,
    app_ids: Option<Vec<String>>,
}

impl TokenVerifier {
    pub fn new(
        jwks: watch::Receiver<HashMap<String, RS256PublicKey>>,
        verify_opts: VerificationOptions,
        app_ids: Option<Vec<String>>,
    ) -> Self {
        Self {
            jwks,
            verify_opts,
            app_ids,
        }
    }
}

impl AppCheck for TokenVerifier {
    fn verify_token(
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

    fn verify_opts(&self) -> VerificationOptions {
        self.verify_opts.clone()
    }

    fn verify_app_ids(&self) -> Option<&Vec<String>> {
        self.app_ids.as_ref()
    }
}
