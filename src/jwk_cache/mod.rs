use super::TokenVerifier;
use crate::Error;
use jwt_simple::{algorithms::RS256PublicKey, common::VerificationOptions};
use std::collections::{HashMap, HashSet};
use tokio::{
    sync::watch,
    time::{interval, Duration},
};
use triggered::Listener;

mod base64_serde;
mod jwk_set;

pub struct JwkCache {
    client: reqwest::Client,
    duration: Duration,
    jwks: watch::Sender<HashMap<String, RS256PublicKey>>,
    url: String,
}

impl JwkCache {
    pub async fn new(
        duration: Duration,
        url: String,
        verify_opts: VerificationOptions,
        app_ids: Option<HashSet<String>>,
    ) -> Result<(TokenVerifier, Self), Error> {
        let client = reqwest::Client::new();
        let jwks = jwk_set::fetch_key_set(&client, &url).await?;
        let (sender, receiver) = watch::channel(jwks);
        let cache = Self {
            client,
            duration,
            jwks: sender,
            url,
        };
        let verifier = TokenVerifier::new(receiver, verify_opts, app_ids);
        Ok((verifier, cache))
    }

    pub async fn run(mut self, shutdown: Listener) {
        tracing::info!("starting firebase appcheck jwk cache");

        let mut refresh_timer = interval(self.duration);

        loop {
            tokio::select! {
                biased;
                _ = shutdown.clone() => break,
                _ = refresh_timer.tick() => {
                    if let Err(err) = self.refresh_key_set().await {
                        tracing::error!(?err, "failure to refresh appcheck verifying public keys");
                    }
                }
            }
        }

        tracing::info!("stopping firebase appcheck jwk cache");
    }

    async fn refresh_key_set(&mut self) -> Result<(), Error> {
        let new_jwks = jwk_set::fetch_key_set(&self.client, &self.url).await?;
        self.jwks.send_replace(new_jwks);
        Ok(())
    }
}
