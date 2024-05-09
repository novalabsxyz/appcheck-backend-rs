use super::TokenVerifier;
use crate::Error;
use jwt_simple::{algorithms::RS256PublicKey, common::VerificationOptions};
use std::collections::HashMap;
use tokio::{
    sync::watch,
    time::{interval, Duration},
};
use triggered::Listener;

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
        app_ids: Option<Vec<String>>,
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

mod jwk_set {
    use super::{base64, Error, HashMap, RS256PublicKey};
    use serde::Deserialize;

    const KTY: &str = "RSA";
    const ALG: &str = "RS256";

    pub(super) async fn fetch_key_set(
        client: &reqwest::Client,
        url: &str,
    ) -> Result<HashMap<String, RS256PublicKey>, Error> {
        client
            .get(url)
            .send()
            .await?
            .error_for_status()
            .map_err(|err| {
                tracing::info!(?err, "failed to retrieve firebase jwk set");
                err
            })?
            .json::<JwkSet>()
            .await?
            .keys
            .into_iter()
            .filter(|key| key.alg == ALG && key.kty == KTY)
            .try_fold(HashMap::new(), |mut set, key| {
                let pub_key = RS256PublicKey::from_components(&key.n, &key.e)?;
                set.insert(key.kid, pub_key);
                Ok(set)
            })
    }

    #[derive(Debug, Deserialize)]
    struct Jwk {
        kty: String,
        #[allow(dead_code)]
        r#use: String,
        alg: String,
        kid: String,
        #[serde(with = "base64")]
        n: Vec<u8>,
        #[serde(with = "base64")]
        e: Vec<u8>,
    }

    #[derive(Debug, Deserialize)]
    struct JwkSet {
        keys: Vec<Jwk>,
    }
}

mod base64 {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        String::deserialize(deserializer).and_then(|string| {
            STANDARD
                .decode(string)
                .map_err(|err| Error::custom(err.to_string()))
        })
    }

    #[allow(dead_code)]
    pub fn serialize<S, B>(bytes: B, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        B: AsRef<[u8]>,
    {
        serializer.serialize_str(&STANDARD.encode(bytes.as_ref()))
    }
}
