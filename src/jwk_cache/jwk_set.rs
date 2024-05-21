use super::{base64_serde, Error, HashMap, RS256PublicKey};
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
            tracing::info!(key_id = %key.kid, "adding public key to validation cache");
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
    #[serde(with = "base64_serde")]
    n: Vec<u8>,
    #[serde(with = "base64_serde")]
    e: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}
