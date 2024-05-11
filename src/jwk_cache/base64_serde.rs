use base64::{engine::general_purpose::URL_SAFE, Engine};
use serde::{Deserialize, Deserializer, Serializer};

pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer).and_then(|string| {
        URL_SAFE
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
    serializer.serialize_str(&URL_SAFE.encode(bytes.as_ref()))
}
