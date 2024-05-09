use jwt_simple::{common::VerificationOptions, prelude::Duration};
use serde::Deserialize;
use std::collections::HashSet;

#[derive(Clone, Debug, Deserialize)]
pub struct Settings {
    /// The URL to retrieve rotating jwks from Firebase
    #[serde(default = "default_jwk_url", with = "http_serde::uri")]
    pub url: http::Uri,
    /// The amount of time to cache fetched keys in hours
    #[serde(default = "default_cache_duration")]
    pub duration: u64,
    /// Firebase project number
    pub project_num: u64,
    /// The list of allowed app IDs to gate authentication
    pub app_ids: Option<Vec<String>>,
    /// Reject tokens created more than max_validity seconds ago
    pub max_validity_secs: Option<u64>,
    /// How much clock drift  in secs to tolerate when verifying token timestamps; default is 15 min
    pub time_tolerance_secs: Option<u64>,
    /// Accept tokens created in the future
    pub accept_future: Option<bool>,
}

fn default_cache_duration() -> u64 {
    6
}

fn default_jwk_url() -> http::Uri {
    http::Uri::from_static("https://firebaseappcheck.googleapis.com/v1/jwks")
}

impl Settings {
    pub fn duration(&self) -> Duration {
        Duration::from_secs(60 * 60 * self.duration)
    }

    pub fn max_validity(&self) -> Option<Duration> {
        self.max_validity_secs.map(Duration::from_secs)
    }

    pub fn time_tolerance(&self) -> Option<Duration> {
        self.time_tolerance_secs.map(Duration::from_secs)
    }
}

impl From<Settings> for VerificationOptions {
    fn from(settings: Settings) -> Self {
        let default = VerificationOptions::default();
        let max_validity = if settings.max_validity().is_some() {
            settings.max_validity()
        } else {
            default.max_validity
        };
        let time_tolerance = if settings.time_tolerance().is_some() {
            settings.time_tolerance()
        } else {
            default.time_tolerance
        };
        VerificationOptions {
            accept_future: settings.accept_future.unwrap_or(default.accept_future),
            max_validity,
            time_tolerance,
            allowed_issuers: Some(HashSet::from([format!(
                "https://firebaseappcheck.googleapis.com/{}",
                settings.project_num
            )])),
            allowed_audiences: Some(HashSet::from([format!(
                "projects/{}",
                settings.project_num
            )])),
            ..default
        }
    }
}
