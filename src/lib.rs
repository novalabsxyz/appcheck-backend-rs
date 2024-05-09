use jwt_simple::{
    claims::{JWTClaims, NoCustomClaims},
    common::VerificationOptions,
};

pub mod jwk_cache;
pub mod middleware;
mod settings;
pub mod token_verifier;

pub use jwk_cache::JwkCache;
pub use settings::Settings;
pub use token_verifier::TokenVerifier;

pub trait AppCheck {
    /// Validate the signature of the token and that it is unexpired (within expiry tolerance)
    fn verify_token(
        &self,
        key_id: &str,
        token: &str,
        options: VerificationOptions,
    ) -> Result<JWTClaims<NoCustomClaims>, Error>;

    /// Provide verification options to override default token_verify checks;
    /// see `jwt_simplwe::common::VerificationOptions` for full details.
    /// Explicitly expects the `allowed_issuers` and `allowed_audiences`
    fn verify_opts(&self) -> VerificationOptions;

    /// Optionally verify the token subject is among the list of firebase app IDs returned
    fn verify_app_ids(&self) -> Option<&Vec<String>>;
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("token failed validation {0}")]
    InvalidToken(#[from] jwt_simple::Error),
    #[error("failed to fetch jwks {0}")]
    JwkRefresh(#[from] reqwest::Error),
    #[error("no compatible keys in set {0}")]
    JwkSetEmpty(String),
    #[error("token kid does not match known key {0}")]
    UnknownJwk(String),
}
