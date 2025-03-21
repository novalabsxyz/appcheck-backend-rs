pub mod bearer;
pub mod jwk_cache;
pub mod middleware;
mod settings;
pub mod token_verifier;

pub use jwk_cache::JwkCache;
pub use settings::{BearerSettings, Settings};
pub use token_verifier::TokenVerifier;

pub use jwt_simple::claims;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("token failed validation {0}")]
    JwtError(#[from] jwt_simple::Error),
    #[error("unauthorized bearer token")]
    UnknownBearer,
    #[error("failed to fetch jwks {0}")]
    JwkRefresh(#[from] reqwest::Error),
    #[error("no compatible keys in set {0}")]
    JwkSetEmpty(String),
    #[error("token kid does not match known key {0}")]
    UnknownJwk(String),
}
