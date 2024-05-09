use super::TokenVerifier;
use axum::{
    extract::Request,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use futures_util::future::BoxFuture;
use jwt_simple::{
    claims::{JWTClaims, NoCustomClaims},
    token::Token,
};
use std::task::{Context, Poll};
use tower::{Layer, Service};

const APP_CHECK_HEADER: &str = "X-Firebase-AppCheck";

#[derive(Clone)]
struct AppCheckLayer {
    verifier: TokenVerifier,
}

impl<S> Layer<S> for AppCheckLayer {
    type Service = AppCheckService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AppCheckService {
            inner,
            verifier: self.verifier.clone(),
        }
    }
}

#[derive(Clone)]
struct AppCheckService<S> {
    inner: S,
    verifier: TokenVerifier,
}

impl<S> Service<Request> for AppCheckService<S>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, ctx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(ctx)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let verifier = self.verifier.clone();
        let not_ready_inner = self.inner.clone();
        let mut ready_inner = std::mem::replace(&mut self.inner, not_ready_inner);

        Box::pin(async move {
            match token_auth(verifier, &req) {
                Ok(_) => ready_inner.call(req).await,
                Err(err) => Ok(err.into_response()),
            }
        })
    }
}

fn token_auth(
    verifier: TokenVerifier,
    req: &Request,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let token = req
        .headers()
        .get(APP_CHECK_HEADER)
        .and_then(|header| header.to_str().ok())
        .ok_or_else(error_response)?;

    let metadata = Token::decode_metadata(token).map_err(|_| error_response())?;

    // Checks token header `alg` and `typ` fields match the expected values
    if metadata.algorithm() != "RS256" || metadata.signature_type() != Some("JWT") {
        return Err(error_response());
    }

    let Some(key_id) = metadata.key_id() else {
        return Err(error_response());
    };

    // Validates the token signature and that the expiry (+tolerance) is within the limit
    // automatically. Also incorporates validation of issuer, audiences (includes firebase project
    // number) and optional app ID subjects if configured in VerificationOpts
    let claims: JWTClaims<NoCustomClaims> = verifier
        .verify_token(key_id, token, verifier.verify_opts())
        .map_err(|_| error_response())?;

    // If the App Check implementation is configured with a Firebase app allow-list, verify the token
    // subject is among the allowed app IDs
    if let Some(app_ids) = verifier.verify_app_ids() {
        if !claims
            .subject
            .is_some_and(|subject| app_ids.contains(&subject))
        {
            return Err(error_response());
        }
    }

    Ok(())
}

fn error_response() -> (StatusCode, Json<serde_json::Value>) {
    let err_resp = serde_json::json!({
        "status": "fail",
        "message": "request not authenticated",
    });
    (StatusCode::UNAUTHORIZED, Json(err_resp))
}
