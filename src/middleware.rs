use super::{Bearer, TokenVerifier};
use axum::{
    extract::Request,
    http::{header, StatusCode},
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
pub struct AppCheckLayer {
    verifier: TokenVerifier,
}

impl AppCheckLayer {
    pub fn new(verifier: TokenVerifier) -> Self {
        Self { verifier }
    }
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
pub struct AppCheckService<S> {
    inner: S,
    verifier: TokenVerifier,
}

impl<S> AppCheckService<S> {
    fn token_auth(&self, req: &mut Request) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
        if let Some(ref bearer_verifier) = self.verifier.bearer_verifier {
            if let Some(token) = req
                .headers()
                .get(header::AUTHORIZATION)
                .and_then(|auth_header| auth_header.to_str().ok())
                .and_then(|auth_value| {
                    auth_value
                        .strip_prefix("Bearer ")
                        .map(|token| token.to_owned())
                })
            {
                if let Ok(Some(subject)) =
                    bearer_verifier.verify(&token).map(|claims| claims.subject)
                {
                    req.extensions_mut().insert(Bearer::new(&subject));
                    return Ok(());
                }
            }
        }

        let token = req
            .headers()
            .get(APP_CHECK_HEADER)
            .and_then(|header| header.to_str().ok())
            .ok_or_else(|| {
                tracing::debug!("request missing app check token header");
                error_response()
            })?;

        let metadata = Token::decode_metadata(token).map_err(|_| {
            tracing::debug!(token, "token missing metadata");
            error_response()
        })?;

        // Checks token header `alg` and `typ` fields match the expected values
        if metadata.algorithm() != "RS256" || metadata.signature_type() != Some("JWT") {
            tracing::debug!(
                alg = metadata.algorithm(),
                typ = metadata.signature_type(),
                "invalid token metadata headers"
            );
            return Err(error_response());
        }

        let Some(key_id) = metadata.key_id() else {
            tracing::debug!("token missing kid metadata header");
            return Err(error_response());
        };

        // Validates the token signature and that the expiry (+tolerance) is within the limit
        // automatically. Also incorporates validation of issuer, audiences (includes firebase project
        // number) and optional app ID subjects if configured in VerificationOpts
        let claims: JWTClaims<NoCustomClaims> = self
            .verifier
            .verify_token(key_id, token, self.verifier.verify_opts())
            .map_err(|_| {
                tracing::debug!(token, key_id, "invalid app check token");
                error_response()
            })?;

        // If the App Check implementation is configured with a Firebase app allow-list, verify the token
        // subject is among the allowed app IDs
        if let Some(app_ids) = self.verifier.verify_app_ids() {
            if !claims
                .subject
                .is_some_and(|subject| app_ids.contains(&subject))
            {
                tracing::debug!("token sub claim missing or invalid");
                return Err(error_response());
            }
        }

        Ok(())
    }
}

impl<S> Service<Request> for AppCheckService<S>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    #[inline]
    fn poll_ready(&mut self, ctx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(ctx)
    }

    fn call(&mut self, mut req: Request) -> Self::Future {
        let not_ready_inner = self.inner.clone();
        let mut ready_inner = std::mem::replace(&mut self.inner, not_ready_inner);
        let auth_result = self.token_auth(&mut req);

        Box::pin(async move {
            match auth_result {
                Ok(_) => ready_inner.call(req).await,
                Err(err) => Ok(err.into_response()),
            }
        })
    }
}

fn error_response() -> (StatusCode, Json<serde_json::Value>) {
    let err_resp = serde_json::json!({
        "status": "fail",
        "message": "request not authenticated",
    });
    (StatusCode::UNAUTHORIZED, Json(err_resp))
}
