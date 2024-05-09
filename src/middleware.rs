use super::AppCheck;
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::IntoResponse,
    Json,
};
use jwt_simple::{
    claims::{JWTClaims, NoCustomClaims},
    token::Token,
};

const APP_CHECK_HEADER: &str = "X-Firebase-AppCheck";

pub async fn token_auth<A>(
    State(data): State<A>,
    req: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)>
where
    A: AppCheck,
{
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
    let claims: JWTClaims<NoCustomClaims> = data
        .verify_token(key_id, token, data.verify_opts())
        .map_err(|_| error_response())?;

    // If the App Check implementation is configured with a Firebase app allow-list, verify the token
    // subject is among the allowed app IDs
    if let Some(app_ids) = data.verify_app_ids() {
        if !claims
            .subject
            .is_some_and(|subject| app_ids.contains(&subject))
        {
            return Err(error_response());
        }
    }

    Ok(next.run(req).await)
}

fn error_response() -> (StatusCode, Json<serde_json::Value>) {
    let err_resp = serde_json::json!({
        "status": "fail",
        "message": "request not authenticated",
    });
    (StatusCode::UNAUTHORIZED, Json(err_resp))
}
