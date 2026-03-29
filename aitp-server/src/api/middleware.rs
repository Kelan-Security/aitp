use axum::{
    body::Body, extract::Request, http::StatusCode, middleware::Next, response::IntoResponse,
};
use http_body_util::BodyExt; // For `collect` method

use crate::crypto::{hybrid_sig, HybridSignature, HybridVerifyingKey};

pub async fn require_hybrid_signature(
    req: Request<Body>,
    next: Next,
) -> Result<impl IntoResponse, StatusCode> {
    let headers = req.headers().clone();

    // Extract Post-Quantum Entity Identity
    let pubkey_hex = headers
        .get("X-Kelan-Agent-Key")
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let pk_bytes = hex::decode(pubkey_hex).map_err(|_| StatusCode::BAD_REQUEST)?;

    let signature_hex = headers
        .get("X-Kelan-Signature")
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let sig_bytes = hex::decode(signature_hex).map_err(|_| StatusCode::BAD_REQUEST)?;

    // Reconstruct primitives
    let vk = HybridVerifyingKey::from_bytes(&pk_bytes).ok_or(StatusCode::UNAUTHORIZED)?;
    let sig = HybridSignature::from_bytes(&sig_bytes).ok_or(StatusCode::UNAUTHORIZED)?;

    // We must read the payload to verify it.
    let (parts, body) = req.into_parts();
    let body_bytes = body
        .collect()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .to_bytes();

    // Verify!
    hybrid_sig::verify_hybrid(&vk, &body_bytes, &sig).map_err(|_| StatusCode::FORBIDDEN)?;

    // Reconstruct request and proceed
    let req = Request::from_parts(parts, Body::from(body_bytes));
    Ok(next.run(req).await)
}
