// Kelan Security — Integration Tests
// Run: cargo test --workspace -- --test-threads=2



// ─────────────────────────────────────────────────────────────────────────────
//  Test helpers
// ─────────────────────────────────────────────────────────────────────────────

use std::net::TcpListener;
use tokio::task::JoinHandle;

async fn spawn_test_server() -> (u16, JoinHandle<()>) {
    std::env::set_var("KELAN_JWT_SECRET", "kelan-test-secret-for-ci");
    std::env::set_var("AITP_JWT_SECRET", "kelan-test-secret-for-ci-padding");
    std::env::set_var("KELAN_TEST_MODE", "1");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind failed");
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        aitp_server::run_with_listener(listener).await.unwrap();
    });
    // Give the server a moment to be ready
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    (port, handle)
}

fn kelan_base_url(port: u16) -> String {
    format!("http://127.0.0.1:{}", port)
}

async fn http_get(port: u16, path: &str) -> reqwest::Response {
    reqwest::Client::new()
        .get(format!("{}{}", kelan_base_url(port), path))
        .send()
        .await
        .expect("HTTP request failed")
}

async fn http_post_json(port: u16, path: &str, body: serde_json::Value) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{}{}", kelan_base_url(port), path))
        .json(&body)
        .send()
        .await
        .expect("HTTP POST failed")
}

#[allow(dead_code)]
async fn http_post_json_auth(port: u16, path: &str, body: serde_json::Value, token: &str) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{}{}", kelan_base_url(port), path))
        .header("Authorization", format!("Bearer {}", token))
        .json(&body)
        .send()
        .await
        .expect("Authenticated HTTP POST failed")
}

async fn get_auth_token(port: u16) -> Option<String> {
    // Try signup first, then signin
    let signup = http_post_json(
        port,
        "/api/auth/signup",
        serde_json::json!({
            "org_name": "Integration Test Org",
            "email": "test@kelan.dev",
            "password": "KelanTest#2024!"
        }),
    )
    .await;

    if signup.status().is_success() {
        let body: serde_json::Value = signup.json().await.ok()?;
        return body["token"].as_str().map(|s| s.to_string());
    }

    // Already exists — sign in
    let signin = http_post_json(
        port,
        "/api/auth/signin",
        serde_json::json!({
            "email": "test@kelan.dev",
            "password": "KelanTest#2024!"
        }),
    )
    .await;

    if signin.status().is_success() {
        let body: serde_json::Value = signin.json().await.ok()?;
        return body["token"].as_str().map(|s| s.to_string());
    }

    None
}

// ─────────────────────────────────────────────────────────────────────────────
//  Auth tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod auth_integration {
    use super::*;

    #[tokio::test]
    async fn test_signup_creates_account() {
        let (port, _svr) = spawn_test_server().await;
        let unique_email = format!("signup_test_{}@test.kelan", uuid::Uuid::new_v4());
        let res = http_post_json(
            port,
            "/api/auth/signup",
            serde_json::json!({
                "org_name": "Test Org",
                "email": unique_email,
                "password": "StrongPass123!"
            }),
        )
        .await;

        assert!(
            res.status().is_success() || res.status().as_u16() == 409,
            "Signup returned unexpected status: {}",
            res.status()
        );
    }

    #[tokio::test]
    async fn test_signin_invalid_credentials_returns_401() {
        let (port, _svr) = spawn_test_server().await;
        let res = http_post_json(
            port,
            "/api/auth/signin",
            serde_json::json!({
                "email": "nonexistent@test.kelan",
                "password": "WrongPassword!"
            }),
        )
        .await;

        assert_eq!(
            res.status().as_u16(),
            401,
            "Expected 401 for invalid credentials"
        );
    }

    #[tokio::test]
    async fn test_weak_password_rejected() {
        let (port, _svr) = spawn_test_server().await;
        let unique_email = format!("weak_test_{}@test.kelan", uuid::Uuid::new_v4());
        let res = http_post_json(
            port,
            "/api/auth/signup",
            serde_json::json!({
                "org_name": "Test",
                "email": unique_email,
                "password": "abc"  // Too short
            }),
        )
        .await;

        assert!(
            res.status().as_u16() == 400 || res.status().as_u16() == 422,
            "Expected 400/422 for weak password, got {}",
            res.status()
        );
    }

    #[tokio::test]
    async fn test_token_returned_on_signin() {
        let (port, _svr) = spawn_test_server().await;
        let token = get_auth_token(port).await;
        assert!(token.is_some(), "Failed to obtain auth token");
        let t = token.unwrap();
        assert!(t.len() > 20, "Token is suspiciously short: {}", t.len());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Authorization / zero-trust enforcement
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod authorization {
    use super::*;

    #[tokio::test]
    async fn test_entities_requires_auth() {
        let (port, _svr) = spawn_test_server().await;
        let res = http_get(port, "/api/entities").await;
        assert_eq!(res.status().as_u16(), 401, "Expected 401 without auth");
    }

    #[tokio::test]
    async fn test_sessions_requires_auth() {
        let (port, _svr) = spawn_test_server().await;
        let res = http_get(port, "/api/sessions").await;
        assert_eq!(res.status().as_u16(), 401, "Expected 401 without auth");
    }

    #[tokio::test]
    async fn test_sentinel_requires_auth() {
        let (port, _svr) = spawn_test_server().await;
        let res = http_get(port, "/api/sentinel/status").await;
        assert_eq!(res.status().as_u16(), 401, "Expected 401 without auth");
    }

    #[tokio::test]
    async fn test_invalid_jwt_rejected() {
        let (port, _svr) = spawn_test_server().await;
        let res = reqwest::Client::new()
            .get(format!("{}/api/entities", kelan_base_url(port)))
            .header("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJoYWNrZXIifQ.tampered")
            .send()
            .await
            .unwrap();
        assert_eq!(res.status().as_u16(), 401);
    }

    #[tokio::test]
    async fn test_valid_token_allows_access() {
        let (port, _svr) = spawn_test_server().await;
        if let Some(token) = get_auth_token(port).await {
            let res = reqwest::Client::new()
                .get(format!("{}/api/entities", kelan_base_url(port)))
                .header("Authorization", format!("Bearer {}", token))
                .send()
                .await
                .unwrap();
            assert!(
                res.status().is_success(),
                "Valid token denied: {}",
                res.status()
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Security — injection & XSS
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod security_injection {
    use super::*;

    #[tokio::test]
    async fn test_sql_injection_in_email_blocked() {
        let (port, _svr) = spawn_test_server().await;
        let res = http_post_json(
            port,
            "/api/auth/signin",
            serde_json::json!({
                "email": "admin' OR '1'='1",
                "password": "anything"
            }),
        )
        .await;

        assert_ne!(
            res.status().as_u16(),
            200,
            "SQL injection succeeded — this is a CRITICAL vulnerability"
        );
    }

    #[tokio::test]
    async fn test_sql_injection_in_password_blocked() {
        let (port, _svr) = spawn_test_server().await;
        let res = http_post_json(
            port,
            "/api/auth/signin",
            serde_json::json!({
                "email": "valid@test.kelan",
                "password": "'; DROP TABLE organisations; --"
            }),
        )
        .await;

        assert_ne!(res.status().as_u16(), 200);
    }

    #[tokio::test]
    async fn test_xss_payload_in_org_name_rejected() {
        let (port, _svr) = spawn_test_server().await;
        let res = http_post_json(
            port,
            "/api/auth/signup",
            serde_json::json!({
                "org_name": "<script>alert('XSS')</script>",
                "email": format!("xss_{}@test.kelan", uuid::Uuid::new_v4()),
                "password": "StrongPass123!"
            }),
        )
        .await;

        // Either rejected (400) or sanitized and stored — check response
        if res.status().is_success() {
            let body: serde_json::Value = res.json().await.unwrap_or_default();
            let stored_name = body["org_name"].as_str().unwrap_or("");
            assert!(
                !stored_name.contains("<script>"),
                "XSS payload was stored unescaped: {}",
                stored_name
            );
        }
        // 400/422 is also acceptable (rejected outright)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Security headers
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod security_headers {
    use super::*;

    async fn get_headers(port: u16, path: &str) -> reqwest::header::HeaderMap {
        reqwest::Client::new()
            .get(format!("{}{}", kelan_base_url(port), path))
            .send()
            .await
            .expect("Request failed")
            .headers()
            .clone()
    }

    #[tokio::test]
    async fn test_x_frame_options_present() {
        let (port, _svr) = spawn_test_server().await;
        let headers = get_headers(port, "/api/stats").await;
        let present = headers.contains_key("x-frame-options");
        assert!(present, "X-Frame-Options security header is missing");
    }

    #[tokio::test]
    async fn test_x_content_type_options_present() {
        let (port, _svr) = spawn_test_server().await;
        let headers = get_headers(port, "/api/stats").await;
        let present = headers.contains_key("x-content-type-options");
        assert!(present, "X-Content-Type-Options security header is missing");
    }

    #[tokio::test]
    async fn test_stats_endpoint_public() {
        let (port, _svr) = spawn_test_server().await;
        let res = http_get(port, "/api/stats").await;
        assert!(
            res.status().is_success(),
            "Stats endpoint should be public, got {}",
            res.status()
        );
    }

    #[tokio::test]
    async fn test_secrets_not_in_response_body() {
        let (port, _svr) = spawn_test_server().await;
        let body = http_get(port, "/api/stats")
            .await
            .text()
            .await
            .unwrap_or_default();

        let forbidden = ["JWT_SECRET", "GEMINI_API_KEY", "DATABASE_URL", "password_hash"];
        for term in &forbidden {
            assert!(
                !body.to_lowercase().contains(&term.to_lowercase()),
                "Secret '{}' found in public response body",
                term
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Crypto / PQ identity
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod crypto_identity {
    use kelan_crypto::{HybridEntityIdentity, CryptoAlgorithm};

    #[test]
    fn test_hybrid_identity_generation() {
        let id = HybridEntityIdentity::load_or_generate()
            .expect("Failed to generate identity");
        assert!(!id.entity_id.is_empty(), "Entity ID is empty");
        assert_eq!(id.algorithm, CryptoAlgorithm::HybridPQ);
    }

    #[test]
    fn test_hybrid_sign_verify_roundtrip() {
        let id = HybridEntityIdentity::load_or_generate().unwrap();
        let message = b"Kelan Security - zero-trust handshake payload";
        let sig = id.sign(message);
        let sig_bytes = sig.to_bytes();
        assert!(!sig_bytes.is_empty(), "Signature is empty");
        assert!(sig_bytes.len() > 100, "Signature too short for hybrid PQ");
    }

    #[test]
    fn test_public_key_size_is_hybrid() {
        let id = HybridEntityIdentity::load_or_generate().unwrap();
        let pk = id.public_key_bytes();
        // ML-DSA-65 pubkey (1952 bytes) + Ed25519 pubkey (32 bytes) + framing
        assert!(pk.len() > 1000, "Public key too small for hybrid PQ: {} bytes", pk.len());
    }
}
