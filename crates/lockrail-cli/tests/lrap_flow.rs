use lockrail_protocol::{
    AccessProof, AgentKeypairDoc, CapabilityClaims, CapabilityToken, body_hash, enforce_request,
};
use lockrail_vault::{KdfParamsDoc, Vault};
use secrecy::SecretString;

#[test]
fn rust_sapp_end_to_end() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("vault.lockrail");
    let mut vault =
        Vault::init(&path, SecretString::from("pw"), KdfParamsDoc::test_fast()).unwrap();
    vault.add_key("openai".into(), "sk-secret".into()).unwrap();
    let agent = AgentKeypairDoc::generate("claude", "claude-code");
    let claims = CapabilityClaims::new(
        "openai",
        10,
        vec!["api.openai.com".into()],
        vec!["POST".into()],
        vec!["/v1/*".into()],
        "Authorization",
        "Bearer ",
        Some(1),
        Some(agent.public_key.clone()),
        Some("task-1".into()),
        Some("test".into()),
    );
    let token = CapabilityToken::issue(claims, &vault.signing_key().unwrap()).unwrap();
    let cap = CapabilityToken::verify(
        &token,
        &vault.issuer_public_key().unwrap(),
        &vault.revoked_list(),
    )
    .unwrap();
    enforce_request(
        &cap.claims,
        "POST",
        "https://api.openai.com/v1/chat/completions",
    )
    .unwrap();
    let bh = body_hash(br#"{"model":"x"}"#);
    let proof = AccessProof::sign(
        &agent,
        &token,
        "POST",
        "https://api.openai.com/v1/chat/completions",
        &bh,
        Some("task-1".into()),
        Some("test".into()),
    )
    .unwrap();
    proof
        .verify(
            cap.claims.agent_public_key.as_ref().unwrap(),
            &token,
            "POST",
            "https://api.openai.com/v1/chat/completions",
            &bh,
            &cap.claims.task_id,
            &cap.claims.purpose,
        )
        .unwrap();
    assert_eq!(vault.use_key("openai").unwrap(), "sk-secret");
}

#[test]
fn proof_cannot_move_to_different_body() {
    let agent = AgentKeypairDoc::generate("agent", "custom");
    let issuer = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let claims = CapabilityClaims::new(
        "k",
        10,
        vec!["api.example.com".into()],
        vec!["POST".into()],
        vec!["/".into()],
        "Authorization",
        "Bearer ",
        None,
        Some(agent.public_key.clone()),
        None,
        None,
    );
    let token = CapabilityToken::issue(claims.clone(), &issuer).unwrap();
    let bh1 = body_hash(b"one");
    let bh2 = body_hash(b"two");
    let proof = AccessProof::sign(
        &agent,
        &token,
        "POST",
        "https://api.example.com/",
        &bh1,
        None,
        None,
    )
    .unwrap();
    assert!(
        proof
            .verify(
                claims.agent_public_key.as_ref().unwrap(),
                &token,
                "POST",
                "https://api.example.com/",
                &bh2,
                &None,
                &None
            )
            .is_err()
    );
}
