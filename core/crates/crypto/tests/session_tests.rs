//! Tests that complement the end-to-end integration tests in
//! `store/tests/integration.rs`. These cover edge cases specific to the
//! crypto layer that aren't exercised there.

use test_utils::TestClient;

#[tokio::test]
async fn wrong_recipient_cannot_decrypt() {
    let alice = TestClient::new("alice", 1).await;
    let bob = TestClient::new("bob", 1).await;
    let carol = TestClient::new("carol", 1).await;

    let bob_bundle = bob.publish_prekeys().await;
    crypto::session::initiate_session(
        &mut alice.store.clone(),
        &alice.address,
        &bob.address,
        &bob_bundle,
    )
    .await
    .unwrap();

    let encrypted = crypto::session::encrypt(
        &mut alice.store.clone(),
        &alice.address,
        &bob.address,
        b"for bob only",
    )
    .await
    .unwrap();

    // Carol should not be able to decrypt a message intended for Bob.
    let result = crypto::session::decrypt(
        &mut carol.store.clone(),
        &carol.address,
        &alice.address,
        &encrypted,
    )
    .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn prekey_generation_produces_valid_bundle() {
    let client = TestClient::new("user", 1).await;
    let bundle = client.publish_prekeys().await;

    assert!(!bundle.identity_key.is_empty());
    assert!(!bundle.signed_prekey.public_key.is_empty());
    assert!(!bundle.signed_prekey.signature.is_empty());
    assert!(bundle.one_time_prekey.is_some());
    assert!(!bundle.kyber_prekey.public_key.is_empty());
    assert!(!bundle.kyber_prekey.signature.is_empty());
}

#[tokio::test]
async fn session_without_one_time_prekey() {
    let alice = TestClient::new("alice", 1).await;
    let bob = TestClient::new("bob", 1).await;

    // Publish bundle but strip the one-time prekey (simulates exhausted pool).
    let mut bob_bundle = bob.publish_prekeys().await;
    bob_bundle.one_time_prekey = None;

    crypto::session::initiate_session(
        &mut alice.store.clone(),
        &alice.address,
        &bob.address,
        &bob_bundle,
    )
    .await
    .expect("should work without one-time prekey");

    let encrypted = crypto::session::encrypt(
        &mut alice.store.clone(),
        &alice.address,
        &bob.address,
        b"still works",
    )
    .await
    .unwrap();

    let decrypted = crypto::session::decrypt(
        &mut bob.store.clone(),
        &bob.address,
        &alice.address,
        &encrypted,
    )
    .await
    .unwrap();

    assert_eq!(decrypted, b"still works");
}
