//! OpenPGP validity semantics: a signature is judged against the key's
//! validity *at the commit time*, not the audit time.

use rand::SeedableRng;
use sigaudit::pgp_keyring::{PgpKey, PgpKeyring, PgpValidity};
use sigaudit::pgp_verify;

use pgp::composed::SignedKeyDetails;
use pgp::composed::{KeyType, SecretKeyParamsBuilder, SignedSecretKey};
use pgp::packet::{SignatureConfig, SignatureType, Subpacket, SubpacketData};
use pgp::types::{Duration, Password, SignedUser, Tag};

fn make_key(created: i64) -> SignedSecretKey {
    make_key_seeded(created, 1)
}

fn make_key_seeded(created: i64, seed: u64) -> SignedSecretKey {
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);
    SecretKeyParamsBuilder::default()
        .key_type(KeyType::Ed25519Legacy)
        .can_sign(true)
        .can_certify(true)
        .primary_user_id("Test <test@example.com>".into())
        .created_at(pgp::types::Timestamp::from_secs(created as u32))
        .build()
        .unwrap()
        .generate(&mut rng)
        .unwrap()
}

/// Rebuild a certificate with a fresh self-signature carrying a key
/// expiration of `valid_secs` seconds, created at `sig_time`.
fn with_expiry(key: &SignedSecretKey, sig_time: i64, valid_secs: u32) -> PgpKey {
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(2);
    let public = key.to_public_key();
    let uid = public.details.users[0].id.clone();
    let mut cfg =
        SignatureConfig::from_key(&mut rng, &key.primary_key, SignatureType::CertPositive).unwrap();
    cfg.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(
            pgp::types::Timestamp::from_secs(sig_time as u32),
        ))
        .unwrap(),
        Subpacket::regular(SubpacketData::KeyExpirationTime(Duration::from_secs(
            valid_secs,
        )))
        .unwrap(),
    ];
    let sig = cfg
        .sign_certification(
            &key.primary_key,
            &public.primary_key,
            &Password::empty(),
            Tag::UserId,
            &uid,
        )
        .unwrap();
    let cert = pgp::composed::SignedPublicKey::new(
        public.primary_key.clone(),
        SignedKeyDetails::new(
            vec![],
            vec![],
            vec![SignedUser::new(uid, vec![sig])],
            vec![],
        ),
        vec![],
    );
    PgpKey::from_cert(cert)
}

/// Rebuild a certificate with a key revocation created at `revoked_at`.
fn with_revocation(key: &SignedSecretKey, revoked_at: i64) -> PgpKey {
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(3);
    let public = key.to_public_key();
    let uid = public.details.users[0].id.clone();
    let mut cfg =
        SignatureConfig::from_key(&mut rng, &key.primary_key, SignatureType::KeyRevocation)
            .unwrap();
    cfg.hashed_subpackets = vec![Subpacket::regular(SubpacketData::SignatureCreationTime(
        pgp::types::Timestamp::from_secs(revoked_at as u32),
    ))
    .unwrap()];
    let sig = cfg
        .sign_key(&key.primary_key, &Password::empty(), &public.primary_key)
        .unwrap();
    let cert = pgp::composed::SignedPublicKey::new(
        public.primary_key.clone(),
        SignedKeyDetails::new(
            vec![sig],
            vec![],
            vec![SignedUser::new(uid, vec![])],
            vec![],
        ),
        vec![],
    );
    PgpKey::from_cert(cert)
}

#[test]
fn expiry_boundary_is_inclusive_of_the_expiry_instant() {
    // Created at 1000, valid for 1000s => expires at 2000. GnuPG treats `now`
    // at or past the expiry instant as expired (`key_expire >= curtime ? 0 : …`).
    let key = make_key(1000);
    let cert = with_expiry(&key, 1000, 1000);
    assert_eq!(cert.expires, 2000);
    assert_eq!(cert.validity_at(1999), PgpValidity::Valid);
    assert_eq!(cert.validity_at(2000), PgpValidity::Expired);
    assert_eq!(cert.validity_at(2001), PgpValidity::Expired);
}

#[test]
fn key_with_no_expiry_is_valid_forever() {
    let key = make_key(1000);
    let cert = PgpKey::from_cert(key.to_public_key());
    assert_eq!(cert.expires, 0);
    assert_eq!(cert.validity_at(0), PgpValidity::Valid);
    assert_eq!(cert.validity_at(i64::from(u32::MAX)), PgpValidity::Valid);
}

#[test]
fn revocation_only_counts_from_its_creation_time() {
    let key = make_key(1000);
    let cert = with_revocation(&key, 5000);
    assert_eq!(cert.revoked_at, Some(5000));
    assert_eq!(cert.validity_at(4999), PgpValidity::RevokedLater);
    assert_eq!(cert.validity_at(5000), PgpValidity::Revoked);
}

#[test]
fn unverified_revocation_is_ignored() {
    // A revocation signed by the wrong key must not mark the certificate dead:
    // that would be a cheap denial of service against an audit.
    let key = make_key(1000);
    let attacker = make_key_seeded(1000, 99);
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(4);
    let public = key.to_public_key();
    let uid = public.details.users[0].id.clone();
    let mut cfg = SignatureConfig::from_key(
        &mut rng,
        &attacker.primary_key,
        SignatureType::KeyRevocation,
    )
    .unwrap();
    cfg.hashed_subpackets = vec![Subpacket::regular(SubpacketData::SignatureCreationTime(
        pgp::types::Timestamp::from_secs(5000),
    ))
    .unwrap()];
    let forged = cfg
        .sign_key(
            &attacker.primary_key,
            &Password::empty(),
            &public.primary_key,
        )
        .unwrap();
    let cert = pgp::composed::SignedPublicKey::new(
        public.primary_key.clone(),
        SignedKeyDetails::new(
            vec![forged],
            vec![],
            vec![SignedUser::new(uid, vec![])],
            vec![],
        ),
        vec![],
    );
    let parsed = PgpKey::from_cert(cert);
    assert_eq!(parsed.revoked_at, None);
}

#[test]
fn verification_uses_commit_time_for_expiry() {
    // Sign a payload with a key that has since expired; the same signature
    // must be accepted at a commit time inside the valid window and rejected
    // outside it.
    let key = make_key(1_500_000_000);
    let cert = with_expiry(&key, 1_500_000_000, 86_400);
    let mut ring = PgpKeyring::new();
    // Provide the certificate with its expiry.
    let fpr = cert.fingerprint.clone();
    ring.insert(cert);

    let payload = b"signed content";
    let sig = sign_with(&key, payload);

    let inside = pgp_verify::verify(&ring, payload, &sig, 1_500_001_000);
    assert!(inside.verified, "{:?}", inside.reason);
    assert!(inside.issue.is_none(), "{:?}", inside.issue);

    let outside = pgp_verify::verify(&ring, payload, &sig, 1_500_200_000);
    assert!(outside.verified, "crypto must still verify");
    assert!(matches!(
        outside.issue,
        Some(sigaudit::model::KeyIssue::Expired)
    ));
    let _ = fpr;
}

fn sign_with(key: &SignedSecretKey, payload: &[u8]) -> Vec<u8> {
    use pgp::composed::DetachedSignature;
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(5);
    let sig = DetachedSignature::sign_binary_data(
        &mut rng,
        &key.primary_key,
        &Password::empty(),
        pgp::crypto::hash::HashAlgorithm::Sha256,
        payload,
    )
    .unwrap();
    sig.to_armored_bytes(Default::default()).unwrap()
}

#[test]
fn expired_signature_at_past_time_is_reported_untrusted_not_invalid() {
    let key = make_key(1_500_000_000);
    let cert = with_expiry(&key, 1_500_000_000, 86_400);
    let mut ring = PgpKeyring::new();
    ring.insert(cert);
    let payload = b"content";
    let sig = sign_with(&key, payload);
    let outcome = pgp_verify::verify(&ring, payload, &sig, 1_500_200_000);
    assert!(outcome.verified);
    assert!(!outcome.trusted);
    assert!(outcome.reason.as_deref().unwrap().contains("expired"));
}
