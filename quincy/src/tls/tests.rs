use super::*;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

fn authority() -> (Certificate, KeyPair) {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(2040, 1, 1);
    (params.self_signed(&key).unwrap(), key)
}

fn leaf(
    ca: &Certificate,
    ca_key: &KeyPair,
    usage: ExtendedKeyUsagePurpose,
) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec!["example.test".into()]).unwrap();
    params.extended_key_usages = vec![usage];
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(2040, 1, 1);
    let cert = params.signed_by(&key, ca, ca_key).unwrap();
    (
        cert.der().clone(),
        PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
    )
}

fn now(year: i32) -> UnixTime {
    UnixTime::since_unix_epoch(std::time::Duration::from_secs(
        rcgen::date_time_ymd(year, 1, 1)
            .unix_timestamp()
            .try_into()
            .unwrap(),
    ))
}

#[test]
fn explicit_roots_do_not_replace_user_grants_or_chain_validation() {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let (ca, ca_key) = authority();
    let (server, key) = leaf(&ca, &ca_key, ExtendedKeyUsagePurpose::ServerAuth);
    let key = Arc::new(CertifiedKey::from_der(vec![server], key, &provider).unwrap());
    let identity = Identity::new(key, &[ca.der().clone()]).unwrap();
    let (client, _) = leaf(&ca, &ca_key, ExtendedKeyUsagePurpose::ClientAuth);
    let (other_ca, other_key) = authority();
    let (foreign, _) = leaf(&other_ca, &other_key, ExtendedKeyUsagePurpose::ClientAuth);
    let verifier = identity
        .verifier(
            provider.clone(),
            [
                compute_cert_fingerprint(&client),
                compute_cert_fingerprint(&foreign),
            ]
            .into(),
        )
        .unwrap();
    assert!(verifier.client_auth_mandatory());
    assert!(verifier.verify_client_cert(&client, &[], now(2030)).is_ok());
    assert!(
        verifier
            .verify_client_cert(&foreign, &[], now(2030))
            .is_err()
    );
    assert!(
        verifier
            .verify_client_cert(&client, &[], now(2050))
            .is_err()
    );
    let denied = identity.verifier(provider, HashSet::new()).unwrap();
    assert!(denied.verify_client_cert(&client, &[], now(2030)).is_err());
}

#[test]
fn server_only_certificate_cannot_authenticate_as_client() {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let (ca, ca_key) = authority();
    let (server, key) = leaf(&ca, &ca_key, ExtendedKeyUsagePurpose::ServerAuth);
    let key = Arc::new(CertifiedKey::from_der(vec![server.clone()], key, &provider).unwrap());
    let identity = Identity::new(key, &[ca.der().clone()]).unwrap();
    let verifier = identity
        .verifier(provider, [compute_cert_fingerprint(&server)].into())
        .unwrap();
    assert!(
        verifier
            .verify_client_cert(&server, &[], now(2030))
            .is_err()
    );
}

#[test]
fn empty_or_invalid_trust_is_rejected_without_defaults() {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let (ca, ca_key) = authority();
    let (server, key) = leaf(&ca, &ca_key, ExtendedKeyUsagePurpose::ServerAuth);
    let key = Arc::new(CertifiedKey::from_der(vec![server], key, &provider).unwrap());
    assert!(Identity::new(key.clone(), &[]).is_err());
    assert!(Identity::new(key, &[CertificateDer::from(vec![0])]).is_err());
}
