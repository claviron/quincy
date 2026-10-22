use std::collections::HashMap;
use std::sync::Arc;

use super::{FileIdentityProvider, IdentityProvider, IdentitySnapshot};
use crate::users::{UserEntry, UsersFile};

fn entry(fingerprint: &str) -> UserEntry {
    UserEntry {
        authorized_keys: Vec::new(),
        authorized_certs: vec![fingerprint.into()],
        bandwidth_limit: None,
        address_pool: Vec::new(),
    }
}

#[test]
fn snapshot_rejects_duplicate_and_invalid_credentials() {
    let fingerprint = format!("sha256:{}", "ab".repeat(32));
    let duplicate = HashMap::from([
        ("alice".into(), entry(&fingerprint)),
        (
            "bob".into(),
            entry(&fingerprint.to_uppercase().replace("SHA256", "sha256")),
        ),
    ]);
    assert!(IdentitySnapshot::new(duplicate).is_err());
    assert!(IdentitySnapshot::new(HashMap::from([("alice".into(), entry("invalid"))])).is_err());
}

#[test]
fn snapshot_rebuilds_indices_from_entries() {
    let fingerprint = format!("sha256:{}", "ab".repeat(32));
    let mut users =
        UsersFile::from_entries(HashMap::from([("alice".into(), entry(&fingerprint))])).unwrap();
    // UsersFile exposes a mutable compatibility map; snapshots never trust its
    // potentially stale indices and only accept entries for fresh validation.
    let alice = users.users.remove("alice").unwrap();
    users.users.insert("bob".into(), alice);
    let snapshot = IdentitySnapshot::new(users.users).unwrap();
    assert_eq!(
        snapshot
            .credentials()
            .find_user_by_cert_fingerprint(&fingerprint),
        Some("bob")
    );
}

#[test]
fn empty_snapshot_explicitly_denies_all_identities() {
    let snapshot = IdentitySnapshot::new(HashMap::new()).unwrap();
    assert!(snapshot.users().is_empty());
    assert!(
        snapshot
            .credentials()
            .collect_cert_fingerprints()
            .is_empty()
    );
    assert!(
        snapshot
            .credentials()
            .collect_noise_public_keys()
            .is_empty()
    );
}

#[test]
fn file_reload_is_transactional_and_keeps_pinned_snapshots_alive() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("users.toml");
    std::fs::write(&path, "[users.alice]\n").unwrap();
    let provider = FileIdentityProvider::new(&path).unwrap();
    let mut updates = provider.subscribe().unwrap();
    let initial = updates.borrow_and_update().clone();

    std::fs::write(&path, "not valid TOML").unwrap();
    assert!(provider.reload().is_err());
    assert!(!updates.has_changed().unwrap());
    assert!(Arc::ptr_eq(&initial, &updates.borrow()));

    std::fs::write(&path, "[users.bob]\n").unwrap();
    provider.reload().unwrap();
    assert!(updates.has_changed().unwrap());
    let current = updates.borrow_and_update().clone();
    assert!(current.users().contains_key("bob"));
    assert!(!current.users().contains_key("alice"));
    assert!(initial.users().contains_key("alice"));

    std::fs::remove_file(path).unwrap();
    assert!(provider.reload().is_err());
    assert!(Arc::ptr_eq(&current, &updates.borrow()));
}
