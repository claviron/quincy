use std::collections::HashMap;
use std::sync::Arc;
use std::task::Poll;

use figment::{
    Figment,
    providers::{Format, Toml},
};
use quincy::config::{ClientConfig, ServerConfig};
use quincy::error::AuthError;
use tokio::sync::{mpsc, oneshot, watch};

use super::{Admission, Pools, Updates};
use crate::provider::{IdentityProvider, IdentitySnapshot};
use crate::server::{HandshakeOutcome, QuincyServer};

fn config(protocol: &str) -> ServerConfig {
    let path = format!("../quincy-tests/tests/static/configs/{protocol}/server.toml");
    let source = std::fs::read_to_string(path)
        .unwrap()
        .replace("tests/static/", "../quincy-tests/tests/static/");
    Figment::new()
        .merge(Toml::string(&source))
        .extract()
        .unwrap()
}

fn initial() -> Arc<IdentitySnapshot> {
    Arc::new(
        IdentitySnapshot::load(std::path::Path::new(
            "../quincy-tests/tests/static/users.toml",
        ))
        .unwrap(),
    )
}

struct Source(watch::Receiver<Arc<IdentitySnapshot>>);

impl IdentityProvider for Source {
    fn subscribe(&self) -> quincy::Result<watch::Receiver<Arc<IdentitySnapshot>>> {
        Ok(self.0.clone())
    }
}

#[test]
fn custom_provider_never_opens_users_file() {
    let mut config = config("tls_standard");
    let directory = tempfile::tempdir().unwrap();
    config.users_file = directory.path().join("does-not-exist.toml");
    let (_, receiver) = watch::channel(initial());
    assert!(QuincyServer::new_with_identity_provider(config.clone(), &Source(receiver)).is_ok());
    assert!(QuincyServer::new(config).is_err());
}

#[test]
fn unavailable_provider_fails_before_starting_io() {
    struct Unavailable;
    impl IdentityProvider for Unavailable {
        fn subscribe(&self) -> quincy::Result<watch::Receiver<Arc<IdentitySnapshot>>> {
            Err(AuthError::StoreUnavailable.into())
        }
    }
    assert!(
        QuincyServer::new_with_identity_provider(config("tls_standard"), &Unavailable).is_err()
    );
}

#[test]
fn pool_updates_cannot_reassign_live_addresses() {
    let config = config("tls_standard");
    let mut entries = initial().users().clone();
    entries.get_mut("test").unwrap().address_pool = vec!["10.0.0.2/32".parse().unwrap()];
    let snapshot = Arc::new(IdentitySnapshot::new(entries.clone()).unwrap());
    let pools = snapshot.pools();
    let allocator =
        crate::server::address_pool::AddressPoolManager::new(config.tunnel_network, pools.clone())
            .unwrap();
    let address = allocator.allocate_address("test").unwrap();
    let installed = Admission::prepare(&config, snapshot, &pools).unwrap();

    entries.get_mut("test").unwrap().address_pool = vec!["10.0.0.3/32".parse().unwrap()];
    assert!(
        Admission::prepare(
            &config,
            Arc::new(IdentitySnapshot::new(entries).unwrap()),
            &pools
        )
        .is_err()
    );
    // Revocation may remove a user, but their reserved range remains allocated
    // by the original manager and cannot become another user's global address.
    let empty = Arc::new(IdentitySnapshot::new(HashMap::new()).unwrap());
    assert!(Admission::prepare(&config, empty, &pools).is_ok());
    assert_eq!(
        installed.identity.users()["test"].address_pool,
        pools["test"]
    );
    assert!(allocator.allocate_address("test").is_none());
    assert_ne!(allocator.allocate_address("other").unwrap(), address);
    allocator.release_address("test", &address.addr());
    assert_eq!(allocator.allocate_address("test").unwrap(), address);
}

#[tokio::test]
async fn failed_update_retains_admission_and_later_update_can_succeed() {
    let config = config("tls_standard");
    let initial = initial();
    let installed = Admission::prepare(&config, initial.clone(), &Pools::new()).unwrap();
    let (sender, receiver) = watch::channel(initial.clone());
    let mut updates = Updates::new(receiver, config, Pools::new());
    let mut entries = initial.users().clone();
    entries.get_mut("test").unwrap().address_pool = vec!["10.0.0.2/32".parse().unwrap()];
    sender.send_replace(Arc::new(IdentitySnapshot::new(entries).unwrap()));
    assert!(updates.next().await.unwrap().is_err());
    assert!(Arc::ptr_eq(&installed.identity, &initial));

    let empty = Arc::new(IdentitySnapshot::new(HashMap::new()).unwrap());
    sender.send_replace(empty.clone());
    let replacement = updates.next().await.unwrap().unwrap();
    assert!(Arc::ptr_eq(&replacement.identity, &empty));
    drop(sender);
    assert!(updates.next().await.is_none());
    assert!(!updates.is_open());
}

#[tokio::test]
async fn select_cancellation_keeps_the_owned_preparation() {
    let config = config("tls_standard");
    let initial = initial();
    let (_sender, receiver) = watch::channel(initial.clone());
    let mut updates = Updates::new(receiver, config.clone(), Pools::new());
    let (release, wait) = std::sync::mpsc::sync_channel(0);
    let (started, ready) = oneshot::channel();
    updates.task = Some(tokio::task::spawn_blocking(move || {
        started.send(()).unwrap();
        wait.recv().unwrap();
        Admission::prepare(&config, initial, &Pools::new())
    }));
    ready.await.unwrap();
    {
        let next = updates.next();
        tokio::pin!(next);
        assert!(matches!(futures::poll!(next.as_mut()), Poll::Pending));
    }
    assert!(updates.task.is_some());
    release.send(()).unwrap();
    assert!(updates.next().await.unwrap().is_ok());
    assert!(updates.task.is_none());
}

#[tokio::test]
async fn shutdown_drains_owned_preparation() {
    let config = config("tls_standard");
    let initial = initial();
    let (_sender, receiver) = watch::channel(initial.clone());
    let mut updates = Updates::new(receiver, config.clone(), Pools::new());
    let (release, wait) = oneshot::channel();
    updates.task = Some(tokio::task::spawn_blocking(move || {
        wait.blocking_recv().unwrap();
        Admission::prepare(&config, initial, &Pools::new())
    }));
    {
        let drain = updates.drain();
        tokio::pin!(drain);
        assert!(matches!(futures::poll!(drain.as_mut()), Poll::Pending));
        release.send(()).unwrap();
        drain.await;
    }
    assert!(updates.task.is_none());
}

#[test]
fn policy_replacement_preserves_an_existing_shared_limiter() {
    use crate::server::session::{ConnectionSession, UserSessionRegistry};
    use quincy::config::Bandwidth;
    use std::time::Instant;

    let mut entries = initial().users().clone();
    entries.get_mut("test").unwrap().bandwidth_limit = Some(Bandwidth::from_bytes_per_second(1024));
    let old = IdentitySnapshot::new(entries.clone()).unwrap();
    entries.get_mut("test").unwrap().bandwidth_limit = Some(Bandwidth::from_bytes_per_second(2048));
    let new = IdentitySnapshot::new(entries).unwrap();
    let registry = UserSessionRegistry::new();
    let first = "192.0.2.2/29".parse().unwrap();
    let second = "192.0.2.3/29".parse().unwrap();
    let add = |address, snapshot: &IdentitySnapshot| {
        registry
            .add_connection(
                "test",
                ConnectionSession {
                    client_address: address,
                    connected_at: Instant::now(),
                },
                snapshot.users()["test"].bandwidth_limit,
            )
            .unwrap()
    };
    let held = add(first, &old);
    assert!(Arc::ptr_eq(&held, &add(second, &new)));
    registry.remove_connection("test", &first);
    registry.remove_connection("test", &second);
    assert!(!Arc::ptr_eq(&held, &add(first, &new)));
}

#[tokio::test]
async fn pinned_tls_config_and_lookup_survive_a_new_default_config() {
    let config = config("tls_standard");
    let old = Arc::new(Admission::prepare(&config, initial(), &Pools::new()).unwrap());
    let replacement = Admission::prepare(
        &config,
        Arc::new(IdentitySnapshot::new(HashMap::new()).unwrap()),
        &Pools::new(),
    )
    .unwrap();

    let endpoint = quinn::Endpoint::server(
        replacement.transport.as_ref().clone(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let address = endpoint.local_addr().unwrap();
    let source =
        std::fs::read_to_string("../quincy-tests/tests/static/configs/tls_standard/client.toml")
            .unwrap()
            .replace("tests/static/", "../quincy-tests/tests/static/");
    let client: ClientConfig = Figment::new()
        .merge(Toml::string(&source))
        .extract()
        .unwrap();
    let mut client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(client.quinn_client_config().unwrap());
    let connecting = client_endpoint.connect(address, "localhost").unwrap();
    let (ingress, _receiver) = mpsc::channel(1);
    let protocol = Arc::new(config.protocol);
    let server = async {
        let incoming = endpoint.accept().await.unwrap();
        // The default config already denies this certificate. Only the pinned
        // accept_with config may admit the handshake that owns the old snapshot.
        QuincyServer::handshake_and_identify(incoming, protocol.clone(), old, ingress).await
    };
    let (client, result) = tokio::join!(connecting, server);
    let client = client.unwrap();
    let HandshakeOutcome::Identified {
        connection,
        quic_connection,
    } = result
    else {
        panic!("pinned handshake failed")
    };
    assert_eq!(connection.username(), "test");
    assert!(
        crate::identity::identify_peer(
            &quic_connection,
            &protocol,
            replacement.identity.credentials()
        )
        .is_err()
    );
    // Reuse the TLS client config/session cache after revocation as well.
    let reconnecting = client_endpoint.connect(address, "localhost").unwrap();
    let (ingress, _receiver) = mpsc::channel(1);
    let server = async {
        QuincyServer::handshake_and_identify(
            endpoint.accept().await.unwrap(),
            protocol,
            Arc::new(replacement),
            ingress,
        )
        .await
    };
    let (reconnect, result) = tokio::join!(reconnecting, server);
    assert!(matches!(result, HandshakeOutcome::Failed));
    if let Ok(connection) = reconnect {
        connection.closed().await;
    }
    client
        .send_datagram(bytes::Bytes::from_static(b"still connected"))
        .unwrap();
    assert_eq!(
        quic_connection.read_datagram().await.unwrap().as_ref(),
        b"still connected"
    );
    client.close(1_u32.into(), b"Client shutdown");
    endpoint.close(1_u32.into(), b"Server shutdown");
    endpoint.wait_idle().await;
}
