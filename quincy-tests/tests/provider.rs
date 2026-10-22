mod common;

use std::collections::HashMap;
use std::net::{Ipv4Addr, UdpSocket};
use std::path::Path;
use std::sync::Arc;

use common::{TestChannels, TestInterface, dummy_packet, setup_interface};
use quincy::config::{ClientConfig, FromPath, ServerConfig};
use quincy_client::client::QuincyClient;
use quincy_server::provider::{IdentityProvider, IdentitySnapshot};
use quincy_server::server::QuincyServer;
use quincy_server::server::lifecycle::{Observer, Session};
use rstest::rstest;
use tokio::sync::{mpsc, oneshot, watch};

struct Source(watch::Receiver<Arc<IdentitySnapshot>>);

impl IdentityProvider for Source {
    fn subscribe(&self) -> quincy::Result<watch::Receiver<Arc<IdentitySnapshot>>> {
        Ok(self.0.clone())
    }
}

struct Sessions(mpsc::UnboundedSender<(bool, Session)>);

impl Observer for Sessions {
    fn connected(&self, session: Session) {
        self.0.send((true, session)).unwrap();
    }

    fn disconnected(&self, session: Session) {
        self.0.send((false, session)).unwrap();
    }
}

async fn publish(
    sender: &watch::Sender<Arc<IdentitySnapshot>>,
    applied: &mut watch::Receiver<Arc<IdentitySnapshot>>,
    snapshot: Arc<IdentitySnapshot>,
) {
    sender.send_replace(snapshot.clone());
    applied.changed().await.unwrap();
    assert!(Arc::ptr_eq(&applied.borrow_and_update(), &snapshot));
}

async fn traffic(client: &TestChannels, server: &TestChannels, source: Ipv4Addr) {
    let packet = dummy_packet(source, Ipv4Addr::new(192, 0, 2, 1));
    client.tx.lock().await.send(packet.clone()).unwrap();
    assert_eq!(server.rx.lock().await.recv().await.unwrap(), packet);
    let reply = dummy_packet(Ipv4Addr::new(192, 0, 2, 1), source);
    server.tx.lock().await.send(reply.clone()).unwrap();
    assert_eq!(client.rx.lock().await.recv().await.unwrap(), reply);
}

/// A real QUIC exchange using mock interfaces: no host TUN, routes or firewall.
/// Revocation and replacement must not reset allocations or active data paths.
#[rstest]
#[case("tls_standard")]
#[case("tls_hybrid")]
#[case("tls_postquantum")]
#[case("noise_standard")]
#[case("noise_hybrid")]
#[case("noise_postquantum")]
#[tokio::test]
async fn identity_updates_preserve_sessions_and_allocations(#[case] protocol: &str) {
    struct Server;
    struct ClientA;
    struct ClientB;
    struct ClientC;
    struct ClientD;
    let server_ch = setup_interface::<Server>();
    let client_a_ch = setup_interface::<ClientA>();
    let client_b_ch = setup_interface::<ClientB>();
    let _client_c_ch = setup_interface::<ClientC>();
    let _client_d_ch = setup_interface::<ClientD>();
    let directory = Path::new("tests/static/configs").join(protocol);
    let mut server_config =
        ServerConfig::from_path(&directory.join("server.toml"), "QUINCY_").unwrap();
    let mut client_config =
        ClientConfig::from_path(&directory.join("client.toml"), "QUINCY_").unwrap();
    // Ephemeral ports keep this test independent of other suites and instances.
    let reservation = UdpSocket::bind("[::]:0").unwrap();
    server_config.bind_port = reservation.local_addr().unwrap().port();
    client_config.connection_string = format!("localhost:{}", server_config.bind_port);
    server_config.tunnel_network = "192.0.2.1/29".parse().unwrap();
    let mut entries = IdentitySnapshot::load(&server_config.users_file)
        .unwrap()
        .users()
        .clone();
    entries.get_mut("test").unwrap().address_pool = vec!["192.0.2.2/32".parse().unwrap()];
    let initial = Arc::new(IdentitySnapshot::new(entries.clone()).unwrap());
    let (source, receiver) = watch::channel(initial.clone());
    // The custom constructor must not consult a fallback users file.
    server_config.users_file = Path::new("unused-users-file.toml").into();
    let (events, mut sessions) = mpsc::unbounded_channel();
    let server = QuincyServer::new_with_identity_provider(server_config, &Source(receiver))
        .unwrap()
        .with_observer(Arc::new(Sessions(events)));
    let mut applied = server.subscribe_identity();
    let (shutdown, stop) = oneshot::channel();
    drop(reservation);
    let task = tokio::spawn(async move {
        server
            .run_until::<TestInterface<Server>>(async {
                stop.await
                    .map_err(|_| quincy::QuincyError::system("test shutdown sender dropped"))
            })
            .await
    });

    let mut a = QuincyClient::new(client_config.clone());
    a.start::<TestInterface<ClientA>>().await.unwrap();
    assert_eq!(
        a.client_address().unwrap().addr(),
        Ipv4Addr::new(192, 0, 2, 2)
    );
    assert_eq!(sessions.recv().await.unwrap().1.username, "test");

    let mut user = entries.remove("test").unwrap();
    user.address_pool.clear();
    entries.insert("renamed".into(), user);
    publish(
        &source,
        &mut applied,
        Arc::new(IdentitySnapshot::new(entries).unwrap()),
    )
    .await;
    let mut b = QuincyClient::new(client_config.clone());
    b.start::<TestInterface<ClientB>>().await.unwrap();
    assert_eq!(
        b.client_address().unwrap().addr(),
        Ipv4Addr::new(192, 0, 2, 3)
    );
    assert_eq!(sessions.recv().await.unwrap().1.username, "renamed");

    // Explicit revocation denies NEW connections, even with the same credentials,
    // but neither resets the allocator nor terminates an existing session.
    publish(
        &source,
        &mut applied,
        Arc::new(IdentitySnapshot::new(HashMap::new()).unwrap()),
    )
    .await;
    let mut denied = QuincyClient::new(client_config.clone());
    assert!(denied.start::<TestInterface<ClientC>>().await.is_err());
    traffic(&client_a_ch, &server_ch, Ipv4Addr::new(192, 0, 2, 2)).await;
    traffic(&client_b_ch, &server_ch, Ipv4Addr::new(192, 0, 2, 3)).await;

    // Disconnect releases to the ORIGINAL user's pool, even after revocation.
    a.stop().await.unwrap();
    a.wait_for_shutdown().await.unwrap();
    let (connected, ended) = sessions.recv().await.unwrap();
    assert!(!connected);
    assert_eq!(ended.username, "test");
    publish(&source, &mut applied, initial).await;
    let mut d = QuincyClient::new(client_config);
    d.start::<TestInterface<ClientD>>().await.unwrap();
    assert_eq!(
        d.client_address().unwrap().addr(),
        Ipv4Addr::new(192, 0, 2, 2)
    );
    assert_eq!(sessions.recv().await.unwrap().1.username, "test");

    // A provider going offline is not an implicit deny-all or server shutdown.
    drop(source);
    traffic(&client_b_ch, &server_ch, Ipv4Addr::new(192, 0, 2, 3)).await;
    b.stop().await.unwrap();
    b.wait_for_shutdown().await.unwrap();
    d.stop().await.unwrap();
    d.wait_for_shutdown().await.unwrap();
    shutdown.send(()).unwrap();
    task.await.unwrap().unwrap();
}
