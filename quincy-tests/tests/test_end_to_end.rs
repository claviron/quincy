mod common;

use common::{TestInterface, dummy_packet, setup_interface};
use quincy::QuincyError;
use quincy::config::{ClientConfig, FromPath, ServerConfig};
use quincy::network::interface::Interface;
use quincy_client::client::QuincyClient;
use quincy_server::server::QuincyServer;
use rstest::rstest;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::path::Path;

fn use_ephemeral_server_port(client_config: &mut ClientConfig, server_config: &mut ServerConfig) {
    let listener = TcpListener::bind(SocketAddr::new(server_config.bind_address, 0))
        .expect("reserve ephemeral server port");
    let port = listener
        .local_addr()
        .expect("read reserved server port")
        .port();

    server_config.bind_port = port;
    client_config.connection_string = format!("localhost:{port}");
}

#[rstest]
#[case("tls_standard")]
#[case("noise_standard")]
#[tokio::test]
async fn test_network_policy_exchange_and_local_preferences(
    #[case] protocol: &str,
    #[values(0, 1, 2, 3, 4)] scenario: u8,
) {
    use quincy::network_policy::{NetworkPolicy, TunnelMode, resolve_network};

    struct Client;
    struct Server;
    let client_ch = setup_interface::<Client>();
    let server_ch = setup_interface::<Server>();
    let config_dir = Path::new("tests/static/configs").join(protocol);
    let mut client_config =
        ClientConfig::from_path(&config_dir.join("client.toml"), "QUINCY_").unwrap();
    let mut server_config =
        ServerConfig::from_path(&config_dir.join("server.toml"), "QUINCY_").unwrap();
    use_ephemeral_server_port(&mut client_config, &mut server_config);
    let policy = NetworkPolicy {
        mode: if scenario == 0 {
            TunnelMode::Split
        } else {
            TunnelMode::Full
        },
        routes: vec!["198.51.100.0/24".parse().unwrap()],
        excluded_routes: vec!["198.51.100.64/26".parse().unwrap()],
        dns_servers: vec!["192.0.2.53".parse().unwrap()],
    };
    client_config.network.routes.clear();
    client_config.network.dns_servers.clear();
    server_config.network = Some(policy);
    if scenario == 2 || scenario == 4 {
        client_config.network.routes = vec!["203.0.113.0/24".parse().unwrap()];
        client_config.network.dns_servers = vec!["203.0.113.53".parse().unwrap()];
    }
    if scenario == 3 {
        client_config.network.accept_server_routes = false;
        client_config.network.use_dns = false;
    }
    if scenario == 4 {
        server_config.network = None;
    }
    let expected = resolve_network(
        &client_config.network,
        server_config.network.as_ref(),
        server_config.tunnel_network,
    )
    .unwrap();
    let mut client = QuincyClient::new(client_config);
    let server = QuincyServer::new(server_config).unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(async move {
        server
            .run_until::<TestInterface<Server>>(async {
                shutdown_rx
                    .await
                    .map_err(|_| QuincyError::system("test shutdown sender dropped"))
            })
            .await
    });
    client
        .start_with_interface::<TestInterface<Client>, _>(|config| {
            assert_eq!(config.routes, expected.routes);
            assert_eq!(config.dns_servers, expected.dns_servers);
            Interface::create(
                config.client_address,
                config.mtu,
                config.tunnel_gateway,
                config.interface_name,
                Some(config.routes),
                Some(config.dns_servers),
                Some(config.remote_address),
            )
        })
        .await
        .unwrap();

    // The control-message extension must not change data-plane packet delivery.
    let packet = match (
        client.client_address().unwrap(),
        client.server_address().unwrap(),
    ) {
        (ipnet::IpNet::V4(client), ipnet::IpNet::V4(server)) => {
            dummy_packet(client.addr(), server.addr())
        }
        _ => panic!("test fixture requires an IPv4 tunnel"),
    };
    client_ch.tx.lock().await.send(packet.clone()).unwrap();
    assert_eq!(server_ch.rx.lock().await.recv().await.unwrap(), packet);
    client.stop().await.unwrap();
    client.wait_for_shutdown().await.unwrap();
    shutdown_tx.send(()).unwrap();
    server_task.await.unwrap().unwrap();
}

#[cfg(unix)]
fn assert_fd_closed(raw_fd: std::os::fd::RawFd) {
    assert_ne!(
        raw_fd, -1,
        "test did not capture a descriptor before ownership transfer"
    );

    // SAFETY: this only queries whether the captured descriptor number still
    // refers to an open fd after ownership moved into the failed construction path.
    let flags = unsafe { libc::fcntl(raw_fd, libc::F_GETFD) };
    let errno = std::io::Error::last_os_error().raw_os_error();

    assert_eq!(flags, -1);
    assert_eq!(errno, Some(libc::EBADF));
}

#[rstest]
#[case("tests/static/configs/tls_standard")]
#[case("tests/static/configs/tls_hybrid")]
#[case("tests/static/configs/tls_postquantum")]
#[case("tests/static/configs/noise_standard")]
#[case("tests/static/configs/noise_hybrid")]
#[case("tests/static/configs/noise_postquantum")]
#[tokio::test]
async fn test_end_to_end_communication(#[case] config_dir: &str) {
    struct Client;
    struct Server;

    let client_ch = setup_interface::<Client>();
    let server_ch = setup_interface::<Server>();

    let client_config =
        ClientConfig::from_path(&Path::new(config_dir).join("client.toml"), "QUINCY_").unwrap();
    let server_config =
        ServerConfig::from_path(&Path::new(config_dir).join("server.toml"), "QUINCY_").unwrap();

    let mut client = QuincyClient::new(client_config);
    let server = QuincyServer::new(server_config).unwrap();

    let ip_server = Ipv4Addr::new(10, 0, 0, 1);
    let ip_client = Ipv4Addr::new(10, 0, 0, 2);

    tokio::spawn(async move { server.run::<TestInterface<Server>>().await.unwrap() });
    client.start::<TestInterface<Client>>().await.unwrap();

    assert_eq!(
        client.client_address().map(|addr| addr.addr()),
        Some(IpAddr::V4(ip_client))
    );
    assert_eq!(
        client.server_address().map(|addr| addr.addr()),
        Some(IpAddr::V4(ip_server))
    );

    // Test client -> server
    let test_packet = dummy_packet(ip_client, ip_server);

    client_ch.tx.lock().await.send(test_packet.clone()).unwrap();

    let recv_packet = server_ch.rx.lock().await.recv().await.unwrap();

    assert_eq!(test_packet, recv_packet);

    // Test server -> client
    let test_packet = dummy_packet(ip_server, ip_client);

    server_ch.tx.lock().await.send(test_packet.clone()).unwrap();

    let recv_packet = client_ch.rx.lock().await.recv().await.unwrap();

    assert_eq!(test_packet, recv_packet);
}

#[tokio::test]
async fn test_start_with_interface_failure_leaves_client_stopped() {
    use std::cell::Cell;

    struct Client;
    struct Server;

    let _server_ch = setup_interface::<Server>();

    let mut client_config = ClientConfig::from_path(
        Path::new("tests/static/configs/tls_standard/client.toml"),
        "QUINCY_",
    )
    .unwrap();
    let mut server_config = ServerConfig::from_path(
        Path::new("tests/static/configs/tls_standard/server.toml"),
        "QUINCY_",
    )
    .unwrap();

    use_ephemeral_server_port(&mut client_config, &mut server_config);

    let mut client = QuincyClient::new(client_config);
    let server = QuincyServer::new(server_config).unwrap();
    let create_called = Cell::new(false);

    tokio::spawn(async move { server.run::<TestInterface<Server>>().await.unwrap() });

    let result = client
        .start_with_interface::<TestInterface<Client>, _>(|interface_config| {
            create_called.set(true);

            assert_eq!(
                interface_config.client_address.addr().to_string(),
                "10.0.0.2"
            );
            assert_eq!(
                interface_config.server_address.addr().to_string(),
                "10.0.0.1"
            );
            assert_eq!(interface_config.mtu, 1400);

            Err::<Interface<TestInterface<Client>>, _>(QuincyError::system(
                "forced interface creation failure",
            ))
        })
        .await;

    assert!(result.is_err());
    assert!(create_called.get());
    assert!(!client.is_running());
    assert_eq!(client.client_address(), None);
    assert_eq!(client.server_address(), None);
}

#[cfg(unix)]
#[tokio::test]
async fn test_start_with_tun_fd_failure_closes_fd_and_leaves_client_stopped() {
    use std::cell::Cell;
    use std::fs::File;
    use std::os::fd::{AsRawFd, OwnedFd};

    struct Server;

    let _server_ch = setup_interface::<Server>();

    let mut client_config = ClientConfig::from_path(
        Path::new("tests/static/configs/tls_standard/client.toml"),
        "QUINCY_",
    )
    .unwrap();
    let mut server_config = ServerConfig::from_path(
        Path::new("tests/static/configs/tls_standard/server.toml"),
        "QUINCY_",
    )
    .unwrap();

    use_ephemeral_server_port(&mut client_config, &mut server_config);

    let mut client = QuincyClient::new(client_config);
    let server = QuincyServer::new(server_config).unwrap();
    let raw_fd = Cell::new(-1);

    tokio::spawn(async move { server.run::<TestInterface<Server>>().await.unwrap() });

    // SAFETY: the callback returns an owned fd, intentionally using a non-TUN
    // fd to exercise the rejected construction path.
    let result = unsafe {
        client
            .start_with_tun_fd(|interface_config| {
                assert_eq!(
                    interface_config.client_address.addr().to_string(),
                    "10.0.0.2"
                );
                assert_eq!(interface_config.mtu, 1400);

                let file = File::open("/dev/null").expect("open /dev/null");
                raw_fd.set(file.as_raw_fd());
                Ok::<OwnedFd, QuincyError>(file.into())
            })
            .await
    };

    assert!(result.is_err());
    assert!(!client.is_running());
    assert_eq!(client.client_address(), None);
    assert_eq!(client.server_address(), None);

    assert_fd_closed(raw_fd.get());
}
