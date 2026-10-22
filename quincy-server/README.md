# quincy-server-forked

An unofficial fork of [Quincy](https://github.com/quincy-rs/quincy), based on
upstream 3.1.0, for embedding a VPN server in a host-owned runtime.
It is not an upstream Quincy release.

```toml
quincy-server = { package = "quincy-server-forked", version = "0.0.1", default-features = false }
```

The Rust library name remains `quincy_server`. The companion core dependency
is `quincy-forked`, so client and server integrations must use that same core
package when exchanging Quincy types.

## Lifecycle additions

- `server::lifecycle::Observer` receives connected/disconnected observations
  with the authenticated username and assigned tunnel address.
- `QuincyServer::with_observer` installs an observer before starting IO.
- `QuincyServer::run_until` accepts the host's shutdown future without
  installing another process signal handler.
- The ordinary `run` entry point retains stand-alone signal handling.
- Server shutdown closes admission and drains its owned connections before
  releasing the TUN interface.

Observers are synchronous local bookkeeping hooks, not an IO execution path.
Send external commands through a separately owned executor. The host supplies
TUN privileges, configuration and credentials; this package grants none.

Fork source: [claviron/quincy](https://github.com/claviron/quincy).
Licensed under AGPL-3.0-or-later; original Quincy attribution is preserved.
