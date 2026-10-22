# quincy-forked

An unofficial fork of [Quincy](https://github.com/quincy-rs/quincy), based on
upstream 3.1.0. It supplies the VPN core used by `quincy-server-forked`.
It is not an upstream Quincy release.

```toml
quincy = { package = "quincy-forked", version = "0.0.1", default-features = false }
```

The Rust library name remains `quincy`. Configuration, QUIC, authentication
and TUN APIs retain their upstream names. The host-managed lifecycle additions
live in the companion server package; this core package keeps its type identity
consistent with that server.

Fork source: [claviron/quincy](https://github.com/claviron/quincy).
Licensed under AGPL-3.0-or-later; original Quincy attribution is preserved.
