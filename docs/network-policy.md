# Routing and DNS policy

The server can send routing and DNS settings after authenticating a client.
The client applies them through its existing privileged network component;
the server sends typed data, never commands or scripts.

Add an optional `[network]` section to the server configuration:

```toml
[network]
mode = "split"
routes = ["198.51.100.0/24", "203.0.113.0/24"]
excluded_routes = ["203.0.113.128/25"]
dns_servers = ["192.0.2.53"]
```

`split` sends only the listed networks through the tunnel. `full` sends the
tunnel's entire IP address family through it, except excluded networks:

```toml
[network]
mode = "full"
excluded_routes = ["198.51.100.0/24", "203.0.113.9/32"]
dns_servers = ["192.0.2.53"]
```

Full mode on an IPv4 tunnel covers IPv4; on an IPv6 tunnel it covers IPv6.
It does not block or capture the other address family and is not a kill switch.
Routes and exclusions must match the tunnel's address family. The VPN server's
transport address keeps its existing automatic exclusion.

Excluded networks are subtracted from the tunnel routes. Their traffic keeps
using the system's existing routes; Quincy does not replace the physical
gateway. More-specific routes already present in the OS still take precedence.
An exclusion overlapping the tunnel's own connected network is rejected.
Full mode uses two `/1` routes rather than replacing the existing default.
Exclusion subtraction may produce additional CIDRs during connection setup.

## Client preferences

Existing client configuration remains valid. Explicit nonempty local `routes`
and `dns_servers` take precedence independently over the server's settings.
If a local list is empty, the corresponding server list is used.

```toml
[network]
accept_server_routes = true
use_dns = true
```

Both options default to `true`. Set `accept_server_routes = false` to use only
local routes, including an empty list. Set `use_dns = false` to leave system
DNS unchanged, even if local or server DNS addresses are configured.
An omitted server policy leaves legacy client behavior unchanged.

Policy reception requires a client supporting this extension. Older clients
do not apply the new settings; do not rely on a pushed policy to constrain them.
The assignment envelope is limited to 16 KiB, with at most 64 routes,
64 exclusions, 16 DNS addresses and 4096 compiled tunnel CIDRs. Invalid or
oversized policy fails before configuring a client interface.

## Validation

The tests cover configuration defaults, wire compatibility, bounds, CIDR
subtraction, local overrides, DNS opt-out and authenticated policy exchange over
TLS and Noise. Exchange tests use an in-memory interface and do not change the
host's routes or DNS. Route and DNS guards retain their existing lifecycle.

Validate privileged networking separately on each target OS: connect with split
and full profiles, check a tunneled and an excluded destination, check DNS with
`use_dns` enabled and disabled, then disconnect and verify cleanup. Linux and
FreeBSD DNS configuration requires `resolvconf`; macOS uses `networksetup`.
