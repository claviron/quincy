//! Authenticated server policy and side-effect-free client network planning.
//!
//! Exclusions are subtracted from tunnel CIDRs, rather than installing routes
//! through a guessed physical gateway. Destinations outside the resulting CIDRs
//! continue to use the operating system's existing routing table.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};

use crate::config::NetworkConfig;
use crate::error::{ConfigError, Result};

/// Maximum number of route entries or exclusions in a server policy.
pub const MAX_POLICY_ROUTES: usize = 64;
/// Maximum number of DNS addresses in a server policy.
pub const MAX_POLICY_DNS: usize = 16;
/// Maximum number of CIDRs produced after exclusion subtraction.
pub const MAX_EFFECTIVE_ROUTES: usize = 4096;

/// Selects explicit networks or the tunnel's entire IP address family.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelMode {
    #[default]
    Split,
    Full,
}

/// Data sent after authentication; it never contains commands or scripts.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicy {
    #[serde(default)]
    pub mode: TunnelMode,
    #[serde(default)]
    pub routes: Vec<IpNet>,
    #[serde(default)]
    pub excluded_routes: Vec<IpNet>,
    #[serde(default)]
    pub dns_servers: Vec<IpAddr>,
}

/// Effective settings passed to the ordinary interface lifecycle.
#[derive(Debug, PartialEq, Eq)]
pub struct NetworkPlan {
    pub routes: Vec<IpNet>,
    pub dns_servers: Vec<IpAddr>,
}

fn invalid(reason: &str) -> crate::QuincyError {
    ConfigError::InvalidValue {
        field: "network".into(),
        reason: reason.into(),
    }
    .into()
}

impl NetworkPolicy {
    /// Validate both configuration and untrusted received policy before OS changes.
    pub fn validate(&self, tunnel: IpNet) -> Result<()> {
        if self.routes.len() > MAX_POLICY_ROUTES
            || self.excluded_routes.len() > MAX_POLICY_ROUTES
            || self.dns_servers.len() > MAX_POLICY_DNS
        {
            return Err(invalid("server network policy exceeds its entry limits"));
        }
        if self
            .routes
            .iter()
            .chain(&self.excluded_routes)
            .any(|route| route.addr().is_ipv4() != tunnel.addr().is_ipv4())
        {
            return Err(invalid("routes must use the tunnel's IP address family"));
        }
        // The interface's connected route cannot be removed by subtracting
        // explicit routes. Reject such exclusions instead of silently ignoring them.
        if self
            .excluded_routes
            .iter()
            .any(|route| overlaps(*route, tunnel))
        {
            return Err(invalid("an excluded route overlaps the tunnel network"));
        }
        if self.dns_servers.iter().any(|address| {
            address.is_unspecified()
                || address.is_multicast()
                || address.is_loopback()
                || matches!(address, IpAddr::V4(v4) if v4.is_broadcast())
        }) {
            return Err(invalid("DNS servers must be usable unicast addresses"));
        }
        self.tunnel_routes(tunnel)?;
        Ok(())
    }

    fn tunnel_routes(&self, tunnel: IpNet) -> Result<Vec<IpNet>> {
        let mut routes = match self.mode {
            TunnelMode::Split => self.routes.iter().map(IpNet::trunc).collect(),
            // Two /1s preserve the system default and work on all supported
            // backends, including Linux where adding a second /0 may collide.
            TunnelMode::Full => split(if tunnel.addr().is_ipv4() {
                IpNet::V4(Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).unwrap())
            } else {
                IpNet::V6(Ipv6Net::new(Ipv6Addr::UNSPECIFIED, 0).unwrap())
            })
            .to_vec(),
        };
        for excluded in &self.excluded_routes {
            let mut next = Vec::new();
            for route in routes {
                subtract(route, excluded.trunc(), &mut next)?;
            }
            routes = next;
        }
        // Aggregation may combine /1s back into /0; keep defaults split for
        // platform portability after deduplicating overlapping input routes.
        Ok(IpNet::aggregate(&routes)
            .into_iter()
            .flat_map(|route| {
                if route.prefix_len() == 0 {
                    split(route).to_vec()
                } else {
                    vec![route]
                }
            })
            .collect())
    }
}

/// Resolve local preferences without touching interfaces, routes or DNS.
/// Explicit local lists take precedence independently. No server policy keeps
/// the legacy configuration unchanged; disabling DNS overrides either source.
pub fn resolve_network(
    local: &NetworkConfig,
    policy: Option<&NetworkPolicy>,
    tunnel: IpNet,
) -> Result<NetworkPlan> {
    if let Some(policy) = policy {
        policy.validate(tunnel)?;
    }
    let routes = if !local.routes.is_empty() || !local.accept_server_routes {
        local.routes.clone()
    } else if let Some(policy) = policy {
        policy.tunnel_routes(tunnel)?
    } else {
        Vec::new()
    };
    let dns_servers = if !local.use_dns {
        Vec::new()
    } else if !local.dns_servers.is_empty() {
        local.dns_servers.clone()
    } else {
        policy
            .map(|policy| policy.dns_servers.clone())
            .unwrap_or_default()
    };
    Ok(NetworkPlan {
        routes,
        dns_servers,
    })
}

fn overlaps(a: IpNet, b: IpNet) -> bool {
    a.contains(&b.network()) || b.contains(&a.network())
}

fn split(network: IpNet) -> [IpNet; 2] {
    match network {
        IpNet::V4(network) => {
            let prefix = network.prefix_len() + 1;
            let base = u32::from(network.network());
            [base, base | (1 << (32 - prefix))].map(|address| {
                Ipv4Net::new(Ipv4Addr::from(address), prefix)
                    .unwrap()
                    .into()
            })
        }
        IpNet::V6(network) => {
            let prefix = network.prefix_len() + 1;
            let base = u128::from(network.network());
            [base, base | (1 << (128 - prefix))].map(|address| {
                Ipv6Net::new(Ipv6Addr::from(address), prefix)
                    .unwrap()
                    .into()
            })
        }
    }
}

fn subtract(route: IpNet, excluded: IpNet, output: &mut Vec<IpNet>) -> Result<()> {
    if excluded.contains(&route.network()) && excluded.prefix_len() <= route.prefix_len() {
        return Ok(());
    }
    if !overlaps(route, excluded) {
        if output.len() == MAX_EFFECTIVE_ROUTES {
            return Err(invalid("excluded routes produce too many tunnel routes"));
        }
        output.push(route);
    } else {
        for half in split(route) {
            subtract(half, excluded, output)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use figment::{
        Figment,
        providers::{Format, Toml},
    };

    #[test]
    fn network_policy_toml_preserves_legacy_client_defaults() {
        let config: NetworkConfig = Figment::new()
            .merge(Toml::string(
                "routes = [\"203.0.113.0/24\"]\ndns_servers = [\"192.0.2.53\"]",
            ))
            .extract()
            .unwrap();
        assert!(config.accept_server_routes && config.use_dns);
        assert_eq!(config.routes, vec![net("203.0.113.0/24")]);
        assert_eq!(config.dns_servers, vec![address("192.0.2.53")]);
    }

    #[test]
    fn network_policy_toml_accepts_server_policy_and_client_opt_out() {
        let policy: NetworkPolicy = Figment::new().merge(Toml::string(
            "mode = \"full\"\nexcluded_routes = [\"203.0.113.0/24\"]\ndns_servers = [\"192.0.2.53\"]"
        )).extract().unwrap();
        assert_eq!(policy.mode, TunnelMode::Full);
        policy.validate(net("192.0.2.1/24")).unwrap();
        let config: NetworkConfig = Figment::new()
            .merge(Toml::string(
                "accept_server_routes = false\nuse_dns = false",
            ))
            .extract()
            .unwrap();
        assert!(!config.accept_server_routes && !config.use_dns);
    }

    fn net(value: &str) -> IpNet {
        value.parse().unwrap()
    }
    fn address(value: &str) -> IpAddr {
        value.parse().unwrap()
    }
    fn routed(plan: &NetworkPlan, value: &str) -> bool {
        plan.routes
            .iter()
            .any(|route| route.contains(&address(value)))
    }
    fn full() -> NetworkPolicy {
        NetworkPolicy {
            mode: TunnelMode::Full,
            ..NetworkPolicy::default()
        }
    }

    #[test]
    fn network_policy_defaults_preserve_legacy_settings() {
        let local = NetworkConfig::default();
        let plan = resolve_network(&local, None, net("192.0.2.1/24")).unwrap();
        assert!(plan.routes.is_empty());
        assert!(plan.dns_servers.is_empty());
        assert!(local.use_dns && local.accept_server_routes);
    }

    #[test]
    fn network_policy_split_subtracts_exclusions_and_deduplicates() {
        let policy = NetworkPolicy {
            routes: vec![net("198.51.100.7/24"), net("198.51.100.0/25")],
            excluded_routes: vec![net("198.51.100.64/26"), net("198.51.100.90/32")],
            dns_servers: vec![address("192.0.2.1")],
            ..NetworkPolicy::default()
        };
        let plan = resolve_network(
            &NetworkConfig::default(),
            Some(&policy),
            net("192.0.2.1/24"),
        )
        .unwrap();
        assert_eq!(
            plan.routes,
            vec![net("198.51.100.0/26"), net("198.51.100.128/25")]
        );
        assert!(!routed(&plan, "198.51.100.90"));
        assert!(!routed(&plan, "203.0.113.1"));
        assert_eq!(plan.dns_servers, policy.dns_servers);
    }

    #[test]
    fn network_policy_full_ipv4_preserves_excluded_networks() {
        let policy = NetworkPolicy {
            excluded_routes: vec![net("198.51.100.0/24"), net("203.0.113.9/32")],
            ..full()
        };
        let plan = resolve_network(
            &NetworkConfig::default(),
            Some(&policy),
            net("192.0.2.1/24"),
        )
        .unwrap();
        assert!(!routed(&plan, "198.51.100.0"));
        assert!(!routed(&plan, "198.51.100.255"));
        assert!(!routed(&plan, "203.0.113.9"));
        assert!(routed(&plan, "203.0.113.8"));
        assert!(routed(&plan, "203.0.113.10"));
        assert!(routed(&plan, "0.0.0.0"));
        assert!(routed(&plan, "255.255.255.255"));
        assert!(!routed(&plan, "2001:db8::1"));
    }

    #[test]
    fn network_policy_full_keeps_default_routes_split() {
        let plan = resolve_network(
            &NetworkConfig::default(),
            Some(&full()),
            net("192.0.2.1/24"),
        )
        .unwrap();
        assert_eq!(plan.routes, vec![net("0.0.0.0/1"), net("128.0.0.0/1")]);
    }

    #[test]
    fn network_policy_full_ipv6_excludes_single_address() {
        let policy = NetworkPolicy {
            excluded_routes: vec![net("2001:db8:1::1/128")],
            ..full()
        };
        let plan = resolve_network(
            &NetworkConfig::default(),
            Some(&policy),
            net("2001:db8:2::1/64"),
        )
        .unwrap();
        assert!(!routed(&plan, "2001:db8:1::1"));
        assert!(routed(&plan, "2001:db8:1::"));
        assert!(routed(&plan, "2001:db8:1::2"));
        assert!(routed(&plan, "::"));
        assert!(routed(&plan, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"));
    }

    #[test]
    fn network_policy_explicit_local_lists_override_server_independently() {
        let policy = NetworkPolicy {
            dns_servers: vec![address("192.0.2.1")],
            ..full()
        };
        let mut local = NetworkConfig {
            routes: vec![net("203.0.113.0/24")],
            ..NetworkConfig::default()
        };
        let plan = resolve_network(&local, Some(&policy), net("192.0.2.1/24")).unwrap();
        assert_eq!(plan.routes, local.routes);
        assert_eq!(plan.dns_servers, policy.dns_servers);
        local.dns_servers = vec![address("203.0.113.53")];
        let plan = resolve_network(&local, Some(&policy), net("192.0.2.1/24")).unwrap();
        assert_eq!(plan.dns_servers, local.dns_servers);
        local.routes.clear();
        let plan = resolve_network(&local, Some(&policy), net("192.0.2.1/24")).unwrap();
        assert_eq!(plan.routes.len(), 2);
        assert_eq!(plan.dns_servers, local.dns_servers);
    }

    #[test]
    fn network_policy_client_can_refuse_routes_and_dns() {
        let policy = NetworkPolicy {
            dns_servers: vec![address("192.0.2.1")],
            ..full()
        };
        let local = NetworkConfig {
            accept_server_routes: false,
            use_dns: false,
            dns_servers: vec![address("203.0.113.53")],
            ..NetworkConfig::default()
        };
        let plan = resolve_network(&local, Some(&policy), net("192.0.2.1/24")).unwrap();
        assert!(plan.routes.is_empty());
        assert!(plan.dns_servers.is_empty());
    }

    #[test]
    fn network_policy_without_server_keeps_explicit_local_lists() {
        let local = NetworkConfig {
            routes: vec![net("203.0.113.0/24")],
            dns_servers: vec![address("203.0.113.53")],
            ..NetworkConfig::default()
        };
        let plan = resolve_network(&local, None, net("192.0.2.1/24")).unwrap();
        assert_eq!(plan.routes, local.routes);
        assert_eq!(plan.dns_servers, local.dns_servers);
    }

    #[test]
    fn network_policy_rejects_mixed_families_and_connected_exclusions() {
        for policy in [
            NetworkPolicy {
                routes: vec![net("2001:db8::/32")],
                ..full()
            },
            NetworkPolicy {
                excluded_routes: vec![net("2001:db8::/32")],
                ..full()
            },
            NetworkPolicy {
                excluded_routes: vec![net("192.0.2.9/32")],
                ..full()
            },
            NetworkPolicy {
                excluded_routes: vec![net("0.0.0.0/0")],
                ..full()
            },
        ] {
            assert!(policy.validate(net("192.0.2.1/24")).is_err());
        }
    }

    #[test]
    fn network_policy_rejects_excessive_entries_and_invalid_dns() {
        for policy in [
            NetworkPolicy {
                routes: vec![net("203.0.113.0/24"); MAX_POLICY_ROUTES + 1],
                ..full()
            },
            NetworkPolicy {
                excluded_routes: vec![net("203.0.113.0/24"); MAX_POLICY_ROUTES + 1],
                ..full()
            },
            NetworkPolicy {
                dns_servers: vec![address("192.0.2.53"); MAX_POLICY_DNS + 1],
                ..full()
            },
        ] {
            assert!(policy.validate(net("192.0.2.1/24")).is_err());
        }
        for value in [
            "0.0.0.0",
            "127.0.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "ff02::1",
        ] {
            let policy = NetworkPolicy {
                dns_servers: vec![address(value)],
                ..full()
            };
            assert!(policy.validate(net("192.0.2.1/24")).is_err());
        }
    }

    #[test]
    fn network_policy_bounds_expanded_routes() {
        let mut output = vec![net("203.0.113.0/24"); MAX_EFFECTIVE_ROUTES];
        assert!(subtract(net("198.51.100.0/24"), net("192.0.2.0/24"), &mut output).is_err());
    }

    #[test]
    fn network_policy_ipv6_churn_cannot_exceed_route_bound() {
        // Spread exclusions over the full address space, forcing long, mostly
        // disjoint prefix paths instead of a small adjacent aggregate.
        let policy = NetworkPolicy {
            excluded_routes: (1..=MAX_POLICY_ROUTES)
                .map(|index| {
                    let address = Ipv6Addr::from((index as u128) << 120 | 1);
                    Ipv6Net::new(address, 128).unwrap().into()
                })
                .collect(),
            ..full()
        };
        assert!(policy.validate(net("2001:db8::1/64")).is_err());
    }

    #[test]
    fn network_policy_subtraction_matches_all_addresses_in_small_network() {
        for excluded_prefix in 24..=32 {
            let policy = NetworkPolicy {
                routes: vec![net("203.0.113.0/24")],
                excluded_routes: vec![net(&format!("203.0.113.64/{excluded_prefix}"))],
                ..NetworkPolicy::default()
            };
            let plan = resolve_network(
                &NetworkConfig::default(),
                Some(&policy),
                net("192.0.2.1/24"),
            )
            .unwrap();
            for last in 0..=255 {
                let ip = address(&format!("203.0.113.{last}"));
                assert_eq!(
                    plan.routes.iter().any(|route| route.contains(&ip)),
                    !policy.excluded_routes[0].contains(&ip)
                );
            }
        }
    }
}
