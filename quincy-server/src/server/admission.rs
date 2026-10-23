//! A pinned credential snapshot and the matching transport authentication config.

use std::collections::HashMap;
use std::sync::Arc;

use quincy::Result;
use quincy::config::{
    AddressRange, AllowedNoiseKeys, NoiseKeyExchange, ServerConfig, ServerProtocolConfig,
};
use quincy::error::AuthError;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::provider::IdentitySnapshot;

#[cfg(test)]
mod tests;

pub(super) type Pools = HashMap<String, Vec<AddressRange>>;

pub(super) struct Admission {
    pub identity: Arc<IdentitySnapshot>,
    pub transport: Arc<quinn::ServerConfig>,
}

impl Admission {
    pub fn prepare(
        config: &ServerConfig,
        identity: Arc<IdentitySnapshot>,
        pools: &Pools,
    ) -> Result<Self> {
        Self::prepare_with_tls(config, identity, pools, None)
    }

    pub fn prepare_with_tls(
        config: &ServerConfig,
        identity: Arc<IdentitySnapshot>,
        pools: &Pools,
        tls: Option<&quincy::tls::Identity>,
    ) -> Result<Self> {
        // Allocation ownership never moves when credentials are replaced. An
        // absent user leaves their pool reserved, including any active leases.
        for (name, entry) in identity.users() {
            if pools.get(name).map(Vec::as_slice).unwrap_or_default() != entry.address_pool {
                return Err(AuthError::InvalidUserStore {
                    reason: "live address pool changes require a server restart".into(),
                }
                .into());
            }
        }

        let users = identity.credentials();
        let (keys, fingerprints) = match &config.protocol {
            ServerProtocolConfig::Noise(noise) => {
                let keys = match noise.key_exchange {
                    NoiseKeyExchange::Standard => {
                        AllowedNoiseKeys::Standard(users.collect_noise_public_keys())
                    }
                    NoiseKeyExchange::Hybrid => {
                        AllowedNoiseKeys::Hybrid(users.collect_noise_hybrid_public_keys())
                    }
                    NoiseKeyExchange::PostQuantum => {
                        AllowedNoiseKeys::PostQuantum(users.collect_noise_pq_public_keys())
                    }
                };
                (Some(keys), None)
            }
            ServerProtocolConfig::Tls(_) => (None, Some(users.collect_cert_fingerprints())),
        };
        Ok(Self {
            transport: Arc::new(match tls {
                Some(tls) => {
                    config.as_quinn_server_config_with_tls(tls, fingerprints.unwrap_or_default())?
                }
                None => config.as_quinn_server_config(keys, fingerprints)?,
            }),
            identity,
        })
    }
}

/// Owns preparation across cancelled select branches. At most one candidate is
/// built at a time; watch coalesces replacements without a retry or poll loop.
pub(super) struct Updates {
    snapshots: watch::Receiver<Arc<IdentitySnapshot>>,
    task: Option<JoinHandle<Result<Admission>>>,
    open: bool,
    config: ServerConfig,
    pools: Pools,
    pub(super) tls: Option<quincy::tls::Identity>,
}

impl Updates {
    pub fn new(
        snapshots: watch::Receiver<Arc<IdentitySnapshot>>,
        config: ServerConfig,
        pools: Pools,
    ) -> Self {
        Self {
            snapshots,
            task: None,
            open: true,
            config,
            pools,
            tls: None,
        }
    }

    pub fn is_open(&self) -> bool {
        self.open
    }

    pub async fn next(&mut self) -> Option<Result<Admission>> {
        if self.task.is_none() {
            if self.snapshots.changed().await.is_err() {
                self.open = false;
                return None;
            }
            let identity = self.snapshots.borrow_and_update().clone();
            let config = self.config.clone();
            let pools = self.pools.clone();
            let tls = self.tls.clone();
            self.task = Some(tokio::task::spawn_blocking(move || match tls.as_ref() {
                Some(tls) => Admission::prepare_with_tls(&config, identity, &pools, Some(tls)),
                None => Admission::prepare(&config, identity, &pools),
            }));
        }
        let result = self.task.as_mut().expect("preparation started").await;
        self.task.take();
        Some(
            result
                .map_err(quincy::QuincyError::from)
                .and_then(|result| result),
        )
    }

    pub async fn drain(&mut self) {
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for Updates {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
