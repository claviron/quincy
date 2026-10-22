//! Replaceable sources of immutable VPN identity and authorization snapshots.
//!
//! Providers publish complete snapshots locally. They do not perform remote IO
//! during authentication. Publication affects future admissions, not live sessions.

mod file;
mod snapshot;

#[cfg(test)]
mod tests;

pub use file::FileIdentityProvider;
pub use snapshot::IdentitySnapshot;

use std::sync::Arc;

use quincy::Result;
use tokio::sync::watch;

/// Supplies an initial snapshot and event-driven replacements.
///
/// A receiver always contains a valid initial value. Closing the sender leaves
/// the last snapshot installed; it does not mean revoke all access. Publish an
/// empty snapshot explicitly to deny future admissions. Source freshness and
/// persistence are the provider owner's responsibility.
pub trait IdentityProvider: Send + Sync {
    fn subscribe(&self) -> Result<watch::Receiver<Arc<IdentitySnapshot>>>;
}
