use std::collections::HashMap;
use std::path::Path;

use quincy::Result;
use quincy::config::AddressRange;

use crate::users::{UserEntry, UsersFile};

/// Validated, immutable users and credential indices. Contains no private keys.
///
/// TLS uses the existing fingerprint-pinning semantics, not CA or certificate
/// expiry validation. Session state and allocated IP addresses are not stored here.
/// User map keys are stable allocation/session identities; renaming one creates
/// a different principal rather than moving its active connections.
#[derive(Debug)]
pub struct IdentitySnapshot {
    users: UsersFile,
}

impl IdentitySnapshot {
    /// Builds a complete snapshot, rejecting ambiguous credentials and pools.
    pub fn new(users: HashMap<String, UserEntry>) -> Result<Self> {
        Ok(Self {
            users: UsersFile::from_entries(users)?,
        })
    }

    /// Loads the existing users TOML format without retaining a writable view.
    pub fn load(path: &Path) -> Result<Self> {
        Ok(Self {
            users: UsersFile::load(path)?,
        })
    }

    /// Returns the immutable authorization records.
    pub fn users(&self) -> &HashMap<String, UserEntry> {
        &self.users.users
    }

    pub(crate) fn credentials(&self) -> &UsersFile {
        &self.users
    }

    pub(crate) fn pools(&self) -> HashMap<String, Vec<AddressRange>> {
        self.users()
            .iter()
            .filter(|(_, entry)| !entry.address_pool.is_empty())
            .map(|(name, entry)| (name.clone(), entry.address_pool.clone()))
            .collect()
    }
}
