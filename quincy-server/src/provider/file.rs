use std::path::{Path, PathBuf};
use std::sync::Arc;

use quincy::Result;
use tokio::sync::watch;

use super::{IdentityProvider, IdentitySnapshot};

/// Uses the existing users file with explicit, transactional reloads.
///
/// No file watcher or polling task is installed. A failed reload retains the
/// previous snapshot. The owner decides when to call `reload`.
pub struct FileIdentityProvider {
    path: PathBuf,
    snapshots: watch::Sender<Arc<IdentitySnapshot>>,
}

impl FileIdentityProvider {
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let initial = Arc::new(IdentitySnapshot::load(&path)?);
        let (snapshots, _) = watch::channel(initial);
        Ok(Self { path, snapshots })
    }

    /// Publishes a parsed candidate. The server independently prepares it and
    /// rejects incompatible live pool changes; observe `subscribe_identity`
    /// on the server to see successful installations.
    pub fn reload(&self) -> Result<()> {
        let snapshot = Arc::new(IdentitySnapshot::load(&self.path)?);
        self.snapshots.send_replace(snapshot);
        Ok(())
    }
}

impl IdentityProvider for FileIdentityProvider {
    fn subscribe(&self) -> Result<watch::Receiver<Arc<IdentitySnapshot>>> {
        Ok(self.snapshots.subscribe())
    }
}
