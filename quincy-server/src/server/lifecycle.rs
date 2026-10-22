//! Host-owned lifecycle observations, independent of any event transport.

use ipnet::IpNet;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Session {
    pub username: String,
    pub address: IpNet,
}

/// Called outside packet forwarding. Observers must only update local state;
/// external IO and error handling belong to the host's independent executor.
pub trait Observer: Send + Sync {
    fn connected(&self, session: Session);
    fn disconnected(&self, session: Session);
}
