//! Native TUN routes are owned by their interface, not by a shared gateway IP.

use super::{InstalledExclusionRoute, posix};
use crate::Result;
use crate::error::RouteError;
use crate::utils::command::run_command;
use ipnet::IpNet;
use std::net::IpAddr;
use std::process::Output;
use tracing::warn;

pub(crate) trait Command {
    fn run(&self, args: &[String]) -> Result<Output>;
}

#[derive(Clone, Copy)]
pub(crate) struct System;

impl Command for System {
    fn run(&self, args: &[String]) -> Result<Output> {
        Ok(run_command("/sbin/route", args)?.wait_with_output()?)
    }
}

/// Scoped routes are mandatory even when another tunnel owns the same prefix.
/// Unscoped routes are installed only when vacant, for ordinary unbound traffic.
/// They remain attached to the TUN and the kernel removes them on device close;
/// deleting them by destination could remove a replacement owned by someone else.
pub(crate) struct Routes<C: Command = System> {
    interface: String,
    address: Option<IpAddr>,
    installed: Vec<IpNet>,
    command: C,
}

impl Routes {
    pub(crate) fn new(interface: String, address: IpNet) -> Result<Self> {
        let mut routes = Self {
            interface,
            address: Some(address.addr()),
            installed: Vec::new(),
            command: System,
        };
        routes.install(&address.trunc())?;
        Ok(routes)
    }
}

/// Installs routes for a caller-owned interface. As with the native wrapper,
/// ordinary routes live until that interface closes; the returned token owns
/// only the optional exclusion route on the physical network.
pub fn add_routes(
    networks: &[IpNet],
    _gateway: &IpAddr,
    tunnel_interface: &str,
    remote: Option<IpAddr>,
) -> Result<Option<InstalledExclusionRoute>> {
    let mut routes = Routes {
        interface: tunnel_interface.into(),
        address: None,
        installed: Vec::new(),
        command: System,
    };
    let result = routes.configure(networks, remote)?;
    routes.installed.clear();
    Ok(result)
}

impl<C: Command + Clone> Routes<C> {
    pub(crate) fn configure(
        &mut self,
        networks: &[IpNet],
        remote: Option<IpAddr>,
    ) -> Result<Option<InstalledExclusionRoute>> {
        let mut batch = Self {
            interface: self.interface.clone(),
            address: self.address,
            installed: Vec::new(),
            command: self.command.clone(),
        };
        let exclusion = posix::add_routes_with(networks, &self.interface, remote, |network| {
            let network = network.trunc();
            // The connected prefix already supplies these on-link routes. In
            // particular, do not recreate a peer host-route owned by the kernel.
            if self.installed.iter().any(|existing| {
                existing.prefix_len() <= network.prefix_len()
                    && existing.contains(&network.network())
            }) {
                return Ok(());
            }
            batch.install(&network)
        })?;
        self.installed.append(&mut batch.installed);
        Ok(exclusion)
    }
}

impl<C: Command> Routes<C> {
    fn args(&self, action: &str, network: &IpNet, scoped: bool) -> Vec<String> {
        let mut args = vec!["-n".into(), action.into()];
        if network.addr().is_ipv6() {
            args.push("-inet6".into());
        }
        args.extend([
            "-net".into(),
            network.trunc().to_string(),
            "-interface".into(),
            self.interface.clone(),
        ]);
        if let Some(address) = self.address
            && network.addr().is_ipv4() == address.is_ipv4()
        {
            args.extend(["-ifa".into(), address.to_string()]);
        }
        if scoped {
            args.extend(["-ifscope".into(), self.interface.clone()]);
        }
        args
    }

    fn install(&mut self, network: &IpNet) -> Result<()> {
        if self.installed.contains(network) {
            return Ok(());
        }
        let scoped = self.command.run(&self.args("add", network, true))?;
        check_output(&scoped, network, false)?;
        self.installed.push(*network);

        let primary = self.command.run(&self.args("add", network, false))?;
        // A foreign unscoped route is never adopted or changed. The scoped
        // route above still guarantees this interface has its own usable path.
        check_output(&primary, network, true)
    }

    pub(crate) fn clear(&mut self) {
        while let Some(network) = self.installed.pop() {
            match self.command.run(&self.args("delete", &network, true)) {
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    if !stderr.contains("not in table")
                        && let Err(error) = check_output(&output, &network, false)
                    {
                        warn!(%error, interface = self.interface, "Failed to remove TUN route");
                    }
                }
                Err(error) => {
                    warn!(%error, interface = self.interface, "Failed to remove TUN route")
                }
            }
        }
    }
}

impl<C: Command> Drop for Routes<C> {
    fn drop(&mut self) {
        self.clear();
    }
}

fn check_output(output: &Output, network: &IpNet, allow_existing: bool) -> Result<()> {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let already_exists = stderr.contains("File exists") || stdout.contains("File exists");
    if allow_existing && already_exists {
        return Ok(());
    }
    // Darwin's route utility can exit zero even when the routing socket write
    // failed. A successful process exit alone is not a successful route install.
    if !output.status.success() || !stderr.trim().is_empty() || already_exists {
        return Err(RouteError::AddFailed {
            destination: network.to_string(),
            message: format!("{} {}", stderr.trim(), stdout.trim())
                .trim()
                .to_string(),
        }
        .into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::os::unix::process::ExitStatusExt;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Fake {
        calls: Arc<Mutex<Vec<Vec<String>>>>,
        replies: Arc<Mutex<VecDeque<Output>>>,
    }

    impl Command for Fake {
        fn run(&self, args: &[String]) -> Result<Output> {
            self.calls.lock().unwrap().push(args.to_vec());
            Ok(self
                .replies
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| output("", "")))
        }
    }

    fn output(stdout: &str, stderr: &str) -> Output {
        Output {
            status: std::process::ExitStatus::from_raw(0),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    fn routes(command: Fake) -> Routes<Fake> {
        Routes {
            interface: "utun42".into(),
            address: Some("192.0.2.2".parse().unwrap()),
            installed: Vec::new(),
            command,
        }
    }

    #[test]
    fn routes_are_scoped_and_include_the_local_interface_address() {
        let routes = routes(Fake::default());
        assert_eq!(
            routes.args("add", &"192.0.2.0/24".parse().unwrap(), true),
            [
                "-n",
                "add",
                "-net",
                "192.0.2.0/24",
                "-interface",
                "utun42",
                "-ifa",
                "192.0.2.2",
                "-ifscope",
                "utun42",
            ]
        );
        assert!(
            routes
                .args("add", &"2001:db8::/64".parse().unwrap(), true)
                .contains(&"-inet6".into())
        );
    }

    #[test]
    fn zero_exit_with_route_error_is_a_failure() {
        let network = "192.0.2.0/24".parse().unwrap();
        assert!(
            check_output(
                &output(
                    "add net",
                    "route: writing to routing socket: Network is unreachable"
                ),
                &network,
                false
            )
            .is_err()
        );
    }

    #[test]
    fn foreign_primary_route_is_not_adopted_or_removed() {
        let fake = Fake::default();
        fake.replies.lock().unwrap().extend([
            output("", ""),
            output("", "route: writing to routing socket: File exists"),
        ]);
        let mut routes = routes(fake.clone());
        let network = "192.0.2.0/24".parse().unwrap();
        routes.install(&network).unwrap();
        routes.install(&network).unwrap();
        drop(routes);
        let calls = fake.calls.lock().unwrap();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[2][1], "delete");
        assert!(calls[2].contains(&"-ifscope".into()));
    }

    #[test]
    fn failed_primary_install_rolls_back_the_scoped_route() {
        let fake = Fake::default();
        fake.replies
            .lock()
            .unwrap()
            .extend([output("", ""), output("", "route: permission denied")]);
        let mut routes = routes(fake.clone());
        assert!(routes.install(&"192.0.2.0/24".parse().unwrap()).is_err());
        drop(routes);
        let calls = fake.calls.lock().unwrap();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[2][1], "delete");
    }

    #[test]
    fn existing_scoped_route_is_an_error_and_is_not_owned() {
        let fake = Fake::default();
        fake.replies
            .lock()
            .unwrap()
            .push_back(output("File exists", ""));
        let mut routes = routes(fake.clone());
        assert!(routes.install(&"192.0.2.0/24".parse().unwrap()).is_err());
        drop(routes);
        assert_eq!(fake.calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn failed_batch_removes_only_new_scoped_routes() {
        let fake = Fake::default();
        let mut routes = routes(fake.clone());
        routes.install(&"192.0.2.0/24".parse().unwrap()).unwrap();
        fake.calls.lock().unwrap().clear();
        fake.replies.lock().unwrap().extend([
            output("", ""),
            output("", ""),
            output(
                "",
                "route: writing to routing socket: Network is unreachable",
            ),
        ]);
        assert!(
            routes
                .configure(
                    &[
                        "198.51.100.0/24".parse().unwrap(),
                        "203.0.113.0/24".parse().unwrap(),
                    ],
                    None
                )
                .is_err()
        );
        assert_eq!(routes.installed, ["192.0.2.0/24".parse::<IpNet>().unwrap()]);
        let calls = fake.calls.lock().unwrap();
        assert_eq!(calls.len(), 4);
        assert_eq!(calls[3][1], "delete");
        assert_eq!(calls[3][3], "198.51.100.0/24");
        drop(calls);
    }

    #[test]
    fn overlapping_interfaces_do_not_remove_each_others_routes() {
        let fake = Fake::default();
        let mut first = routes(fake.clone());
        let mut second = routes(fake.clone());
        second.interface = "utun43".into();
        let network = "192.0.2.0/24".parse().unwrap();
        first.install(&network).unwrap();
        second.install(&network).unwrap();
        fake.calls.lock().unwrap().clear();
        drop(first);
        let calls = fake.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].last().unwrap(), "utun42");
        assert_eq!(second.installed, [network]);
        drop(calls);
    }

    #[test]
    fn connected_prefix_does_not_reinstall_peer_or_duplicate_routes() {
        let fake = Fake::default();
        let mut routes = routes(fake.clone());
        routes.install(&"192.0.2.0/24".parse().unwrap()).unwrap();
        fake.calls.lock().unwrap().clear();
        routes
            .configure(
                &[
                    "192.0.2.1/32".parse().unwrap(),
                    "192.0.2.0/24".parse().unwrap(),
                ],
                None,
            )
            .unwrap();
        assert!(fake.calls.lock().unwrap().is_empty());
    }
}
