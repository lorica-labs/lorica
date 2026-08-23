//! Throwaway interfaces for the tests that need a real attach.
//!
//! Synthetic rather than real, because nothing depends on them: a test that leaves a
//! program attached breaks nothing outside itself. The three constructors answer three
//! different questions and are not interchangeable.

use std::process::Command;

/// Runs `ip` and returns whatever it complained about.
pub fn ip(args: &[&str]) -> Result<(), String> {
    let out = Command::new("ip")
        .args(args)
        .output()
        .map_err(|err| format!("cannot run ip: {err}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_owned())
    }
}

/// The XDP mode `ip -d link show` renders, which is the only thing that attests a native
/// attach: on kernel 6.8 an attach disables not one virtio offload, so a diff of
/// `ethtool -k` proves nothing either way.
pub fn ip_link_mode(iface: &str) -> String {
    let out = Command::new("ip")
        .args(["-d", "link", "show", iface])
        .output()
        .expect("cannot run ip -d link show");
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .find(|word| word.starts_with("xdp"))
        .unwrap_or("none")
        .to_owned()
}

/// The kernel index of an interface, which is what `xdp_md` carries and what
/// `bpf_fib_lookup` is asked about. Read from sysfs rather than parsed out of `ip`, which
/// renders it as a prefix of a line and not as a field.
pub fn ifindex(iface: &str) -> u32 {
    let path = format!("/sys/class/net/{iface}/ifindex");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("cannot read {path}: {err}"))
        .trim()
        .parse()
        .expect("sysfs reported an ifindex that is not a number")
}

/// An interface, up, deleted when the test ends however it ends.
///
/// A `veth` supports native XDP, which a test of native attach cannot do without. A
/// `dummy` has no `ndo_bpf` at all, which is the only honest way to reach the refusal for
/// a driver that cannot do native mode: `lo` looks like a candidate and is not, because an
/// overlay agent is usually already holding its generic hook and then the kernel refuses
/// for the other reason entirely.
pub struct Link {
    pub name: String,
    /// Set only by [`Link::wired`]. The peer lives here, and it is deleted with the link.
    netns: Option<String>,
}

impl Link {
    pub fn veth(name: &str) -> Self {
        let peer = peer_of(name);
        let link = Self::add(name, &["type", "veth", "peer", "name", &peer]);
        ip(&["link", "set", &peer, "up"]).expect("bringing the peer up failed");
        link
    }

    pub fn dummy(name: &str) -> Self {
        Self::add(name, &["type", "dummy"])
    }

    /// A veth whose peer lives in its own network namespace, both sides addressed inside
    /// `10.90.<octet>.0/24`. Returns the link and the address to send *to*.
    ///
    /// The namespace is not tidiness, it is the only way to make packets cross. With both
    /// addresses in one namespace the kernel delivers locally, nothing reaches the wire,
    /// an XDP program on the interface sees nothing, and every count reads zero — which is
    /// indistinguishable from a clean run. That is the false pass this constructor exists
    /// to prevent.
    pub fn wired(name: &str, octet: u8) -> (Self, String) {
        let peer = peer_of(name);
        let netns = format!("{name}-ns");
        let near = format!("10.90.{octet}.1");
        let far = format!("10.90.{octet}.2");

        let mut link = Self::veth(name);
        let _ = ip(&["netns", "del", &netns]);
        ip(&["netns", "add", &netns]).expect("creating the namespace failed");
        link.netns = Some(netns.clone());
        ip(&["link", "set", &peer, "netns", &netns]).expect("moving the peer failed");

        ip(&["addr", "add", &format!("{near}/24"), "dev", name])
            .expect("addressing the link failed");
        link.in_netns(&["ip", "addr", "add", &format!("{far}/24"), "dev", &peer])
            .expect("addressing the peer failed");
        link.in_netns(&["ip", "link", "set", &peer, "up"])
            .expect("bringing the peer up failed");

        (link, near)
    }

    /// Runs a command inside the peer namespace, which is where traffic has to come from:
    /// packets sent from the near side would be delivered locally and never cross.
    pub fn in_netns(&self, argv: &[&str]) -> Result<(), String> {
        let netns = self.netns.as_deref().expect("this link has no namespace");
        let out = Command::new("ip")
            .args(["netns", "exec", netns])
            .args(argv)
            .output()
            .map_err(|err| format!("cannot run ip netns exec: {err}"))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout).trim(),
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    }

    fn add(name: &str, kind: &[&str]) -> Self {
        assert!(name.len() <= 14, "an interface name is at most 15 bytes");
        // A previous run killed between the attach and the delete leaves the interface
        // behind, and `ip link add` then fails on a name that is nobody fault but ours.
        let _ = ip(&["link", "del", name]);
        let mut args = vec!["link", "add", name];
        args.extend_from_slice(kind);
        ip(&args).expect("creating the interface failed");
        ip(&["link", "set", name, "up"]).expect("bringing the interface up failed");
        Self {
            name: name.to_owned(),
            netns: None,
        }
    }
}

impl Drop for Link {
    fn drop(&mut self) {
        let _ = ip(&["link", "del", &self.name]);
        if let Some(netns) = &self.netns {
            let _ = ip(&["netns", "del", netns]);
        }
    }
}

fn peer_of(name: &str) -> String {
    format!("{name}p")
}
