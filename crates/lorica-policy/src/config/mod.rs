//! The configuration an operator writes, and nothing more. No defaulting that hides a
//! decision, no field whose meaning depends on another one.

use serde::Deserialize;

use crate::profile::ProfileKind;

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub profile: ProfileKind,

    #[serde(default)]
    pub settings: Settings,

    /// Named scopes, so `udp:30120` is written once rather than on twenty rules. A
    /// rule refers to a name or states a scope literally.
    #[serde(default)]
    pub services: std::collections::BTreeMap<String, String>,

    /// Room in the unified list for entries the mitigation adds while running.
    /// Defaults to the value of the profile.
    #[serde(default)]
    pub mitigation_reserve: Option<u32>,

    /// The vectors of the signature catalogue stage 6 carries, named by their counter
    /// without the `signature_` prefix.
    ///
    /// Absent is the whole catalogue. An empty list is none of it, and the two cannot share
    /// a spelling: a vector left out is not in the loaded program at all, so a list that
    /// silently meant "everything" when the operator wrote "nothing" would be the one
    /// mistake in this file nobody can see from the outside.
    #[serde(default)]
    pub signatures: Option<Vec<String>>,

    #[serde(default)]
    pub rules: Vec<Rule>,
}

/// The policy bits, spelled out. They compile into the one word the program reads at
/// load time.
#[derive(Deserialize, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// IP options are refused by default; this says otherwise.
    #[serde(default)]
    pub accept_ip_options: bool,
    #[serde(default)]
    pub drop_icmp_echo: bool,
    #[serde(default)]
    pub drop_icmp_other: bool,
    /// Later fragments are dropped by default because they carry no port and can
    /// never match a scope. Turning this on accepts the degraded key that comes with
    /// them, and is what fragmented IPsec or IKE traffic needs.
    #[serde(default)]
    pub allow_later_fragments: bool,
    /// Stage 6 counts its vectors and delivers the packet until this is set. Observation
    /// is the default because a catalogue nobody has watched run against their own
    /// traffic is a list of false positives waiting to be found by an outage.
    #[serde(default)]
    pub enforce_signatures: bool,
}

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ActionName {
    Allow,
    Deny,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// `10.90.1.0/24` or `2001:db8::/32`. A bare address is taken as a single host.
    pub prefix: String,
    pub action: ActionName,

    /// Service names or literal `proto:ports` scopes. An allow rule with none is
    /// refused, because a bare source address is a total bypass.
    #[serde(default)]
    pub scopes: Vec<String>,

    /// Breaks ties between entries the operator wrote and entries the mitigation adds
    /// on the same prefix while running. It settles nothing in this phase, where two
    /// entries on the same prefix are refused outright.
    #[serde(default)]
    pub priority: u8,

    /// Absent means permanent. Only mitigation entries are required to expire; an
    /// operator rule is allowed to be as durable as the configuration file.
    #[serde(default)]
    pub ttl_secs: Option<u64>,
}

impl Config {
    pub fn from_toml(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }
}
