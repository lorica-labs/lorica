//! The configuration an operator writes, and nothing more. No defaulting that hides a
//! decision, no field whose meaning depends on another one.

use serde::Deserialize;

use crate::profile::ProfileKind;

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub profile: ProfileKind,

    /// Whether the mitigation may refuse traffic, or only report what it would refuse.
    ///
    /// The one default in this file that decides something, and it decides the safe
    /// direction: `observe` writes no refusal into the unified list whatever rung the
    /// ladder reaches. An operator who wants drops types the word.
    #[serde(default)]
    pub mode: Mode,

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
    /// Stage 7, and off by default for the reason above. Two sources necessarily share a
    /// leaky bucket — pigeonhole, not hashing quality — so the bank produces candidates, and
    /// arming it lets a bucket a legitimate source shares with an attacker refuse both.
    #[serde(default)]
    pub enforce_buckets: bool,
}

/// Whether what the ladder decides is applied or only reported.
///
/// **The alternative, with its number.** The policy word already carries two arming bits
/// — one for the catalogue, one for the bank — so the cheap move is a third bit for the
/// ladder and no new type. It is not that, because those two arm a *stage* of the data
/// path against traffic it classifies itself, while this arms the agent to write into the
/// list; an operator reading three bits would have to know which of them their own drop
/// came from, and an operator reading `mode = "observe"` knows that none of them can
/// produce one. The cost of the type is one field and one serde attribute.
///
/// Two variants and no `dry-run` third: `observe` *is* the dry run, and it is the default,
/// so a mode meaning "compute everything and apply nothing" would be a second spelling of
/// the same thing.
#[derive(Deserialize, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Observe,
    Armed,
}

/// The same two words the configuration file uses, for the command line.
///
/// It restates what `rename_all = "lowercase"` already says, which is one duplication and
/// the alternative is worse: the agent would either pull serde into its argument parsing to
/// read one word, or grow a second vocabulary where `--mode armed` and `mode = "armed"` could
/// drift apart. The test below fails if they ever do.
impl core::str::FromStr for Mode {
    type Err = String;

    fn from_str(word: &str) -> Result<Self, Self::Err> {
        match word {
            "observe" => Ok(Self::Observe),
            "armed" => Ok(Self::Armed),
            other => Err(format!(
                "unknown mode {other}: expected observe or armed, which are the two the agent has"
            )),
        }
    }
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

#[cfg(test)]
mod tests {
    use super::{Config, Mode};

    /// The default is the whole safety argument of the mode, so it is asserted on a file
    /// that does not mention it rather than left to the derive.
    #[test]
    fn a_configuration_that_says_nothing_observes() {
        let config = Config::from_toml("profile = \"host\"").expect("the minimal file must parse");
        assert_eq!(config.mode, Mode::Observe);
    }

    #[test]
    fn arming_is_one_word_and_a_misspelling_is_refused() {
        let armed = Config::from_toml("profile = \"host\"\nmode = \"armed\"")
            .expect("mode = armed must parse");
        assert_eq!(armed.mode, Mode::Armed);
        // Not a fallback to observe: a file that meant to arm and did not is a file the
        // operator has to be told about, and silently observing would be the mitigation
        // nobody notices is off.
        Config::from_toml("profile = \"host\"\nmode = \"enforce\"")
            .expect_err("a spelling that is neither of the two must be refused");
    }

    /// The command line and the configuration file spell arming the same way.
    ///
    /// Two parsers read the same word — serde's `rename_all` and the `FromStr` above — and
    /// nothing but this makes them agree. A drift would mean `--mode armed` arming an agent
    /// that `mode = "armed"` would not, which is the failure nobody notices until an attack.
    #[test]
    fn the_command_line_and_the_file_spell_the_modes_alike() {
        for (word, mode) in [("observe", Mode::Observe), ("armed", Mode::Armed)] {
            assert_eq!(
                word.parse::<Mode>().expect("the word is one of the two"),
                mode
            );
            let toml = format!("profile = \"host\"\nmode = \"{word}\"");
            assert_eq!(
                Config::from_toml(&toml)
                    .expect("the file spells it the same")
                    .mode,
                mode,
                "{word} parses differently on the command line and in the file"
            );
        }
        "enforce"
            .parse::<Mode>()
            .expect_err("a third spelling must be refused on the command line too");
    }
}
