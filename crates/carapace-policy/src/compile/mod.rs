//! Configuration into map entries, with every refusal happening here rather than at
//! run time.
//!
//! A rule the data path cannot honour is a rule the operator has to hear about while
//! reading the file, not one that quietly does nothing under attack.

pub mod lpm;
pub mod service;

use std::collections::BTreeMap;

use carapace_common::{Action, CounterId, Deadline, LpmKey, LpmValue, SCOPE_MAX, setting};

use crate::{
    config::{ActionName, Config},
    profile::{MapSizes, MemlockModel, ProfileKind},
};

/// Everything the loader needs, and nothing it has to interpret further.
#[derive(Debug)]
pub struct Compiled {
    pub profile: ProfileKind,
    pub settings: u32,
    pub entries: Vec<(LpmKey, LpmValue)>,
    pub sizes: MapSizes,
    pub warnings: Vec<Warning>,
}

/// Something the operator probably did not mean, which is still theirs to decide.
#[derive(Debug, PartialEq, Eq)]
pub enum Warning {
    /// A forged source address costs an attacker nothing on UDP, so an allow entry
    /// scoped to UDP is a hole anybody can walk through by writing the right address
    /// in a header. It is a refusal in no configuration language: an operator behind
    /// a filtered transit link has every right to it.
    AllowOnUdp { prefix: String, scope: String },
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CompileError {
    #[error("{spec} is not an address or a prefix")]
    BadPrefix { spec: String },

    #[error("{spec} declares a {declared}-bit prefix, and the family has {width} bits")]
    PrefixTooLong {
        spec: String,
        declared: u32,
        width: u32,
    },

    #[error(
        "{spec} has bits set outside its prefix; write the network address, because \
         masking it here would accept the line and mean something else"
    )]
    PrefixHasHostBits { spec: String },

    #[error("{spec} resolves to {resolved}, which is not a scope: {kind:?}")]
    BadScope {
        spec: String,
        resolved: String,
        kind: service::BadScope,
    },

    #[error(
        "{prefix} appears more than once; merge the rules into one with several \
         scopes, because two entries on the same prefix leave the trie with no answer \
         and picking one silently is a false positive nobody can see"
    )]
    DuplicatePrefix { prefix: String },

    #[error(
        "the allow rule on {prefix} has no scope, which makes it a bare source \
         address and a total bypass on UDP; give it a protocol and a port range"
    )]
    UnscopedAllow { prefix: String },

    #[error(
        "{prefix} carries {count} scopes and the limit is {SCOPE_MAX}; split the \
         prefix, because an unbounded scope list costs helper calls and register \
         pressure in the data path for a case nobody has"
    )]
    TooManyScopes { prefix: String, count: usize },

    #[error(
        "the {profile} profile budgets {budget} bytes of locked kernel memory and \
         this configuration needs {needed}; the design does not fit in the machine, \
         and it is better to know here"
    )]
    MemlockExceeded {
        profile: ProfileKind,
        needed: u64,
        budget: u64,
    },
}

/// `now_ns` is the kernel monotonic clock, passed in rather than read here: the
/// deadlines this produces are compared against that clock in the data path, and a
/// function that reads a clock cannot be tested against a table of expectations.
pub fn compile(
    config: &Config,
    now_ns: u64,
    model: MemlockModel,
) -> Result<Compiled, CompileError> {
    let mut entries: Vec<(LpmKey, LpmValue)> = Vec::with_capacity(config.rules.len());
    let mut seen: BTreeMap<(u32, [u8; 16]), ()> = BTreeMap::new();
    let mut warnings = Vec::new();

    for rule in &config.rules {
        let key = lpm::parse_prefix(&rule.prefix)?;
        let prefix = lpm::describe(&key);

        if seen.insert((key.prefix_len, key.addr), ()).is_some() {
            return Err(CompileError::DuplicatePrefix { prefix });
        }

        let action = match rule.action {
            ActionName::Allow => Action::Allow,
            ActionName::Deny => Action::Drop,
        };

        if rule.scopes.len() > SCOPE_MAX {
            return Err(CompileError::TooManyScopes {
                prefix,
                count: rule.scopes.len(),
            });
        }
        if action == Action::Allow && rule.scopes.is_empty() {
            return Err(CompileError::UnscopedAllow { prefix });
        }

        let mut value = LpmValue::zeroed();
        value.action = action;
        value.priority = rule.priority;
        value.counter_idx = CounterId::LpmAllowExit.index();
        value.deadline = match rule.ttl_secs {
            // Only a mitigation entry is required to expire. An operator rule is
            // allowed to last as long as the file it is written in.
            None => Deadline::never(),
            Some(secs) => Deadline::after(now_ns, secs.saturating_mul(1_000_000_000)),
        };

        for (index, spec) in rule.scopes.iter().enumerate() {
            let scope = service::resolve(spec, &config.services)?;
            if action == Action::Allow && scope.proto == service::IPPROTO_UDP {
                warnings.push(Warning::AllowOnUdp {
                    prefix: prefix.clone(),
                    scope: spec.clone(),
                });
            }
            value.scopes[index] = scope;
        }
        value.scope_len = rule.scopes.len() as u8;

        entries.push((key, value));
    }

    let reserve = config
        .mitigation_reserve
        .unwrap_or_else(|| config.profile.default_mitigation_reserve());
    let sizes = MapSizes {
        unified_list_entries: (entries.len() as u32).saturating_add(reserve),
        counter_entries: CounterId::COUNT,
    };

    let needed = sizes.memlock_bytes(model);
    let budget = config.profile.memlock_budget();
    if needed > budget {
        return Err(CompileError::MemlockExceeded {
            profile: config.profile,
            needed,
            budget,
        });
    }

    Ok(Compiled {
        profile: config.profile,
        settings: settings_word(&config.settings),
        entries,
        sizes,
        warnings,
    })
}

fn settings_word(settings: &crate::config::Settings) -> u32 {
    let mut word = 0;
    if settings.accept_ip_options {
        word |= setting::ACCEPT_IP_OPTIONS;
    }
    if settings.drop_icmp_echo {
        word |= setting::DROP_ICMP_ECHO;
    }
    if settings.drop_icmp_other {
        word |= setting::DROP_ICMP_OTHER;
    }
    if settings.allow_later_fragments {
        word |= setting::ALLOW_LATER_FRAGMENTS;
    }
    word
}
