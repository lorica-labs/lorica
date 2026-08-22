/// Verdict a stage reached. `Continue` means it reached none and the next stage
/// decides.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action {
    Continue = 0,
    Allow = 1,
    Drop = 2,
    RateLimit = 3,
    Mark = 4,
}

impl Action {
    /// Parses a byte coming from a configuration file or a map dump. Returns `None`
    /// rather than transmuting: an out-of-range discriminant is undefined behaviour,
    /// and configuration is not a trusted source of bytes.
    pub const fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Continue),
            1 => Some(Self::Allow),
            2 => Some(Self::Drop),
            3 => Some(Self::RateLimit),
            4 => Some(Self::Mark),
            _ => None,
        }
    }
}

/// How many `(proto, port range)` couples one list entry can carry. An unbounded
/// loop over the scope list would cost helper calls and register pressure for a case
/// nobody has; past this the policy compiler tells the operator to split the prefix.
pub const SCOPE_MAX: usize = 4;

/// One `(proto, port range)` couple an entry applies to. Both bounds are inclusive.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Scope {
    pub proto: u8,
    pub port_lo: u16,
    pub port_hi: u16,
}

impl Scope {
    pub fn new(proto: u8, port_lo: u16, port_hi: u16) -> Self {
        // SAFETY: all-zero is a valid value of every field. Going through zeroed
        // rather than a struct literal also initialises the tail padding, and this
        // value is copied byte for byte into kernel memory.
        let mut scope: Self = unsafe { core::mem::zeroed() };
        scope.proto = proto;
        scope.port_lo = port_lo;
        scope.port_hi = port_hi;
        scope
    }

    pub const fn matches(&self, proto: u8, port: u16) -> bool {
        self.proto == proto && port >= self.port_lo && port <= self.port_hi
    }
}

/// Value of the unified list.
///
/// The scope lives in the value rather than in the key because an LPM_TRIE matches
/// only the first `prefix_len` bits of its key: putting proto and port in the key
/// would forbid any generic entry and would break the rule that precedence is the
/// specificity of the address.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LpmValue {
    pub action: Action,
    pub priority: u8,
    pub scope_len: u8,
    pub scopes: [Scope; SCOPE_MAX],
    pub deadline: crate::ttl::Deadline,
    pub counter_idx: u32,
}

impl LpmValue {
    pub fn zeroed() -> Self {
        // SAFETY: as in Scope::new. Action::Continue is discriminant 0, so all-zero
        // is a valid value, and this is the only construction that also initialises
        // the two padding holes this layout has.
        unsafe { core::mem::zeroed() }
    }

    /// Whether the entry applies to this `(proto, port)`. An entry with no scope
    /// applies to everything from the prefix; the policy compiler refuses that
    /// combination for `Allow`, where it would be a bare source address and a total
    /// bypass.
    pub fn applies_to(&self, proto: u8, port: u16) -> bool {
        if self.scope_len == 0 {
            return true;
        }
        // Clamped rather than trusted: scope_len is written by userspace, and an
        // out-of-range value must not become an out-of-bounds read the verifier has
        // to reason about.
        let len = if (self.scope_len as usize) < SCOPE_MAX {
            self.scope_len as usize
        } else {
            SCOPE_MAX
        };
        let mut i = 0;
        while i < len {
            if self.scopes[i].matches(proto, port) {
                return true;
            }
            i += 1;
        }
        false
    }
}
