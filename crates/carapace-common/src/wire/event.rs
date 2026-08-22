/// Framing of one ring buffer record. Fixed size, so the drain advances by a known
/// stride and never trusts a length it read from the record it is reading.
///
/// This phase defines the framing and emits nothing. An event per packet would make
/// the log volume O(packets) instead of O(states), and the states worth reporting
/// arrive with the tiers.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EventHeader {
    pub kind: u16,
    pub len: u16,
    pub ts_ns: u64,
}
