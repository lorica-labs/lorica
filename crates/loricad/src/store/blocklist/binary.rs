//! The on-disk form of an operator blocklist, shaped so the startup path parses nothing.
//!
//! **Text is excluded on measurement, and not on the time.** Ten million CIDR lines cost
//! 563 ms to parse, which would be survivable; they cost **249 MiB of peak RSS**, which is
//! five times the whole budget of the agent, because every line is a temporary and the
//! allocator keeps the peak long after the strings are gone. The same ten million entries
//! as a pre-sorted `#[repr(C)]` array are 80 MiB the kernel maps and never copies, at
//! 7.2 ms warm. Conversion happens in `lorica-export`, off the startup path, where 249 MiB
//! for half a second is nobody's problem.
//!
//! **Native byte order, and the file says so by not saying so.** There is no endianness
//! field because a blocklist is produced by `lorica-export` on the machine that loads it;
//! carried to another architecture it has to be re-exported, and [`MAGIC`] plus
//! [`VERSION`] are what a mismatched file trips over instead of being read as garbage.
//!
//! One definition, two crates: `lorica-export` includes this file by path rather than
//! restating the layout. A writer and a reader that disagreed about it would produce a
//! wrong verdict on every address in the list, and nothing at run time would notice.

use core::mem::{align_of, size_of};

use lorica_common::Action;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// First eight bytes of the file. The trailing digit is the format generation, so a stale
/// file fails on the magic rather than on a version field a reader might not reach.
pub const MAGIC: [u8; 8] = *b"LORICAB1";

pub const VERSION: u32 = 1;

/// Sixteen bytes, and a multiple of the four [`Entry`] needs, so the entries begin aligned
/// at a fixed offset in a mapping whose base is page-aligned.
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct Header {
    pub magic: [u8; 8],
    pub version: u32,
    /// Entries that follow. `u32` caps a list at four billion prefixes, which is more than
    /// the IPv4 space holds.
    pub count: u32,
}

/// One operator prefix. Eight bytes, so ten million of them are 80 MiB.
///
/// The padding is a named field rather than left to the compiler: `IntoBytes` refuses a
/// type with implicit padding, and writing the file means turning a slice of these straight
/// into bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct Entry {
    /// The network address, host order, with the host bits already cleared by the exporter.
    pub addr: u32,
    /// 0 to 32. IPv6 has no form here: the two flat tables are IPv4 and IPv6 goes to the
    /// `LPM_TRIE` that survives, so an IPv6 prefix is refused by the exporter rather than
    /// given a representation nothing reads.
    pub prefix_len: u8,
    /// An [`Action`] discriminant.
    pub action: u8,
    pub pad: [u8; 2],
}

impl Entry {
    /// The order the file is sorted in, written once so the exporter that sorts and the
    /// reader that checks cannot drift apart. Address first, then prefix length, which puts
    /// a covering prefix immediately before the longer ones inside it.
    pub const fn key(&self) -> (u32, u8) {
        (self.addr, self.prefix_len)
    }

    /// `None` for a discriminant no [`Action`] has, which is a corrupt file rather than a
    /// choice the operator made.
    pub const fn action(&self) -> Option<Action> {
        Action::from_u8(self.action)
    }
}

pub const HEADER_BYTES: usize = size_of::<Header>();
pub const ENTRY_BYTES: usize = size_of::<Entry>();

const _: () = assert!(HEADER_BYTES == 16);
const _: () = assert!(ENTRY_BYTES == 8);
// The whole point of the format is that the mapping can be cast in place, which needs the
// entries to start aligned. A page-aligned base plus a header that is a multiple of the
// alignment is what guarantees it, and both halves are asserted so neither can drift.
const _: () = assert!(HEADER_BYTES.is_multiple_of(align_of::<Entry>()));
const _: () = assert!(align_of::<Header>() >= align_of::<Entry>());
