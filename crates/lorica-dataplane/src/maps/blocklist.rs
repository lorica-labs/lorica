//! Publishing the two flat blocklist tables into the kernel, in one system call.
//!
//! `CLASS24` and `OA_TABLE` are `.bss` globals rather than maps, which is the whole reason
//! the legitimate path costs an `LDX` instead of a lookup. aya materialises a data section as
//! an `ARRAY` of one entry whose value is the entire section, so publishing a blocklist of any
//! size is **one** `bpf_map_update_elem` against that entry — not one call per prefix, and not
//! a batch whose cost grows with the list. `blocklist_equivalence.rs` measures that claim; this
//! module is what production does with it.
//!
//! **The offsets are read off the ELF and never written down.** Where the linker put the two
//! symbols inside the section is the linker's business, and a constant here that guessed right
//! today would publish a blocklist into the wrong twenty megabytes after an unrelated global
//! moved. The object the agent loads is the object it reads them from.
//!
//! **The write reaches an attached program, and that is intended.** The kernel copies the value
//! without stopping the data path, so a packet can read a slot mid-copy. That is what the
//! fingerprint in the `OA_TABLE` tag is for: a torn slot fails its own consistency check and is
//! treated as empty, so the failure mode of a live reload is a missed refusal and never a
//! wrong one.

use std::{
    io,
    os::fd::{AsRawFd, BorrowedFd},
};

use lorica_common::blocklist::{CLASS24_BYTES, CLASS24_SYMBOL, OA_BYTES, OA_TABLE_SYMBOL, OaSlot};
use object::{Object, ObjectSection, ObjectSymbol};

/// The name aya gives the data section it materialises as a map.
pub const SECTION: &str = ".bss";

const BPF_MAP_UPDATE_ELEM: libc::c_long = 2;

/// Where the two tables sit inside the one section they share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Section {
    /// The whole section, which is the value size of the map holding it.
    pub bytes: usize,
    class24_at: usize,
    oa_at: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum LayoutError {
    #[error("the eBPF object does not parse as an ELF: {0}")]
    NotAnElf(String),
    #[error(
        "the object carries no {SECTION} section, so the blocklist tables are not where the \
         agent would publish them"
    )]
    NoSection,
    #[error("the object carries no {0} symbol")]
    NoSymbol(&'static str),
    #[error(
        "{symbol} is at {at} in a {bytes}-byte {SECTION} and needs {len}, so one write of the \
         section would run past it"
    )]
    OutOfSection {
        symbol: &'static str,
        at: usize,
        len: usize,
        bytes: usize,
    },
    #[error(
        "{0} is not in {SECTION}, so one write of that section would not publish it and the \
         program would keep reading whatever it was loaded with"
    )]
    Elsewhere(&'static str),
}

impl Section {
    /// The offsets, read off the object the agent is about to load.
    ///
    /// Takes the bytes the caller already read for the loader rather than a path: reading the
    /// object twice invites the two reads to disagree, which is a blocklist published into a
    /// layout the loaded program does not have.
    pub fn of(object: &[u8]) -> Result<Self, LayoutError> {
        let elf =
            object::File::parse(object).map_err(|err| LayoutError::NotAnElf(err.to_string()))?;
        let bss = elf.section_by_name(SECTION).ok_or(LayoutError::NoSection)?;
        let index = bss.index();
        let bytes = bss.size() as usize;

        let at = |name: &'static str, len: usize| -> Result<usize, LayoutError> {
            let symbol = elf
                .symbols()
                .find(|symbol| symbol.name() == Ok(name))
                .ok_or(LayoutError::NoSymbol(name))?;
            if symbol.section_index() != Some(index) {
                return Err(LayoutError::Elsewhere(name));
            }
            let at = symbol.address() as usize;
            // Checked here so that `image` can copy without a bounds test per table, and so
            // that a mismatch is named as the symbol it is rather than as a panic on a slice.
            if at.checked_add(len).is_none_or(|end| end > bytes) {
                return Err(LayoutError::OutOfSection {
                    symbol: name,
                    at,
                    len,
                    bytes,
                });
            }
            Ok(at)
        };

        Ok(Self {
            bytes,
            class24_at: at(CLASS24_SYMBOL, CLASS24_BYTES)?,
            oa_at: at(OA_TABLE_SYMBOL, OA_BYTES)?,
        })
    }

    /// The whole section as one value, which is what the map holds.
    ///
    /// **Writing the section whole is only safe because the section is only the two tables.**
    /// Read off the shipped object: `.bss` is 0x1400000 bytes, which is `CLASS24` at 0 and
    /// `OA_TABLE` at 0x400000 and nothing after them, while every global the loader patches
    /// through `override_global` — `SETTINGS`, `SIGNATURE_VECTORS`, `COUNTER_STRIPE`, the
    /// bucket words — is in `.rodata` and untouched by this. A zero-initialised `static` added
    /// to the program later would land here and be zeroed by every publish, so
    /// `bss_is_only_the_blocklist.rs` fails the build rather than letting that happen quietly.
    pub fn image(&self, class24: &[u8], oa: &[OaSlot]) -> Vec<u8> {
        assert_eq!(
            class24.len(),
            CLASS24_BYTES,
            "the /24 table is not the size the program reads"
        );
        assert_eq!(
            std::mem::size_of_val(oa),
            OA_BYTES,
            "the open-addressing table is not the size the program reads"
        );
        // SAFETY: `OaSlot` is `repr(C)`, eight bytes and no padding — asserted in
        // `lorica_common::blocklist` — so the slice is exactly its own bytes.
        let oa = unsafe { std::slice::from_raw_parts(oa.as_ptr().cast::<u8>(), OA_BYTES) };
        let mut image = vec![0u8; self.bytes];
        image[self.class24_at..][..CLASS24_BYTES].copy_from_slice(class24);
        image[self.oa_at..][..OA_BYTES].copy_from_slice(oa);
        image
    }
}

/// One `bpf(BPF_MAP_UPDATE_ELEM)` against the section map.
///
/// The `elem` arm of `union bpf_attr`, field for field: the kernel reads it by offset, so the
/// layout is the contract and the padding after `map_fd` is part of it. aya's own `Array`
/// wrapper cannot carry this — its value type is `Pod` and sized at compile time, and this
/// value is twenty megabytes whose length is read off the ELF.
///
/// # Safety
///
/// `image` must be exactly the value size of the map behind `fd`. The kernel copies that many
/// bytes from the pointer and cannot check the length. [`Section::of`] reads the size off the
/// same object the map was created from, which is what ties the two together.
pub unsafe fn publish(fd: BorrowedFd<'_>, image: &[u8]) -> io::Result<()> {
    #[repr(C)]
    struct Attr {
        map_fd: u32,
        pad: u32,
        key: u64,
        value: u64,
        flags: u64,
    }

    let key: u32 = 0;
    let mut attr = Attr {
        map_fd: fd.as_raw_fd() as u32,
        pad: 0,
        key: (&raw const key) as usize as u64,
        value: image.as_ptr() as usize as u64,
        flags: 0,
    };
    // SAFETY: the key points at four live bytes, which is the map's key size, and the value at
    // `image.len()` live bytes, which the caller has tied to the map's value size.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_UPDATE_ELEM,
            (&raw mut attr).cast::<libc::c_void>(),
            size_of::<Attr>() as libc::c_ulong,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
