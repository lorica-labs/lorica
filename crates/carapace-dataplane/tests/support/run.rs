//! Loading the program and running one packet through it.
//!
//! `BPF_PROG_TEST_RUN` gives a verdict without a NIC, a generator or an attach. It
//! also runs the same packet against the same map entry every time, so it proves
//! correctness and never proves a cache behaviour: a map that grows from four
//! kilobytes to four megabytes is invisible here and expensive in production.

use std::{env, fs, path::PathBuf};

use aya::{
    Ebpf,
    maps::{MapData, PerCpuArray},
    programs::{TestRun, TestRunOptions, Xdp},
};
use carapace_common::{CounterId, PacketView};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdpAction {
    Aborted,
    Drop,
    Pass,
    Tx,
    Redirect,
}

impl XdpAction {
    fn from_return_value(value: u32) -> Self {
        match value {
            0 => Self::Aborted,
            1 => Self::Drop,
            2 => Self::Pass,
            3 => Self::Tx,
            4 => Self::Redirect,
            other => panic!("the program returned {other}, which is not an XDP action"),
        }
    }
}

/// Helper calls actually executed for one packet, as opposed to the calls present in
/// the program. This is the budget the design is written against, and it only exists
/// in a build with the `count-helpers` feature.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct HelperCounts {
    pub map_lookups: u64,
    pub clock_reads: u64,
}

impl HelperCounts {
    pub const fn total(&self) -> u64 {
        self.map_lookups + self.clock_reads
    }
}

/// A local wrapper so `Pod` can be implemented for a foreign type. Sound because
/// every byte pattern of `PacketView` is a valid value, which is the property the
/// trait requires and the reason the family and fragment fields are stored raw.
#[repr(transparent)]
#[derive(Clone, Copy)]
struct ProbeView(PacketView);

// SAFETY: PacketView is Copy, 'static, and has no invalid byte pattern.
unsafe impl aya::Pod for ProbeView {}

pub struct TestProg {
    ebpf: Ebpf,
    name: String,
}

impl TestProg {
    pub fn load(name: &str) -> Self {
        let path = object_path();
        let object = fs::read(&path).unwrap_or_else(|err| {
            panic!(
                "cannot read the eBPF object at {}: {err}\n\
                 build it with: cd crates/carapace-ebpf && cargo +nightly build --release\n\
                 or point CARAPACE_EBPF_OBJ at another one",
                path.display()
            )
        });

        let mut ebpf = Ebpf::load(&object)
            .unwrap_or_else(|err| panic!("loading {} failed: {err}", path.display()));
        let program: &mut Xdp = ebpf
            .program_mut(name)
            .unwrap_or_else(|| panic!("no program named {name} in {}", path.display()))
            .try_into()
            .expect("the program is not an XDP program");
        program
            .load()
            .unwrap_or_else(|err| panic!("the verifier rejected {name}: {err}"));

        Self {
            ebpf,
            name: name.to_owned(),
        }
    }

    fn program(&self) -> &Xdp {
        self.ebpf
            .program(&self.name)
            .expect("the program disappeared")
            .try_into()
            .expect("the program is not an XDP program")
    }

    pub fn run(&self, pkt: &[u8]) -> XdpAction {
        let result = self
            .program()
            .test_run(TestRunOptions {
                data_in: Some(pkt),
                ..Default::default()
            })
            .unwrap_or_else(|err| panic!("test_run on {} bytes failed: {err}", pkt.len()));
        XdpAction::from_return_value(result.return_value)
    }

    /// Average nanoseconds per invocation, chronometered by the kernel around the
    /// loop. It excludes the syscall, the driver, the NAPI poll and the DMA, and it
    /// does not need `bpf_stats_enabled`, whose instrumentation on this hardware
    /// costs more than the budget being measured.
    pub fn ns_per_run(&self, pkt: &[u8], repeat: u32) -> u128 {
        let result = self
            .program()
            .test_run(TestRunOptions {
                data_in: Some(pkt),
                repeat,
                ..Default::default()
            })
            .expect("test_run failed");
        result.duration.as_nanos()
    }

    pub fn counter(&self, name: &str) -> u64 {
        let id = CounterId::from_name(name)
            .unwrap_or_else(|| panic!("no counter named {name} in CounterId"));
        let map = self.ebpf.map("COUNTERS").expect("no COUNTERS map");
        let counters: PerCpuArray<&MapData, u64> =
            PerCpuArray::try_from(map).expect("COUNTERS is not a per-CPU array");
        counters
            .get(&id.index(), 0)
            .expect("reading a counter failed")
            .iter()
            .sum()
    }

    /// The parsed view of the last packet run. Only present in a build with the
    /// `parse-probe` feature of carapace-ebpf.
    pub fn parsed(&self) -> PacketView {
        let map = self.ebpf.map("PARSE_PROBE").unwrap_or_else(|| {
            panic!(
                "no PARSE_PROBE map: the object was built without the parse-probe                  feature of carapace-ebpf"
            )
        });
        let probe: PerCpuArray<&MapData, ProbeView> =
            PerCpuArray::try_from(map).expect("PARSE_PROBE is not a per-CPU array");
        let values = probe.get(&0, 0).expect("reading the parse probe failed");
        // test_run runs on one CPU, so one slot is written. Pick it by its non-zero
        // packet length rather than assuming which CPU ran.
        values
            .iter()
            .map(|probe| probe.0)
            .find(|view| view.packet_len != 0)
            .unwrap_or_else(PacketView::zeroed)
    }

    pub fn helper_counts(&self) -> HelperCounts {
        let map = self.ebpf.map("HELPER_COUNTS").unwrap_or_else(|| {
            panic!(
                "no HELPER_COUNTS map: the object was built without the count-helpers \
                 feature of carapace-ebpf"
            )
        });
        let counts: PerCpuArray<&MapData, u64> =
            PerCpuArray::try_from(map).expect("HELPER_COUNTS is not a per-CPU array");
        let read = |index: u32| -> u64 {
            counts
                .get(&index, 0)
                .expect("reading a helper count failed")
                .iter()
                .sum()
        };
        HelperCounts {
            map_lookups: read(0),
            clock_reads: read(1),
        }
    }
}

/// Where the eBPF object comes from.
///
/// Named here rather than in each test: the object is a different target built by a
/// different toolchain, so cargo cannot produce it as a dependency and the path has
/// to be agreed on once.
pub fn object_path() -> PathBuf {
    if let Ok(path) = env::var("CARAPACE_EBPF_OBJ") {
        return PathBuf::from(path);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../carapace-ebpf/target/bpfel-unknown-none/release/carapace-ebpf")
}
