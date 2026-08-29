#!/usr/bin/env python3
"""Where the instructions of the eBPF program are, by source region.

    attribute-instructions.py [OBJECT] [--objdump PATH] [--function NAME]

Reads the compiled object rather than running it, so it needs no kernel, no target and no
privileges: `llvm-objdump --line-numbers` and the DWARF the release profile already emits.

**Why this exists beside `measure-stage-cost.sh` rather than instead of it.** That script
measures what a packet *executes*, by cutting the pipeline after stage k and differencing two
whole-path readings. It is the right instrument between stages and the wrong one inside a
stage, and the reason is worth stating because it cost a wrong published figure to learn.

A cut level is a branch. Work whose result is dead on the cut path may be sunk below it by the
optimiser and charged to the next level; work still needed after it may be hoisted above.
Neither shows up in the check that the levels sum to the whole, because **sinking conserves the
total** — it moves cost between levels without adding any. Splitting `parse` in two that way
reported 210 instructions of "reading" and 333 of "checking", and the static attribution below
says `refuse()` is thirteen instructions and `udp_length()` is two. The 333 was reading, sunk
to its point of use.

So: differences between stages come from the cutoff sweep, and attribution inside a stage comes
from here. Neither answers the other's question.

**What this cannot tell you.** These are the instructions *present*, not the instructions
*executed*. `parse/ipv6.rs` is a fifth of the entry point and a steady-state IPv4 packet runs
none of it. Read a region's figure as an upper bound on what a packet spends there, and use the
sweep for what a packet actually pays.
"""

import argparse
import collections
import pathlib
import re
import shutil
import subprocess
import sys

FUNC = re.compile(r"^[0-9a-f]+ <(.+)>:")
LOC = re.compile(r"^;\s+(/\S+\.rs):(\d+)")
INSN = re.compile(r"^\s+[0-9a-f]+:\s+[0-9a-f]{2} ")

DEFAULT_OBJECT = "crates/lorica-ebpf/target/bpfel-unknown-none/release/lorica-ebpf"

# Regions of the source, as (label, path fragment, first line, last line). Line ranges rather
# than function names because the disassembly carries line numbers and not symbols: everything
# here is inlined into one entry point, which is the whole reason a per-symbol view says
# nothing.
#
# They are checked against the source at run time: a range whose first line no longer starts
# what it claims is reported rather than silently attributing to the wrong code.
REGIONS = [
    ("Window::bytes (bound + load)", "parse/mod.rs", 122, 146, "pub fn bytes"),
    ("parse() (view construction)", "parse/mod.rs", 148, 179, "pub fn parse"),
    ("walk()", "parse/mod.rs", 184, 193, "fn walk"),
    ("refuse()", "parse/mod.rs", 200, 228, "fn refuse"),
    ("udp_length()", "parse/mod.rs", 243, 252, "fn udp_length"),
    ("fast::headers", "parse/fast.rs", 42, 94, "pub fn headers"),
    ("eth::parse", "parse/eth.rs", 1, 70, None),
    ("ipv4::parse", "parse/ipv4.rs", 1, 80, None),
    ("ipv6::parse", "parse/ipv6.rs", 1, 120, None),
    ("l4::parse", "parse/l4.rs", 1, 140, None),
]


def find_objdump(given):
    if given:
        return given
    for name in ("llvm-objdump", "llvm-objdump-21", "llvm-objdump-20", "llvm-objdump-19"):
        found = shutil.which(name)
        if found:
            return found
    for path in sorted(pathlib.Path("/usr/lib").glob("llvm-*/bin/llvm-objdump"), reverse=True):
        return str(path)
    sys.exit("no llvm-objdump found; pass --objdump PATH")


def shorten(path):
    """The part of a path a reader can place, and `core::` for the standard library.

    Everything under `library/` is inlined arithmetic — `saturating_sub`, `from_be_bytes`,
    `swap_bytes` — and it is the second largest region in this program, so it is folded into
    one name rather than scattered across line numbers nobody can look up.
    """
    if "/library/" in path:
        return "core::" + path.rsplit("/", 1)[-1]
    if "lorica-ebpf/src/" in path:
        return path.split("lorica-ebpf/src/", 1)[1]
    return path.rsplit("/", 1)[-1]


def disassemble(objdump, obj, want):
    """Instructions of `want`, counted per (short path, line)."""
    proc = subprocess.run(
        [objdump, "-d", "--line-numbers", obj], capture_output=True, text=True
    )
    if proc.returncode != 0:
        sys.exit(f"{objdump} failed: {proc.stderr.strip()[:400]}")
    per = collections.Counter()
    here = None
    func = None
    for line in proc.stdout.splitlines():
        match = FUNC.match(line)
        if match:
            func, here = match.group(1), None
            continue
        match = LOC.match(line)
        if match:
            here = (shorten(match.group(1)), int(match.group(2)))
            continue
        if INSN.match(line) and func == want:
            per[here] += 1
    if not per:
        sys.exit(f"no instructions attributed to {want}: is the object built with debug info?")
    return per


def check_regions(root):
    """A range that no longer starts where it says is a wrong answer, not a missing one."""
    stale = []
    for label, path, first, _last, opens in REGIONS:
        if opens is None:
            continue
        source = root / "crates/lorica-ebpf/src" / path
        if not source.exists():
            stale.append(f"{label}: {source} is gone")
            continue
        lines = source.read_text(encoding="utf-8").splitlines()
        if not (0 < first <= len(lines)) or opens not in lines[first - 1]:
            stale.append(f"{label}: line {first} of {path} does not start with `{opens}`")
    return stale


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("object", nargs="?", default=DEFAULT_OBJECT)
    ap.add_argument("--objdump")
    ap.add_argument("--function", default="lorica_xdp")
    ap.add_argument("--lines", type=int, default=20, help="individual source lines to list")
    args = ap.parse_args()

    root = pathlib.Path(__file__).resolve().parents[2]
    obj = pathlib.Path(args.object)
    if not obj.is_absolute():
        obj = root / obj
    if not obj.exists():
        sys.exit(f"no object at {obj}; build it with: cd crates/lorica-ebpf && cargo +nightly build --release")

    stale = check_regions(root)
    if stale:
        # Fatal and not a warning. A range that has drifted reports zero instructions for the
        # region it names, and a zero here reads as "this code is free" — which is the exact
        # wrong answer this tool exists to prevent somebody from publishing.
        sys.exit("; ".join(f"stale region: {note}" for note in stale))

    per = disassemble(find_objdump(args.objdump), str(obj), args.function)
    total = sum(per.values())
    print(f"{args.function}: {total} instructions, {obj.name}\n")

    print(f"{'region':<34}{'instr':>7}{'share':>8}")
    print("-" * 49)
    claimed = 0
    for label, path, first, last, _ in REGIONS:
        count = sum(c for (f, l), c in per.items() if f.endswith(path) and first <= l <= last)
        claimed += count
        print(f"{label:<34}{count:>7}{count / total * 100:>7.1f}%")
    core = sum(c for (f, _), c in per.items() if f.startswith("core::"))
    claimed += core
    print(f"{'core:: (inlined arithmetic)':<34}{core:>7}{core / total * 100:>7.1f}%")
    rest = total - claimed
    print(f"{'elsewhere':<34}{rest:>7}{rest / total * 100:>7.1f}%")

    print(f"\n{'source line':<40}{'instr':>7}")
    print("-" * 47)
    for (path, line), count in per.most_common(args.lines):
        print(f"{path + ':' + str(line):<40}{count:>7}")


if __name__ == "__main__":
    main()
