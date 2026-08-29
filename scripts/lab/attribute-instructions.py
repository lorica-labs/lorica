#!/usr/bin/env python3
"""Where the instructions of the eBPF program are, by source region.

    attribute-instructions.py [OBJECT] [--objdump PATH] [--function NAME] [--lines N]

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
reported 210 instructions of "reading" and 333 of "checking", and this tool says `refuse()` is
thirteen instructions and `udp_length()` is two. The 333 was reading, sunk to its point of use.

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

# Regions of the source, as (label, path, opening signature). **Line ranges are found in the
# source at run time and never written here**, because a range written down is wrong after the
# next edit and a wrong range reports zero for the code it names — which reads as "this code is
# free". The first version of this file did write them down and went stale twice in one
# afternoon, the second time while measuring the very change that had moved them.
#
# A whole file is named by passing `None` as the signature.
REGIONS = [
    ("Window::bytes (bound + copy)", "parse/mod.rs", "pub fn bytes"),
    ("parse() (view construction)", "parse/mod.rs", "pub fn parse"),
    ("walk()", "parse/mod.rs", "fn walk"),
    ("refuse()", "parse/mod.rs", "fn refuse"),
    ("udp_length()", "parse/mod.rs", "fn udp_length"),
    ("eth:: (whole file)", "parse/eth.rs", None),
    ("ipv4:: (whole file)", "parse/ipv4.rs", None),
    ("ipv6:: (whole file)", "parse/ipv6.rs", None),
    ("l4:: (whole file)", "parse/l4.rs", None),
]


def body_lines(lines, at):
    """Lines from a signature to its closing brace, by brace counting.

    Enough for this tree: rustfmt puts the closing brace of an item in column zero and every
    region named above is an item.
    """
    depth = 0
    for offset, line in enumerate(lines[at:]):
        depth += line.count("{") - line.count("}")
        if depth <= 0 and offset > 0:
            return offset
    return len(lines) - at


def span(root, path, opens):
    """Line range of a region, read out of the source. `(range, None)` or `(None, why)`."""
    source = root / "crates/lorica-ebpf/src" / path
    if not source.exists():
        return None, f"{source} is gone"
    lines = source.read_text(encoding="utf-8").splitlines()
    if opens is None:
        return (1, len(lines)), None
    starts = [i for i, line in enumerate(lines) if line.lstrip().startswith(opens)]
    if not starts:
        return None, f"no line of {path} starts with `{opens}`"
    # Two definitions of one name is what a `#[cfg]` pair looks like. Spanning from the first
    # to the end of the last covers both, because only one of them is in any given object and
    # attributing to whichever came first would silently measure the variant that is not built.
    return (starts[0] + 1, starts[-1] + 1 + body_lines(lines, starts[-1])), None


def resolve(root):
    """Every region as `(label, path, first, last)`, plus the ones that could not be found."""
    found, missing = [], []
    for label, path, opens in REGIONS:
        rng, why = span(root, path, opens)
        if why:
            missing.append(f"{label}: {why}")
        else:
            found.append((label, path, rng[0], rng[1]))
    return found, missing


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
    `swap_bytes` — and it is one of the two largest regions in this program, so it is folded
    into one name rather than scattered across line numbers nobody can look up.
    """
    if "/library/" in path:
        return "core::" + path.rsplit("/", 1)[-1]
    if "lorica-ebpf/src/" in path:
        return path.split("lorica-ebpf/src/", 1)[1]
    return path.rsplit("/", 1)[-1]


def disassemble(objdump, obj, want):
    """Instructions of function `want`, counted per `(short path, line)`."""
    proc = subprocess.run([objdump, "-d", "--line-numbers", obj], capture_output=True, text=True)
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
        sys.exit(
            f"no object at {obj}; build it with: "
            "cd crates/lorica-ebpf && cargo +nightly build --release"
        )

    regions, missing = resolve(root)
    if missing:
        # Fatal, not a warning. A region that cannot be located contributes zero, and a zero
        # here reads as "this code is free" — the exact wrong answer this tool exists to stop
        # somebody publishing.
        sys.exit("; ".join(f"cannot locate: {note}" for note in missing))

    per = disassemble(find_objdump(args.objdump), str(obj), args.function)
    total = sum(per.values())
    print(f"{args.function}: {total} instructions, {obj.name}\n")

    print(f"{'region':<32}{'instr':>7}{'share':>8}")
    print("-" * 47)
    claimed = 0
    for label, path, first, last in regions:
        count = sum(c for (f, l), c in per.items() if f.endswith(path) and first <= l <= last)
        claimed += count
        print(f"{label:<32}{count:>7}{count / total * 100:>7.1f}%")
    core = sum(c for (f, _), c in per.items() if f.startswith("core::"))
    claimed += core
    print(f"{'core:: (inlined arithmetic)':<32}{core:>7}{core / total * 100:>7.1f}%")
    rest = total - claimed
    print(f"{'elsewhere':<32}{rest:>7}{rest / total * 100:>7.1f}%")

    if args.lines:
        print(f"\n{'source line':<40}{'instr':>7}")
        print("-" * 47)
        for (path, line), count in per.most_common(args.lines):
            print(f"{path + ':' + str(line):<40}{count:>7}")


if __name__ == "__main__":
    main()
