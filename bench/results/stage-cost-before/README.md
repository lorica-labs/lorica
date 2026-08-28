# The baseline the counter-map conversion is measured against

Commit `5847f14`, the tree immediately before `BPF_F_MMAPABLE` and before the
self-validating slot, run on `carapace-target` (6.8.0-138, four possible
processors) in the same session as the `../stage-cost/` record beside it. Same
machine, same kernel, same optimisation level, same afternoon: that is the only
condition under which the two may be subtracted.

It is kept because the comparison is the whole claim. `1 443.4` instructions per
packet here against `1 480.5` next door is +36.2, and a reader who cannot re-run
the subtraction has to take that on trust.

The cross-check that makes it trustworthy: this figure lands within 0.08 % of
the 1 444.5 this tree recorded months ago on the same harness, so the instrument
reproduces across sessions and not merely within one.
