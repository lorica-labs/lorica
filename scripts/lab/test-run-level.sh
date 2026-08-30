#!/usr/bin/env bash
# The one BPF_PROG_TEST_RUN measurement, as a command to send and a parser for what comes
# back. Sourced from the repository root, not executed.
#
#   . scripts/lab/test-run-level.sh
#   cmd=$(test_run_command run 3 "sudo -n " perf "taskset -c 5 ")
#   test_run_fields "$out" || die ...   # sets TR_LABEL TR_NS TR_CYCLES TR_INSTRUCTIONS TR_LLC
#                                       #      TR_EXTRA TR_MULTIPLEXED
#
# Extracted from measure-stage-cost.sh when measure-noise.sh needed the same load: the
# question that script asks is how much of the cycle figure is the machine rather than the
# program, and it can only ask it about *this* load, under this profiler, with these
# counters. A second copy of the command would answer about a slightly different one within
# a week -- this tree has already shipped two figures that disagreed because two scripts
# each carried their own copy of a constant.
#
# Nothing here talks to a host. Both callers already have their own ssh transport and they
# do not agree on it: measure-stage-cost.sh wraps in `bash -lc '...'`, which forbids a
# single quote in the command, and measure-noise.sh pipes a whole script on stdin because
# its per-run tuning needs quotes and needs the pm-qos file descriptor to stay open across
# the measurement. What is shared is the command text and the parse, and that is all that
# is shared.
#
# **This load measures the instruction regime.** Locality is measured by
# scripts/lab/measure-dispersion.sh, on real traffic, because BPF_PROG_TEST_RUN replays one
# buffer and therefore one source address: no memory pressure exists here to observe. See
# the two-regime rule in the agent tree. What follows lets a caller borrow a counter or two
# from that regime anyway, under a check.

# Events appended to the three this load has always counted, comma separated, empty by default.
#
# **Empty by default is the design and not caution.** Those three fit this PMU without
# multiplexing; a fourth may not, and perf answers a multiplexed counter with a scaled estimate
# printed exactly like a count. Every instruction ceiling in this tree is asserted against this
# load, so an event added silently could turn each of them into an extrapolation.
# `TR_MULTIPLEXED` is what a caller reads before believing anything it added.
#
# What a locality campaign wants here, on a Haswell: `cycle_activity.stalls_ldm_pending` and
# `cycle_activity.stalls_l2_pending`. The names are not portable -- `stalls_l3_miss` and
# `stalls_mem_any` are Skylake and later and this PMU answers `event syntax error` for both --
# so a caller names them for the machine it drives.
LORICA_EXTRA_EVENTS=${LORICA_EXTRA_EVENTS:-}

# The command text. `prefix` goes between `--` and `env` so that whatever it is -- a
# taskset, nothing at all -- is inside what perf counts, exactly like the env it precedes.
# With an empty prefix and no extra events this is byte for byte the string
# measure-stage-cost.sh built inline.
test_run_command() {
    local run_dir=$1 level=$2 elevate=${3:-} perf=${4:-perf} prefix=${5:-}
    local events=cycles,instructions,cache-misses${LORICA_EXTRA_EVENTS:+,$LORICA_EXTRA_EVENTS}
    printf '%s' "cd ~/$run_dir/target-tests && b=\$(ls bin/* | head -1) && ${elevate}$perf stat -x, \
-e $events -- ${prefix}env LORICA_EBPF_OBJ=\$PWD/ebpf/instrumented \
LORICA_EBPF_PLAIN_OBJ=\$PWD/ebpf/plain \
LORICA_STAGE_CUTOFF=$level \$b \
one_level_of_the_pipeline_under_a_profiler --exact --nocapture"
}

# Every event perf had to multiplex, named with the percentage it managed. Empty is the good
# answer.
#
# The enabled percentage is field **five** of the `-x,` form. Field six is the
# instructions-per-cycle annotation and reads 0.43, so a check on it calls a clean run
# multiplexed. And a check that looks for a low percentage in the output of a perf that failed
# to *start* finds none and calls a group that never ran clean. Both mistakes were made while
# this was written, and both reported the reassuring answer.
test_run_enabled() {
    printf '%s\n' "$1" | awk -F, '$3 != "" && $5 != "" && $5 + 0 < 99.5 { print $3 "=" $5 "%" }' \
        | tr '\n' ' '
}

# A counter perf could not deliver reads `<not supported>`, which is not a number. It
# becomes an empty cell rather than entering an arithmetic that would report a zero.
test_run_counter() {
    local value
    value=$(printf '%s\n' "$1" | awk -F, -v ev="$2" '$3 == ev { print $1; exit }')
    case $value in ''|*[!0-9]*) echo "" ;; *) echo "$value" ;; esac
}

# Returns 1 when the run printed no LEVEL record at all, which is the only failure this
# function can tell apart from a bad reading: TR_NS is set to whatever was there and the
# caller checks it, because the caller is the one that can name the level in the message.
test_run_fields() {
    local out=$1 record event
    record=$(printf '%s\n' "$out" | sed -n 's/^LEVEL,\([0-9]*\),\(.*\),\([0-9]*\)$/\1;\2;\3/p' | tail -1)
    [ -n "$record" ] || return 1
    TR_LABEL=${record#*;}; TR_LABEL=${TR_LABEL%;*}
    TR_NS=${record##*;}
    # perf writes its table to stderr in the -x, form: value,unit,event,...
    TR_CYCLES=$(test_run_counter "$out" cycles)
    TR_INSTRUCTIONS=$(test_run_counter "$out" instructions)
    TR_LLC=$(test_run_counter "$out" cache-misses)
    # Set on every run, so a caller that added nothing still learns if the three drifted into
    # multiplexing on a machine with fewer counters than this lab's.
    TR_MULTIPLEXED=$(test_run_enabled "$out")
    # One leading comma per extra event, so a caller appends it to a CSV row unchanged and an
    # event the PMU refused lands as an empty cell rather than as a zero.
    TR_EXTRA=
    for event in ${LORICA_EXTRA_EVENTS//,/ }; do
        TR_EXTRA="$TR_EXTRA,$(test_run_counter "$out" "$event")"
    done
}
