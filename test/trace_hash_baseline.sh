#!/bin/bash
# Wire-format gate: run trace_hash and diff its per-protocol send/recv digests
# against the checked-in baseline. The digests are deterministic only when
# emp-tool was built with -DEMP_TEST_MODE=ON; the CMake registration adds
# this test only to such trees.
# A protocol whose wire bytes change (a non-reproducible refactor) fails here.
#
#   trace_hash_baseline.sh <run-script> <trace_hash-binary> <baseline-file>
#
# Release-only: trace_hash uses larger, NDEBUG-gated lengths whose digests
# differ from a Debug build, so the baseline is a Release artifact (the CMake
# registration restricts this test to Release trees).
set -uo pipefail

if [[ $# -ne 3 ]]; then
	echo "usage: $0 <run-script> <trace_hash-binary> <baseline-file>" >&2
	exit 2
fi
run=$1
binary=$2
baseline=$3

if [[ ! -f "$baseline" ]]; then
	echo "trace_hash_baseline: missing baseline $baseline" >&2
	exit 1
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/emp-trace-baseline.XXXXXX") || exit 1
trap 'rm -rf "$work"' EXIT

# The two-party run drives both roles over loopback.
"$run" "$binary" 2>/dev/null \
	| grep -E 'send=[0-9a-f]{16} recv=[0-9a-f]{16}' > "$work/actual"

if [[ ! -s "$work/actual" ]]; then
	echo "trace_hash_baseline: no digest rows produced (run failed?)" >&2
	exit 1
fi

if ! diff -u "$baseline" "$work/actual"; then
	echo "trace_hash_baseline: wire-format digests changed vs baseline." >&2
	echo "If the change is intentional and reproducible, regenerate:" >&2
	echo "  $run $binary | grep -E 'send=.* recv=' > $baseline" >&2
	echo "and update the table in README.md." >&2
	exit 1
fi

echo "trace_hash_baseline: OK ($(wc -l < "$baseline" | tr -d ' ') protocol rows match)"
