#!/bin/bash
# Regression checks for the per-build-directory tuning_local.h mechanism.
#   $1 = C++ compiler        (CMAKE_CXX_COMPILER)
#   $2 = build tuning include dir (EMP_OT_TUNING_INCLUDE_DIR)
#   $3 = canonical untuned stub (EMP_OT_TUNING_STUB_H)
#
# The probe includes emp-ot/tuning_local.h alone (the generated header has
# no includes of its own), so these checks compile in milliseconds and are
# independent of emp-tool. They pin the three properties the build relies
# on: a stub means no overrides, a tuned file's defines are visible, and
# an earlier -I dir shadows a later one (build dir over source tree).

if [[ $# -ne 3 ]]; then
	echo "usage: $0 <c++-compiler> <tuning-include-dir> <stub-header>" >&2
	exit 2
fi

cxx=$1
build_inc=$2
stub_header=$3
work=$(mktemp -d "${TMPDIR:-/tmp}/emp-tuning-local.XXXXXX") || exit 1
failures=0

cleanup() {
	rm -rf "$work"
}
trap cleanup EXIT

cat >"$work/probe.cpp" <<'EOF'
#include "emp-ot/tuning_local.h"
#if defined(EXPECT_M)
#  if !defined(EMP_TUNE_LPN_BATCH_M)
#    error "expected EMP_TUNE_LPN_BATCH_M to be defined"
#  elif EMP_TUNE_LPN_BATCH_M != EXPECT_M
#    error "EMP_TUNE_LPN_BATCH_M has the wrong value"
#  endif
#else
#  if defined(EMP_TUNE_LPN_BATCH_M)
#    error "unexpected EMP_TUNE_LPN_BATCH_M override"
#  endif
#endif
int main() { return 0; }
EOF

# check <label> <expected: ok|fail> <compiler args...>
check() {
	local label=$1 expected=$2
	shift 2
	if "$cxx" -fsyntax-only "$@" "$work/probe.cpp" 2>"$work/err.log"; then
		local got=ok
	else
		local got=fail
	fi
	if [[ $got != "$expected" ]]; then
		echo "FAIL: $label (expected $expected, got $got)" >&2
		sed 's/^/    /' "$work/err.log" >&2
		((failures += 1))
	else
		echo "ok: $label"
	fi
}

# Fixture include roots, each with an emp-ot/tuning_local.h.
mkdir -p "$work/stub/emp-ot" "$work/tuned/emp-ot"
cp "$stub_header" "$work/stub/emp-ot/tuning_local.h"
echo "#define EMP_TUNE_LPN_BATCH_M 64" >"$work/tuned/emp-ot/tuning_local.h"

# 1. The real build directory always has the header (stub or tuned).
if [[ -f "$build_inc/emp-ot/tuning_local.h" ]]; then
	echo "ok: build dir header exists"
else
	echo "FAIL: $build_inc/emp-ot/tuning_local.h missing" >&2
	((failures += 1))
fi

# 2. Stub semantics: the canonical comment-only header means no overrides.
check "stub -> defaults" ok -I"$work/stub"

# 3. A tuned header's overrides are visible (and the probe can tell).
check "override applies" ok -DEXPECT_M=64 -I"$work/tuned"
check "probe detects overrides" fail -I"$work/tuned"

# 4. Include order: the first -I dir wins, both ways round. This is the
#    property that lets the build-dir header shadow a stale source-tree
#    copy (the build dir's include dir is prepended with BEFORE).
check "earlier dir shadows later (stub first)" ok -I"$work/stub" -I"$work/tuned"
check "earlier dir shadows later (tuned first)" ok -DEXPECT_M=64 -I"$work/tuned" -I"$work/stub"

if ((failures > 0)); then
	echo "test_tuning_local: $failures failure(s)" >&2
	exit 1
fi
echo "test_tuning_local: OK"
