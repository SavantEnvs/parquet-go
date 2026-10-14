#!/usr/bin/env bash
#
# parquet-go/mayhem/build.sh — mining layer: one sanitized libFuzzer binary over
# the merged-row-group offset index, plus the project's KAT oracle probe.
#
#   /mayhem/fuzz_multi_offsetindex — parquet.MultiRowGroup over an opened file's
#                                     row groups (merged repeatedly), then
#                                     OffsetIndex() of each merged column chunk
#                                     (NEW harness; mayhem/harness_multi_offsetindex_test.go.src).
#   /mayhem/kat                     — dynamically-linked known-answer probe used by
#                                     mayhem/test.sh.
#
# Go path is ASan-only for the libFuzzer link (as OSS-Fuzz's Go path is): the .a
# archive carries the Go fuzz code instrumented by go-118-fuzz-build, then clang++
# links it against the libFuzzer engine.
#
# DWARF gate (SPEC §6.2 item 10): Go's gc compiler always emits DWARF4 with no
# downgrade knob. The C/CGO shims clang compiles (the LLVMFuzzerTestOneInput
# wrapper, the CGO bridge) default to DWARF5 under clang-19, so we force them —
# and the final link — to DWARF3 via $GO_DEBUG_FLAGS. verify-repo reads the FIRST
# CU's DWARF version, which is the C shim at DWARF3, satisfying the < 4 gate.
#
# AIR-GAPPED CONTRACT (SPEC §6.5): the PATCH tier re-runs this script OFFLINE.
# This first (online) build populates $GOMODCACHE under /opt/toolchains; the cache
# doubles as a file proxy, which GOPROXY prefers, so the offline re-run resolves
# from it. Re-running on an already-built tree must succeed (idempotent).
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
# ASan-only for the Go libFuzzer link. An explicit empty --build-arg SANITIZER_FLAGS=
# yields a no-sanitizer (natural-crash) build, so default with `=` not `:=`.
: "${SANITIZER_FLAGS=-fsanitize=address}"
: "${MAYHEM_JOBS:=$(nproc)}"
export CC CXX LIB_FUZZING_ENGINE SANITIZER_FLAGS MAYHEM_JOBS

# DWARF3 for every clang-compiled shim + the final link (see header).
: "${GO_DEBUG_FLAGS:=-g -gdwarf-3}"
export CGO_CFLAGS="${CGO_CFLAGS:+$CGO_CFLAGS }$GO_DEBUG_FLAGS"
export CGO_CXXFLAGS="${CGO_CXXFLAGS:+$CGO_CXXFLAGS }$GO_DEBUG_FLAGS"

# Offline-first module resolution. $(go env GOMODCACHE) reads the pinned ENV from
# the Dockerfile, so this path is right under ANY $HOME (CI or the PATCH re-run).
export GOFLAGS="${GOFLAGS:--mod=mod}"
export GOPROXY="${GOPROXY:-file://$(go env GOMODCACHE)/cache/download,https://proxy.golang.org,direct}"
export GOTOOLCHAIN="${GOTOOLCHAIN:-local}"

cd "$SRC"
go version

# go-118-fuzz-build rewrites the stdlib `testing` import to its own shim, which must
# be on the module graph. Order matters: tidy FIRST, then `go get` the shim — a
# trailing tidy would prune it again (nothing imports it until the builder generates
# the entrypoint). Both resolve from the module cache when offline.
go mod tidy 2>&1 | tail -2 || true
go get github.com/AdamKorcz/go-118-fuzz-build/testing 2>&1 | tail -2 || true

mkdir -p "$SRC/mayhem-build"

# The NEW harness ships as .go.src so it is never compiled as an ordinary package
# file; copy it into its OWN fresh, single-file package directory under
# `_mayhem_harness/` (idempotent: rm -rf then mkdir). The leading underscore makes
# every Go tool (build/vet/`go test ./...`) ignore the tree for wildcard patterns,
# while go-118-fuzz-build — given the directory explicitly — still finds it. The
# repo root mixes `package parquet` and `package parquet_test`, which
# go-118-fuzz-build's package loader rejects, hence the fresh directory.
rm -rf "$SRC/_mayhem_harness"
mkdir -p "$SRC/_mayhem_harness/multioffset"
cp -f "$SRC/mayhem/harness_multi_offsetindex_test.go.src" "$SRC/_mayhem_harness/multioffset/harness_test.go"

# build_target <output-name> <fuzz-func> <package-dir>
build_target() {
  local target="$1" func="$2" pkgdir="$3"
  echo "=== building $target ($func in $pkgdir, go-118-fuzz-build) ==="
  go-118-fuzz-build -o "$SRC/mayhem-build/$target.a" -func "$func" "$pkgdir"
  # shellcheck disable=SC2086  # word-splitting of the flag lists is intended
  $CXX $SANITIZER_FLAGS $LIB_FUZZING_ENGINE $GO_DEBUG_FLAGS \
      "$SRC/mayhem-build/$target.a" -o "/mayhem/$target"
  echo "built /mayhem/$target"
}

build_target fuzz_multi_offsetindex FuzzMayhemMultiOffsetIndex "$SRC/_mayhem_harness/multioffset"

# ── The KAT probe used by mayhem/test.sh (NORMAL flags — it is a functional oracle,
#    not a triage artifact, so no sanitizer/fuzz instrumentation here). ───────────
# CGO_ENABLED=1 + the `import "C"` file force EXTERNAL linking so the probe is
# DYNAMICALLY linked and therefore reachable by verify-repo's LD_PRELOAD sabotage
# shim (SPEC §6.3). Assert that, so a toolchain change can't silently turn the
# probe static and weaken the oracle to a `go test`-only pass.
echo "=== building /mayhem/kat (KAT probe, cgo => dynamically linked) ==="
CGO_ENABLED=1 CGO_CFLAGS="$GO_DEBUG_FLAGS" go build -o /mayhem/kat ./mayhem/kat
if ! file /mayhem/kat | grep -q 'dynamically linked'; then
  echo "FATAL: /mayhem/kat is not dynamically linked — the sabotage check could not" >&2
  echo "       neuter it, which would make mayhem/test.sh a reward-hackable oracle." >&2
  file /mayhem/kat >&2
  exit 1
fi
echo "built /mayhem/kat (dynamically linked)"

# Go's `go test` compiles on demand, so there is no separate test-suite build step;
# mayhem/test.sh runs `go test ./...` with the project's normal flags.

echo "build.sh complete:"
ls -la /mayhem/fuzz_multi_offsetindex /mayhem/kat
