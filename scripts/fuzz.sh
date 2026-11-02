#!/bin/sh
# Runs every fuzz target in the module for FUZZTIME each (default 1m).
# A failure stops the run; the crashing input is saved under testdata/fuzz.
set -eu
FUZZTIME=${FUZZTIME:-1m}
cd "$(dirname "$0")/.."
for pkg in $(go list ./...); do
	for target in $(go test -list '^Fuzz' "$pkg" | grep '^Fuzz' || true); do
		echo "== $pkg $target ($FUZZTIME)"
		go test "$pkg" -run '^$' -fuzz "^${target}\$" -fuzztime "$FUZZTIME"
	done
done
echo "all fuzz targets clean"
