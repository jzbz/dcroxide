#!/bin/sh
# SPDX-License-Identifier: ISC
#
# Regenerate crates/dcroxide-node/tests/data/profiler_vectors.txt from a dcrd
# checkout at the parity pin:
#
#   tools/profilergen/run.sh <dcrd checkout> <output file>
#
# export_test.go runs as a test inside the checkout's package main, beside
# profiler.go, through `go test -overlay`, and writes one row for each call
# it makes to dcrd's profileServer.Start.  An address Start accepts is bound
# and served until the next row, so the case list is limited to loopback
# addresses and to documentation addresses no interface has; export_test.go
# refuses any other.  Nothing is written into the checkout.  Go may fetch the
# module's dependencies.

set -eu

if [ $# -ne 2 ]; then
	echo "usage: $0 <dcrd checkout> <output file>" >&2
	exit 2
fi

here=$(cd "$(dirname "$0")" && pwd)
dcrd=$(cd "$1" && pwd)
case $2 in
/*) out=$2 ;;
*) out=$(pwd)/$2 ;;
esac

if [ ! -f "$dcrd/profiler.go" ]; then
	echo "$0: no profiler.go under $dcrd" >&2
	exit 1
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

cat >"$tmp/overlay.json" <<JSON
{"Replace": {
  "$dcrd/dcroxide_profiler_export_test.go": "$here/export_test.go"
}}
JSON

cd "$dcrd"
DCROXIDE_PROFILER_VECTORS=$out go test -count=1 -tags dcroxide_export \
	-overlay "$tmp/overlay.json" -run '^TestExportProfilerVectors$' .
