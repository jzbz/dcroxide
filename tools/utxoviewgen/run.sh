#!/bin/sh
# SPDX-License-Identifier: ISC
#
# Regenerate crates/dcroxide-blockchain/tests/data/utxoview_vectors.txt
# from a dcrd checkout at the parity pin:
#
#   tools/utxoviewgen/run.sh <dcrd checkout> <input file> <output file>
#
# export_test.go runs as a test inside the checkout's internal/blockchain
# package, through `go test -overlay`.  It reads the base view and the two
# blocks from the input file, normally the vector file itself, and writes
# every other row again from dcrd's code; the input and output may be the
# same file.  Nothing is written into the checkout.  Go may fetch the
# module's dependencies.

set -eu

if [ $# -ne 3 ]; then
	echo "usage: $0 <dcrd checkout> <input file> <output file>" >&2
	exit 2
fi

here=$(cd "$(dirname "$0")" && pwd)
dcrd=$(cd "$1" && pwd)
case $2 in
/*) in=$2 ;;
*) in=$(pwd)/$2 ;;
esac
case $3 in
/*) out=$3 ;;
*) out=$(pwd)/$3 ;;
esac

pkg=$dcrd/internal/blockchain
if [ ! -f "$pkg/utxoviewpoint.go" ]; then
	echo "$0: no internal/blockchain under $dcrd" >&2
	exit 1
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

cat >"$tmp/overlay.json" <<JSON
{"Replace": {
  "$pkg/dcroxide_utxoview_export_test.go": "$here/export_test.go"
}}
JSON

cd "$dcrd"
DCROXIDE_UTXOVIEW_INPUT=$in DCROXIDE_UTXOVIEW_VECTORS=$out go test -count=1 \
	-tags dcroxide_export -overlay "$tmp/overlay.json" \
	-run '^TestExportUtxoViewVectors$' ./internal/blockchain
