#!/bin/sh
# SPDX-License-Identifier: ISC
#
# Regenerate processblock_vectors.txt, invalidate_vectors.txt or
# reorg_vectors.txt in crates/dcroxide-blockchain/tests/data from a dcrd
# checkout at the parity pin, one file per run:
#
#   tools/chainopsgen/run.sh <dcrd checkout> <input file> <output file>
#
# export_test.go runs as a test inside the checkout's internal/blockchain
# package, through `go test -overlay`.  It reads the seeded outputs, the
# blocks, the operations and the utxo universe's outpoints from the input
# file, normally the vector file itself, and writes every other field again
# from dcrd's code; the input and output may be the same file.  Each input's
# fraud proof names the output it spends; DCROXIDE_CHAINOPS_WITNESS=constant
# reproduces the files as they were before (export_test.go says how).  The
# run prints how many blocks it rewrote.  Nothing is written into the
# checkout.  Go may fetch the module's dependencies.

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
if [ ! -f "$pkg/chain.go" ]; then
	echo "$0: no internal/blockchain under $dcrd" >&2
	exit 1
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

cat >"$tmp/overlay.json" <<JSON
{"Replace": {
  "$pkg/dcroxide_chainops_export_test.go": "$here/export_test.go"
}}
JSON

cd "$dcrd"
DCROXIDE_CHAINOPS_INPUT=$in DCROXIDE_CHAINOPS_VECTORS=$out go test -count=1 -v \
	-tags dcroxide_export -overlay "$tmp/overlay.json" \
	-run '^TestExportChainOpsVectors$' ./internal/blockchain
