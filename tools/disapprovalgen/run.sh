#!/bin/sh
# SPDX-License-Identifier: ISC
#
# Regenerate crates/dcroxide-blockchain/tests/data/disapproval_vectors.txt
# from a dcrd checkout at the parity pin:
#
#   tools/disapprovalgen/run.sh <dcrd checkout> <output file>
#
# export_test.go runs as a test inside the checkout's internal/blockchain
# package, through `go test -overlay`, beside a copy of that commit's
# blockchain/chaingen/generator.go with three changes, so that a run at an
# unchanged commit writes the same file:
#
# - the exporter sets block one's timestamp, which the generator reads from
#   the wall clock;
# - the random values the generator puts in coinbases and elsewhere come
#   from a fixed stream the exporter restarts for each run;
# - a block's proof of work is searched on one thread, so the nonce found is
#   the lowest that solves it rather than the first of several threads'.
#
# Nothing is written into the checkout, and the copy is derived from the
# checkout's own generator.go on every run, so the vectors are always that
# commit's behaviour.  Go may fetch the module's dependencies.

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

gen=$dcrd/blockchain/chaingen/generator.go
pkg=$dcrd/internal/blockchain
if [ ! -f "$gen" ] || [ ! -f "$pkg/utxoviewpoint.go" ]; then
	echo "$0: no chaingen generator or internal/blockchain under $dcrd" >&2
	exit 1
fi
for call in 'time\.Now()' 'runtime\.NumCPU()'; do
	if [ "$(grep -c "$call" "$gen")" -ne 1 ]; then
		echo "$0: expected one $call call in $gen" >&2
		exit 1
	fi
done

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

sed -e 's/time\.Now()/exportBlockOneTime/' -e 's/rand\.Uint64()/exportRandUint64()/g' \
	-e 's/rand\.Read(/exportRandRead(/g' -e 's/runtime\.NumCPU()/1/' \
	"$gen" >"$tmp/generator.go"
if grep -q 'rand\.\|runtime\.NumCPU' "$tmp/generator.go"; then
	echo "$0: a use of crypto/rand or runtime.NumCPU in $gen is not seamed" >&2
	exit 1
fi
cat >>"$tmp/generator.go" <<'GO'

// The copy still imports crypto/rand and runtime, whose calls the script
// replaced.
var (
	_ = rand.Uint64
	_ = runtime.NumCPU
)

// exportBlockOneTime is block one's timestamp, set by the exporter in place
// of the wall clock.
var exportBlockOneTime time.Time

// exportRandState is the state of the SplitMix64 stream that stands in for
// crypto/rand.
var exportRandState uint64

// ExportReset sets the timestamp the generator gives block one and restarts
// the stream that stands in for crypto/rand.
func ExportReset(blockOne time.Time) {
	exportBlockOneTime = blockOne
	exportRandState = 0
}

func exportRandUint64() uint64 {
	exportRandState += 0x9e3779b97f4a7c15
	z := exportRandState
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

func exportRandRead(b []byte) {
	for i := range b {
		if i%8 == 0 {
			binary.LittleEndian.PutUint64(exportRandBuf[:], exportRandUint64())
		}
		b[i] = exportRandBuf[i%8]
	}
}

var exportRandBuf [8]byte
GO

cat >"$tmp/overlay.json" <<JSON
{"Replace": {
  "$gen": "$tmp/generator.go",
  "$pkg/dcroxide_disapproval_export_test.go": "$here/export_test.go"
}}
JSON

cd "$dcrd"
DCROXIDE_DISAPPROVAL_VECTORS=$out go test -count=1 -tags dcroxide_export \
	-overlay "$tmp/overlay.json" -run '^TestExportDisapprovalVectors$' \
	./internal/blockchain
