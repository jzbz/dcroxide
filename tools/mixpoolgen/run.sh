#!/bin/sh
# SPDX-License-Identifier: ISC
#
# Regenerate crates/dcroxide-mixing/tests/data/mixpool_vectors.txt from a
# dcrd checkout at the parity pin:
#
#   tools/mixpoolgen/run.sh <dcrd checkout> <output file>
#
# export_test.go runs as a test inside the checkout's mixing/mixpool package,
# through `go test -overlay`, beside a copy of that commit's mixpool.go whose
# time.Now() and time.Since() calls answer the scenario's recorded time.
# Nothing is written into the checkout, and the copy is derived from the
# checkout's own mixpool.go on every run, so the vectors are always that
# commit's behaviour.  Go may fetch the mixing module's dependencies.
#
# DCROXIDE_MIXPOOL_SCRIPT=6f6cf21b selects the script the file held at that
# pin, which reproduces that file byte for byte when run against 6f6cf21b.

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

pkg=$dcrd/mixing/mixpool
if [ ! -f "$pkg/mixpool.go" ]; then
	echo "$0: no mixing/mixpool/mixpool.go under $dcrd" >&2
	exit 1
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

sed -e 's/time\.Now()/exportNow()/g' -e 's/time\.Since(/exportSince(/g' \
	"$pkg/mixpool.go" >"$tmp/mixpool.go"
cat >>"$tmp/mixpool.go" <<'EOF'

// exportSeamed marks this copy as the clock-seamed one the exporter needs.
const exportSeamed = true
EOF

cat >"$tmp/overlay.json" <<EOF
{"Replace": {
  "$pkg/mixpool.go": "$tmp/mixpool.go",
  "$pkg/dcroxide_export_test.go": "$here/export_test.go"
}}
EOF

cd "$dcrd/mixing"
DCROXIDE_MIXPOOL_VECTORS=$out go test -count=1 -tags dcroxide_export \
	-overlay "$tmp/overlay.json" -run '^TestExportMixpoolVectors$' ./mixpool
