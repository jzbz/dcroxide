// SPDX-License-Identifier: ISC

// Command dcrdstat measures how many payload bytes dcrd actually stores.
//
// ADR-0004 compares dcrd's 6.15 GiB of metadata against dcroxide's 14.48
// and treats the difference as structural overhead. ADR-0009 withdrew the
// ratio that framing produced, because only dcrd's *file sizes* were ever
// measured: dividing by dcroxide's payload assumes both stores hold
// identical bytes, and one cross-check falsifies that — dcrd's whole utxodb
// is 0.108 GiB where dcroxide's utxosetv3 payload alone is 0.13, which no
// amount of structural efficiency can produce over the same bytes. dcrd's
// domain-level compressed encodings are smaller payload, not smaller
// overhead, and the two effects cannot be separated without this number.
//
// The measurement mirrors `dcroxide-bench redbstat --buckets` so the two
// sides are directly comparable: iterate every key/value pair, attribute it
// to a bucket by ffldb's four-byte bucket-id prefix, and sum key plus value
// bytes. ffldb's layout is the one dcroxide ports exactly — `bidx` +
// parent id + name for the bucket index, bucket id + key for data — so the
// same attribution applies to both.
//
// The UTXO set lives in a separate goleveldb (`utxodb`) that is not
// bucketized; it is summed whole.
//
// Point this at a COPY. goleveldb runs recovery on open, and a datadir that
// figures are quoted from should not be written to.
//
// Usage:
//
//	dcrdstat -datadir <dir>   # containing blocks_ffldb/ and utxodb/
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

// ffldb's key layout, from dcrd database/ffldb/db.go.
var bucketIndexPrefix = []byte("bidx")

// bucketTotals accumulates one bucket's rows and stored bytes.
type bucketTotals struct {
	Name         string `json:"name"`
	Rows         uint64 `json:"rows"`
	PayloadBytes uint64 `json:"payload_bytes"`
	LargestRow   uint64 `json:"largest_row_bytes"`
}

// MeanRowBytes is the mean stored bytes per row.
func (b bucketTotals) MeanRowBytes() float64 {
	if b.Rows == 0 {
		return 0
	}
	return float64(b.PayloadBytes) / float64(b.Rows)
}

type report struct {
	MetadataFileBytes uint64         `json:"metadata_file_bytes"`
	UtxoFileBytes     uint64         `json:"utxo_file_bytes"`
	MetadataPayload   uint64         `json:"metadata_payload_bytes"`
	UtxoPayload       uint64         `json:"utxo_payload_bytes"`
	UtxoRows          uint64         `json:"utxo_rows"`
	Buckets           []bucketTotals `json:"buckets"`
}

// dirBytes sums the apparent size of every regular file under root.
func dirBytes(root string) (uint64, error) {
	var total uint64
	err := filepath.Walk(root, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			total += uint64(info.Size())
		}
		return nil
	})
	return total, err
}

// scanMetadata walks ffldb's metadata database, attributing every data row
// to its bucket by the four-byte id that prefixes the key.
func scanMetadata(path string) (map[[4]byte]*bucketTotals, map[[4]byte]string, uint64, error) {
	db, err := leveldb.OpenFile(path, &opt.Options{ReadOnly: true})
	if err != nil {
		// A datadir left unclean by a killed node needs recovery, which a
		// read-only open refuses. Say so rather than silently writing to
		// something the caller may care about.
		return nil, nil, 0, fmt.Errorf("opening %s read-only: %w "+
			"(if this reports corruption, copy the datadir and recover the copy)", path, err)
	}
	defer db.Close()

	totals := make(map[[4]byte]*bucketTotals)
	names := make(map[[4]byte]string)
	var payload uint64

	iter := db.NewIterator(nil, nil)
	defer iter.Release()
	for iter.Next() {
		key := iter.Key()
		val := iter.Value()
		payload += uint64(len(key)) + uint64(len(val))

		if bytes.HasPrefix(key, bucketIndexPrefix) {
			// `bidx` + parent id (4) + name -> child bucket id (4).
			if len(val) == 4 && len(key) > len(bucketIndexPrefix)+4 {
				var id [4]byte
				copy(id[:], val)
				names[id] = string(key[len(bucketIndexPrefix)+4:])
			}
			continue
		}
		if len(key) < 4 {
			continue
		}
		var id [4]byte
		copy(id[:], key[:4])
		t := totals[id]
		if t == nil {
			t = &bucketTotals{}
			totals[id] = t
		}
		t.Rows++
		n := uint64(len(key)) + uint64(len(val))
		t.PayloadBytes += n
		if n > t.LargestRow {
			t.LargestRow = n
		}
	}
	return totals, names, payload, iter.Error()
}

// scanUtxo sums the UTXO database, which is not bucketized.
func scanUtxo(path string) (uint64, uint64, error) {
	db, err := leveldb.OpenFile(path, &opt.Options{ReadOnly: true})
	if err != nil {
		return 0, 0, fmt.Errorf("opening %s read-only: %w", path, err)
	}
	defer db.Close()

	var rows, payload uint64
	iter := db.NewIterator(nil, nil)
	defer iter.Release()
	for iter.Next() {
		rows++
		payload += uint64(len(iter.Key())) + uint64(len(iter.Value()))
	}
	return rows, payload, iter.Error()
}

func main() {
	datadir := flag.String("datadir", "", "a dcrd network data directory (required)")
	asJSON := flag.Bool("json", false, "emit JSON instead of a table")
	flag.Parse()
	if *datadir == "" {
		fmt.Fprintln(os.Stderr, "usage: dcrdstat -datadir <dir> [-json]")
		os.Exit(2)
	}

	metaPath := filepath.Join(*datadir, "blocks_ffldb", "metadata")
	utxoPath := filepath.Join(*datadir, "utxodb")

	totals, names, metaPayload, err := scanMetadata(metaPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	utxoRows, utxoPayload, err := scanUtxo(utxoPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	metaFile, _ := dirBytes(metaPath)
	utxoFile, _ := dirBytes(utxoPath)

	rep := report{
		MetadataFileBytes: metaFile,
		UtxoFileBytes:     utxoFile,
		MetadataPayload:   metaPayload,
		UtxoPayload:       utxoPayload,
		UtxoRows:          utxoRows,
	}
	for id, t := range totals {
		name := names[id]
		if name == "" {
			name = fmt.Sprintf("<id %02x%02x%02x%02x>", id[0], id[1], id[2], id[3])
		}
		t.Name = name
		rep.Buckets = append(rep.Buckets, *t)
	}
	sort.Slice(rep.Buckets, func(i, j int) bool {
		return rep.Buckets[i].PayloadBytes > rep.Buckets[j].PayloadBytes
	})

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
		return
	}

	const mib = 1024.0 * 1024.0
	fmt.Printf("%-24s %12s %14s %11s\n", "bucket", "rows", "payload MiB", "mean row")
	for _, b := range rep.Buckets {
		fmt.Printf("%-24s %12d %14.1f %11.0f\n",
			b.Name, b.Rows, float64(b.PayloadBytes)/mib, b.MeanRowBytes())
	}
	fmt.Printf("\n%-24s %12d %14.1f\n", "utxodb (not bucketized)", utxoRows, float64(utxoPayload)/mib)
	fmt.Println()
	total := metaPayload + utxoPayload
	files := metaFile + utxoFile
	fmt.Printf("payload   metadata %.2f GiB + utxo %.2f GiB = %.2f GiB\n",
		float64(metaPayload)/mib/1024, float64(utxoPayload)/mib/1024, float64(total)/mib/1024)
	fmt.Printf("on disk   metadata %.2f GiB + utxo %.2f GiB = %.2f GiB\n",
		float64(metaFile)/mib/1024, float64(utxoFile)/mib/1024, float64(files)/mib/1024)
	if total > 0 {
		fmt.Printf("\ngoleveldb structural overhead over its own payload: %.2fx\n",
			float64(files)/float64(total))
		fmt.Println("compare dcroxide: redbstat --buckets reports the same two numbers.")
	}
}
