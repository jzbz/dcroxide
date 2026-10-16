// SPDX-License-Identifier: ISC

//go:build dcroxide_export

// The generator of crates/dcroxide-blockchain/tests/data/utxoview_vectors.txt.
// It runs as a test inside dcrd's own internal/blockchain package, so every
// state it writes is what dcrd's utxo viewpoint made of the blocks; run.sh in
// this directory arranges that without touching the dcrd checkout.  The rows
// it writes are those the replay in
// crates/dcroxide-blockchain/tests/utxoview_vectors.rs reads.
//
// Its inputs are the rows of the file it regenerates that are not derived:
// the base view (`base` and its entry rows) and the two blocks (`parent` and
// `block`).  Every other row is computed again by dcrd's code at the commit
// it runs in:
//
//   - parent: the parent's regular tree is fetched and connected over the
//     base view (fetchRegularInputUtxos, connectRegularTransactions), which
//     writes `pstxos` and `afterparent`;
//   - block: the child, which disapproves the parent, is connected by
//     connectBlock, which reads the parent's spend journal from a test
//     database the exporter wrote `pstxos` to, and writes `stxos` and
//     `afterconnect`;
//   - the child is disconnected by disconnectBlock, which writes
//     `afterdisconnect`.
//
// One view is kept across the three steps and never committed.  Fetches go
// to a cache that holds nothing, so an outpoint the view lacks resolves to
// dcrd's nil entry; nil entries are left out of the rows, since the port's
// view stores nothing for them.  Entry rows are sorted by outpoint hash
// bytes, then index, then tree, the order the port's view iterates in, and
// hashes are written in their byte order.  The treasury agenda is active
// throughout and the network is regnet.

package blockchain

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/database/v3"
	"github.com/decred/dcrd/dcrutil/v4"
	"github.com/decred/dcrd/wire"
)

// exportEmptyCache is a utxo cache that holds nothing: every outpoint the
// view asks for resolves to a nil entry, as a missing output does in dcrd's
// UtxoCache.FetchEntries.  The view calls nothing else of it here.
type exportEmptyCache struct {
	UtxoCacher
}

func (exportEmptyCache) FetchEntries(filteredSet ViewFilteredSet, view *UtxoViewpoint) error {
	for outpoint := range filteredSet {
		view.entries[outpoint] = nil
	}
	return nil
}

// exportHex is the hex of a byte string, or "-" for an empty one.
func exportHex(b []byte) string {
	if len(b) == 0 {
		return "-"
	}
	return hex.EncodeToString(b)
}

// exportUnhex is the inverse of exportHex.
func exportUnhex(t *testing.T, s string) []byte {
	t.Helper()
	if s == "-" {
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func exportUint(t *testing.T, s string, bits int) uint64 {
	t.Helper()
	v, err := strconv.ParseUint(s, 10, bits)
	if err != nil {
		t.Fatalf("bad number %q: %v", s, err)
	}
	return v
}

// exportParseEntry reads an entry row: `e hash index tree amount height
// blockindex scriptversion state flags pkscript minouts`.
func exportParseEntry(t *testing.T, row string) (wire.OutPoint, *UtxoEntry) {
	t.Helper()
	f := strings.Split(row, " ")
	if len(f) != 12 || f[0] != "e" {
		t.Fatalf("bad entry row %q", row)
	}
	var outpoint wire.OutPoint
	copy(outpoint.Hash[:], exportUnhex(t, f[1]))
	outpoint.Index = uint32(exportUint(t, f[2], 32))
	tree, err := strconv.ParseInt(f[3], 10, 8)
	if err != nil {
		t.Fatalf("bad tree in %q: %v", row, err)
	}
	outpoint.Tree = int8(tree)
	amount, err := strconv.ParseInt(f[4], 10, 64)
	if err != nil {
		t.Fatalf("bad amount in %q: %v", row, err)
	}
	entry := &UtxoEntry{
		amount:        amount,
		pkScript:      exportUnhex(t, f[10]),
		blockHeight:   uint32(exportUint(t, f[5], 32)),
		blockIndex:    uint32(exportUint(t, f[6], 32)),
		scriptVersion: uint16(exportUint(t, f[7], 16)),
		state:         utxoState(exportUint(t, f[8], 8)),
		packedFlags:   utxoFlags(exportUint(t, f[9], 8)),
	}
	if minOuts := exportUnhex(t, f[11]); minOuts != nil {
		entry.ticketMinOuts = &ticketMinimalOutputs{data: minOuts}
	}
	return outpoint, entry
}

// exportParseBlock reads a block from its hex and checks that it serializes
// back to the same bytes.
func exportParseBlock(t *testing.T, s string) *dcrutil.Block {
	t.Helper()
	raw := exportUnhex(t, s)
	var msgBlock wire.MsgBlock
	if err := msgBlock.Deserialize(bytes.NewReader(raw)); err != nil {
		t.Fatalf("bad block: %v", err)
	}
	var buf bytes.Buffer
	if err := msgBlock.Serialize(&buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), raw) {
		t.Fatal("a block does not serialize back to its input bytes")
	}
	return dcrutil.NewBlock(&msgBlock)
}

// exportWriter collects the rows of the file.
type exportWriter struct {
	rows []string
}

func (w *exportWriter) row(format string, args ...any) {
	w.rows = append(w.rows, fmt.Sprintf(format, args...))
}

// snapshot writes the view's entries under a header row naming their count
// and the view's best hash.
func (w *exportWriter) snapshot(tag string, view *UtxoViewpoint) {
	outpoints := make([]wire.OutPoint, 0, len(view.entries))
	for outpoint, entry := range view.entries {
		if entry != nil {
			outpoints = append(outpoints, outpoint)
		}
	}
	sort.Slice(outpoints, func(i, j int) bool {
		a, b := &outpoints[i], &outpoints[j]
		if c := bytes.Compare(a.Hash[:], b.Hash[:]); c != 0 {
			return c < 0
		}
		if a.Index != b.Index {
			return a.Index < b.Index
		}
		return a.Tree < b.Tree
	})
	best := view.BestHash()
	w.row("%s %d %s", tag, len(outpoints), hex.EncodeToString(best[:]))
	for _, outpoint := range outpoints {
		entry := view.entries[outpoint]
		var minOuts []byte
		if entry.ticketMinOuts != nil {
			minOuts = entry.ticketMinOuts.data
		}
		w.row("e %s %d %d %d %d %d %d %d %d %s %s",
			hex.EncodeToString(outpoint.Hash[:]), outpoint.Index, outpoint.Tree,
			entry.amount, entry.blockHeight, entry.blockIndex,
			entry.scriptVersion, entry.state, entry.packedFlags,
			exportHex(entry.pkScript), exportHex(minOuts))
	}
}

// stxos writes a spend journal under a header row naming its length.
func (w *exportWriter) stxos(tag string, stxos []spentTxOut) {
	w.row("%s %d", tag, len(stxos))
	for i := range stxos {
		stxo := &stxos[i]
		var minOuts []byte
		if stxo.ticketMinOuts != nil {
			minOuts = stxo.ticketMinOuts.data
		}
		w.row("s %d %d %d %d %d %s %s", stxo.amount, stxo.blockHeight,
			stxo.blockIndex, stxo.scriptVersion, stxo.packedFlags,
			exportHex(stxo.pkScript), exportHex(minOuts))
	}
}

// TestExportUtxoViewVectors regenerates the file named by
// DCROXIDE_UTXOVIEW_VECTORS from the inputs in the file named by
// DCROXIDE_UTXOVIEW_INPUT, which may be the same file.
func TestExportUtxoViewVectors(t *testing.T) {
	inPath := os.Getenv("DCROXIDE_UTXOVIEW_INPUT")
	outPath := os.Getenv("DCROXIDE_UTXOVIEW_VECTORS")
	if inPath == "" || outPath == "" {
		t.Skip("DCROXIDE_UTXOVIEW_INPUT and DCROXIDE_UTXOVIEW_VECTORS are not set")
	}

	// Read the inputs.
	input, err := os.ReadFile(inPath)
	if err != nil {
		t.Fatal(err)
	}
	type baseEntry struct {
		outpoint wire.OutPoint
		entry    *UtxoEntry
	}
	var base []baseEntry
	var baseBest chainhash.Hash
	var parentHex, blockHex string
	lines := strings.Split(strings.TrimSuffix(string(input), "\n"), "\n")
	for i := 0; i < len(lines); i++ {
		f := strings.Split(lines[i], " ")
		switch f[0] {
		case "base":
			if len(f) != 3 || base != nil {
				t.Fatalf("bad base row %q", lines[i])
			}
			copy(baseBest[:], exportUnhex(t, f[2]))
			count := int(exportUint(t, f[1], 32))
			for j := 0; j < count; j++ {
				i++
				outpoint, entry := exportParseEntry(t, lines[i])
				base = append(base, baseEntry{outpoint, entry})
			}
		case "parent":
			parentHex = f[1]
		case "block":
			blockHex = f[1]
		}
	}
	if base == nil || parentHex == "" || blockHex == "" {
		t.Fatal("the input lacks the base view or a block")
	}
	parent := exportParseBlock(t, parentHex)
	block := exportParseBlock(t, blockHex)
	if headerApprovesParent(&block.MsgBlock().Header) {
		t.Fatal("the child block must disapprove its parent")
	}

	const isTreasuryEnabled = true
	params := chaincfg.RegNetParams()
	chain, err := chainSetup(t, params)
	if err != nil {
		t.Fatal(err)
	}

	var w exportWriter
	view := NewUtxoViewpoint(exportEmptyCache{})
	view.SetBestHash(&baseBest)
	for _, b := range base {
		view.entries[b.outpoint] = b.entry
	}
	w.snapshot("base", view)

	// Connect the parent's regular tree over the base view.
	w.row("parent %s", parentHex)
	err = view.fetchRegularInputUtxos(parent, isTreasuryEnabled)
	if err != nil {
		t.Fatal(err)
	}
	var parentStxos []spentTxOut
	view.connectRegularTransactions(parent, &parentStxos, isTreasuryEnabled)
	w.stxos("pstxos", parentStxos)
	w.snapshot("afterparent", view)

	// The child's connect reads the parent's spend journal from the
	// database to undo the parent's regular tree.
	err = chain.db.Update(func(dbTx database.Tx) error {
		return dbPutSpendJournalEntry(dbTx, parent.Hash(), parentStxos)
	})
	if err != nil {
		t.Fatal(err)
	}
	w.row("block %s", blockHex)
	var stxos []spentTxOut
	err = view.connectBlock(chain.db, params, block, parent, &stxos,
		isTreasuryEnabled)
	if err != nil {
		t.Fatal(err)
	}
	w.stxos("stxos", stxos)
	w.snapshot("afterconnect", view)

	// Disconnect the child again, which redoes the parent's regular tree.
	err = view.disconnectBlock(params, block, parent, stxos, isTreasuryEnabled)
	if err != nil {
		t.Fatal(err)
	}
	w.snapshot("afterdisconnect", view)

	file, err := os.Create(outPath)
	if err != nil {
		t.Fatal(err)
	}
	out := bufio.NewWriter(file)
	for _, row := range w.rows {
		fmt.Fprintln(out, row)
	}
	if err := out.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
