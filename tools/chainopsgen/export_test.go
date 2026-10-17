// SPDX-License-Identifier: ISC

//go:build dcroxide_export

// The generator of three files in crates/dcroxide-blockchain/tests/data:
// processblock_vectors.txt, invalidate_vectors.txt and reorg_vectors.txt,
// which the replays of the same names in crates/dcroxide-blockchain/tests
// read, as do a few other tests there.  It runs as a test inside dcrd's own
// internal/blockchain package, so every expectation it writes is what dcrd's
// chain did with the file's blocks and operations; run.sh in this directory
// arranges that without touching the dcrd checkout.  One run reads one file
// and writes one file of the same shape.
//
// The blocks are not built here.  They were built once, with seed outpoints,
// payee hashes, extra data and nonces drawn at random, and are read from the
// file being regenerated, together with every other row or field that is not
// derived:
//
//   - the seeded outputs (`u` rows), each committed to the utxo cache as a
//     modified entry in its own view;
//   - the bulk import switches (`bulk`), passed to EnableBulkImportMode;
//   - the blocks given to ProcessBlock (`pb`) and the headers given to
//     ProcessBlockHeader (`hdr`);
//   - the blocks attached as validated (`blk`): each is stored, added to the
//     block index with its data stored and validated, and made a best chain
//     candidate, and a `reorg` row names the tip that reorganizeChain is then
//     asked to reach, under the chain lock;
//   - the operations ForceHeadReorganization (`frg`), InvalidateBlock (`inv`)
//     and ReconsiderBlock (`rec`), with the hashes they name;
//   - where the best state is written (`state`), and the outpoints of the
//     utxo universe (`uc`), in the file's order.
//
// Every other field is written again from dcrd at the commit it runs in: each
// verdict (the error kind, or "ok"), fork length and node status, the best
// state, the tip and the status of every block the file processed after each
// operation, and for each universe outpoint whether FetchUtxoEntry finds it
// unspent, with the entry's fields.  Hashes are written in their byte order.
//
// Every input that spends an output carries a fraud proof of it: ValueIn,
// BlockHeight and BlockIndex name the amount, block height and block index of
// the output.  checkTransactionInputs checks them, but a block connected under
// bulk import or attached as validated skips that check; these files' blocks
// are all connected that way, apart from a few given full validation, which
// fail an earlier check.  An output a disconnect brings back takes them from
// the input that spent it whenever the view does not already hold it, and
// since dcrd 22fd2431 assertBlockUtxoView checks them on every block the chain
// attaches.  DCROXIDE_CHAINOPS_WITNESS picks what the inputs carry:
//
//   - spent (the default): the amount, height and index of the output spent,
//     from the `u` row of a seeded output, or, for an output of one of the
//     file's blocks, from chaingen's MakeSpendableOut or MakeSpendableStakeOut,
//     the values dcrd's own test generator puts on a spend;
//   - constant: 500000000, 0 and 1 on every input that spends an output, the
//     seeded outputs' values, as the files carried before they were
//     regenerated.  It reproduces such a file and nothing else: the run fails
//     if it would change a block or a header.  dcrd 22fd2431 and later panic
//     on those files' blocks.
//
// An input of the null outpoint (a coinbase's, a treasurybase's, a vote's
// stakebase or a treasury spend's) spends no output and keeps what it
// carries.  An output that two of the file's blocks create with different
// details cannot be spent: the run fails.
//
// A block whose transactions change is rewritten.  A header that committed to
// its transactions by the combined merkle root of DCP0005 commits to the new
// ones; a skeleton header with any other root keeps it.  Every header names
// its parent's new hash, parents first, whether the parent is one of the
// file's blocks or a header whose block the file does not hold, and a header
// that changes is ground again from its old nonce upwards until its BLAKE256
// and BLAKE3 proof of work hashes each pass or fail as the old header's did.
// A `hdr` row of one of the file's blocks takes that block's new header; a
// header whose block the file does not hold is relinked and ground the same
// way, its merkle root kept.  The hashes the operation rows name are mapped to
// the new ones; a hash of no block or header in the file is kept.  Since the
// blocks are read from the input, a run over its own output rewrites nothing
// and writes it again byte for byte.

package blockchain

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/decred/dcrd/blockchain/standalone/v2"
	"github.com/decred/dcrd/blockchain/v5/chaingen"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/database/v3"
	"github.com/decred/dcrd/dcrutil/v4"
	"github.com/decred/dcrd/wire"
)

// exportOpsOut is what a fraud proof names of an output.
type exportOpsOut struct {
	amount int64
	height uint32
	index  uint32
}

// exportOpsConstant is the fraud proof the files carried on every input that
// spends an output before they were regenerated.
var exportOpsConstant = exportOpsOut{500000000, 0, 1}

func exportOpsUint(t *testing.T, s string, bits int) uint64 {
	t.Helper()
	v, err := strconv.ParseUint(s, 10, bits)
	if err != nil {
		t.Fatalf("bad number %q: %v", s, err)
	}
	return v
}

func exportOpsInt(t *testing.T, s string, bits int) int64 {
	t.Helper()
	v, err := strconv.ParseInt(s, 10, bits)
	if err != nil {
		t.Fatalf("bad number %q: %v", s, err)
	}
	return v
}

func exportOpsHash(t *testing.T, s string) chainhash.Hash {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != chainhash.HashSize {
		t.Fatalf("bad hash %q", s)
	}
	var h chainhash.Hash
	copy(h[:], b)
	return h
}

func exportOpsHashHex(h chainhash.Hash) string {
	return hex.EncodeToString(h[:])
}

// exportOpsOutPoint reads the `hash index tree` fields of a `u` or `uc` row.
func exportOpsOutPoint(t *testing.T, f []string) wire.OutPoint {
	t.Helper()
	if len(f) < 4 {
		t.Fatalf("short row %q", strings.Join(f, " "))
	}
	return wire.OutPoint{
		Hash:  exportOpsHash(t, f[1]),
		Index: uint32(exportOpsUint(t, f[2], 32)),
		Tree:  int8(exportOpsInt(t, f[3], 8)),
	}
}

// exportOpsKind is a verdict as the files write it: "ok", or the kind of the
// rule or context error.
func exportOpsKind(err error) string {
	if err == nil {
		return "ok"
	}
	var rErr RuleError
	if errors.As(err, &rErr) {
		return fmt.Sprintf("%v", rErr.Err)
	}
	var cErr ContextError
	if errors.As(err, &cErr) {
		return fmt.Sprintf("%v", cErr.Err)
	}
	return "other:" + err.Error()
}

// exportOpsPow is whether the header's BLAKE256 and BLAKE3 proof of work
// hashes each meet its target.
func exportOpsPow(h *wire.BlockHeader) [2]bool {
	v1 := h.PowHashV1()
	v2 := h.PowHashV2()
	return [2]bool{
		standalone.CheckProofOfWorkHash(&v1, h.Bits) == nil,
		standalone.CheckProofOfWorkHash(&v2, h.Bits) == nil,
	}
}

func exportOpsBytes(t *testing.T, mb *wire.MsgBlock) []byte {
	t.Helper()
	b, err := mb.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// exportOpsRewriter puts the witness policy's fraud proofs on every block of
// a file and rewrites the headers that follow from it.
type exportOpsRewriter struct {
	t      *testing.T
	policy string
	seeds  map[wire.OutPoint]exportOpsOut
	// outs holds every output of the file's blocks, from each block that
	// creates it.
	outs map[wire.OutPoint][]chaingen.SpendableOut
	// blocks holds the file's blocks and headers the headers of its `hdr`
	// rows whose block it does not hold, by their hash in the file; done,
	// headersDone and newHash hold the rewritten blocks, the rewritten
	// headers without a block and the new hash of every rewritten block or
	// header, by the same hash.
	blocks      map[chainhash.Hash]*wire.MsgBlock
	headers     map[chainhash.Hash]*wire.BlockHeader
	done        map[chainhash.Hash]*wire.MsgBlock
	headersDone map[chainhash.Hash]wire.BlockHeader
	newHash     map[chainhash.Hash]chainhash.Hash
	// The number of blocks and of headers without a block that changed.
	changedBlocks, changedHeaders int
}

func (r *exportOpsRewriter) witness(op wire.OutPoint) exportOpsOut {
	if r.policy == "constant" {
		return exportOpsConstant
	}
	if s, ok := r.seeds[op]; ok {
		return s
	}
	c := r.outs[op]
	if len(c) == 0 {
		r.t.Fatalf("no seeded output or block of the file creates %v", op)
	}
	for _, o := range c[1:] {
		if o != c[0] {
			r.t.Fatalf("output %v is created twice with different details", op)
		}
	}
	return exportOpsOut{int64(c[0].Amount()), c[0].BlockHeight(), c[0].BlockIndex()}
}

// header returns old with its parent's new hash and, when merkle is not nil,
// that merkle root, ground again when either changes it.  A parent of the
// file not rewritten yet, a block or a header without one, is rewritten
// first.
func (r *exportOpsRewriter) header(old *wire.BlockHeader, merkle *chainhash.Hash) wire.BlockHeader {
	h := *old
	if n, ok := r.newHash[old.PrevBlock]; ok {
		h.PrevBlock = n
	} else if b, ok := r.blocks[old.PrevBlock]; ok {
		h.PrevBlock = r.block(b).Header.BlockHash()
	} else if p, ok := r.headers[old.PrevBlock]; ok {
		ph := r.headerOnly(p)
		h.PrevBlock = ph.BlockHash()
	}
	if merkle != nil {
		h.MerkleRoot = *merkle
	}
	if h == *old {
		return h
	}
	want := exportOpsPow(old)
	for exportOpsPow(&h) != want {
		h.Nonce++
		if h.Nonce == old.Nonce {
			r.t.Fatalf("no nonce grinds header %v as before", old.BlockHash())
		}
	}
	return h
}

// block returns the rewritten copy of one of the file's blocks.
func (r *exportOpsRewriter) block(old *wire.MsgBlock) *wire.MsgBlock {
	oldHash := old.BlockHash()
	if nb, ok := r.done[oldHash]; ok {
		return nb
	}
	oldBytes := exportOpsBytes(r.t, old)
	nb := new(wire.MsgBlock)
	if err := nb.FromBytes(oldBytes); err != nil {
		r.t.Fatal(err)
	}
	for _, txs := range [][]*wire.MsgTx{nb.Transactions, nb.STransactions} {
		for _, tx := range txs {
			for _, in := range tx.TxIn {
				if in.PreviousOutPoint.Hash == (chainhash.Hash{}) {
					continue
				}
				w := r.witness(in.PreviousOutPoint)
				in.ValueIn = w.amount
				in.BlockHeight = w.height
				in.BlockIndex = w.index
			}
		}
	}
	var merkle *chainhash.Hash
	oldRoot := standalone.CalcCombinedTxTreeMerkleRoot(old.Transactions, old.STransactions)
	if oldRoot == old.Header.MerkleRoot {
		m := standalone.CalcCombinedTxTreeMerkleRoot(nb.Transactions, nb.STransactions)
		merkle = &m
	}
	nb.Header = r.header(&old.Header, merkle)
	r.done[oldHash] = nb
	r.newHash[oldHash] = nb.BlockHash()
	if !bytes.Equal(exportOpsBytes(r.t, nb), oldBytes) {
		r.changedBlocks++
	}
	return nb
}

// headerOnly returns the rewritten copy of one of the file's headers whose
// block it does not hold: relinked and ground again, its merkle root kept.
func (r *exportOpsRewriter) headerOnly(old *wire.BlockHeader) wire.BlockHeader {
	oldHash := old.BlockHash()
	if nh, ok := r.headersDone[oldHash]; ok {
		return nh
	}
	nh := r.header(old, nil)
	r.headersDone[oldHash] = nh
	r.newHash[oldHash] = nh.BlockHash()
	if nh != *old {
		r.changedHeaders++
	}
	return nh
}

// mapHash maps a hash an operation row names through the rewrite.
func (r *exportOpsRewriter) mapHash(t *testing.T, s string) chainhash.Hash {
	t.Helper()
	h := exportOpsHash(t, s)
	if n, ok := r.newHash[h]; ok {
		return n
	}
	return h
}

// exportOpsRow is one row of the input, with its block or header rewritten.
type exportOpsRow struct {
	f      []string
	block  *wire.MsgBlock
	header *wire.BlockHeader
}

// exportOpsRead reads the input's rows and rewrites its blocks and headers
// under the witness policy.
func exportOpsRead(t *testing.T, path, policy string) ([]exportOpsRow, *exportOpsRewriter) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	r := &exportOpsRewriter{
		t:           t,
		policy:      policy,
		seeds:       make(map[wire.OutPoint]exportOpsOut),
		outs:        make(map[wire.OutPoint][]chaingen.SpendableOut),
		blocks:      make(map[chainhash.Hash]*wire.MsgBlock),
		headers:     make(map[chainhash.Hash]*wire.BlockHeader),
		done:        make(map[chainhash.Hash]*wire.MsgBlock),
		headersDone: make(map[chainhash.Hash]wire.BlockHeader),
		newHash:     make(map[chainhash.Hash]chainhash.Hash),
	}
	var rows []exportOpsRow
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1<<20), 1<<26)
	for sc.Scan() {
		f := strings.Split(sc.Text(), " ")
		row := exportOpsRow{f: f}
		switch f[0] {
		case "u":
			if len(f) != 10 {
				t.Fatalf("bad seed row %q", sc.Text())
			}
			r.seeds[exportOpsOutPoint(t, f)] = exportOpsOut{
				amount: exportOpsInt(t, f[4], 64),
				height: uint32(exportOpsUint(t, f[5], 32)),
				index:  uint32(exportOpsUint(t, f[6], 32)),
			}
		case "pb", "blk":
			raw, err := hex.DecodeString(f[1])
			if err != nil {
				t.Fatalf("bad block hex: %v", err)
			}
			mb := new(wire.MsgBlock)
			if err := mb.FromBytes(raw); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(exportOpsBytes(t, mb), raw) {
				t.Fatalf("block %v does not serialize to its bytes", mb.BlockHash())
			}
			row.block = mb
			h := mb.BlockHash()
			if _, ok := r.blocks[h]; ok {
				break
			}
			r.blocks[h] = mb
			for i, tx := range mb.Transactions {
				for j := range tx.TxOut {
					s := chaingen.MakeSpendableOut(mb, uint32(i), uint32(j))
					r.outs[s.PrevOut()] = append(r.outs[s.PrevOut()], s)
				}
			}
			for i, tx := range mb.STransactions {
				for j := range tx.TxOut {
					s := chaingen.MakeSpendableStakeOut(mb, uint32(i), uint32(j))
					r.outs[s.PrevOut()] = append(r.outs[s.PrevOut()], s)
				}
			}
		case "hdr":
			raw, err := hex.DecodeString(f[1])
			if err != nil {
				t.Fatalf("bad header hex: %v", err)
			}
			bh := new(wire.BlockHeader)
			if err := bh.FromBytes(raw); err != nil {
				t.Fatal(err)
			}
			row.header = bh
		case "bulk", "reorg", "state", "frg", "inv", "rec", "uc":
		default:
			t.Fatalf("unknown row %q", f[0])
		}
		rows = append(rows, row)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}

	// The headers whose block the file does not hold, so that a block or
	// header naming one as its parent rewrites it first.
	for i := range rows {
		if h := rows[i].header; h != nil {
			hash := h.BlockHash()
			if _, ok := r.blocks[hash]; !ok {
				r.headers[hash] = h
			}
		}
	}

	// Rewrite every block, then every header.
	for i := range rows {
		if rows[i].block != nil {
			rows[i].block = r.block(rows[i].block)
		}
	}
	for i := range rows {
		old := rows[i].header
		if old == nil {
			continue
		}
		var nh wire.BlockHeader
		if b, ok := r.blocks[old.BlockHash()]; ok {
			nh = r.block(b).Header
		} else {
			nh = r.headerOnly(old)
		}
		rows[i].header = &nh
	}
	return rows, r
}

// exportOpsSeed commits a seeded output to the utxo cache as a modified entry.
func exportOpsSeed(t *testing.T, chain *BlockChain, f []string) {
	t.Helper()
	script, err := hex.DecodeString(f[9])
	if err != nil {
		t.Fatalf("bad script %q: %v", f[9], err)
	}
	view := NewUtxoViewpoint(chain.utxoCache)
	view.entries[exportOpsOutPoint(t, f)] = &UtxoEntry{
		amount:        exportOpsInt(t, f[4], 64),
		pkScript:      script,
		blockHeight:   uint32(exportOpsUint(t, f[5], 32)),
		blockIndex:    uint32(exportOpsUint(t, f[6], 32)),
		scriptVersion: uint16(exportOpsUint(t, f[7], 16)),
		packedFlags:   utxoFlags(exportOpsUint(t, f[8], 8)),
		state:         utxoStateModified,
	}
	if err := chain.utxoCache.Commit(view); err != nil {
		t.Fatal(err)
	}
}

// exportOpsUtxoRow writes a `uc` row: whether the outpoint is unspent, and if
// so its entry's amount, height, block index, script version, packed flags
// and script.
func exportOpsUtxoRow(t *testing.T, chain *BlockChain, f []string) string {
	t.Helper()
	entry, err := chain.FetchUtxoEntry(exportOpsOutPoint(t, f))
	if err != nil {
		t.Fatal(err)
	}
	if entry == nil || entry.IsSpent() {
		return fmt.Sprintf("uc %s %s %s 0", f[1], f[2], f[3])
	}
	return fmt.Sprintf("uc %s %s %s 1 %d %d %d %d %d %s", f[1], f[2], f[3],
		entry.Amount(), entry.BlockHeight(), entry.BlockIndex(),
		entry.ScriptVersion(), uint8(entry.packedFlags),
		hex.EncodeToString(entry.PkScript()))
}

func TestExportChainOpsVectors(t *testing.T) {
	in := os.Getenv("DCROXIDE_CHAINOPS_INPUT")
	outPath := os.Getenv("DCROXIDE_CHAINOPS_VECTORS")
	if in == "" || outPath == "" {
		t.Skip("DCROXIDE_CHAINOPS_INPUT or DCROXIDE_CHAINOPS_VECTORS is not set")
	}
	policy := os.Getenv("DCROXIDE_CHAINOPS_WITNESS")
	if policy == "" {
		policy = "spent"
	}
	if policy != "spent" && policy != "constant" {
		t.Fatalf("DCROXIDE_CHAINOPS_WITNESS is %q, not spent or constant", policy)
	}

	rows, r := exportOpsRead(t, in, policy)
	if policy == "constant" && r.changedBlocks+r.changedHeaders != 0 {
		t.Fatalf("the constant witness changes %d blocks and %d headers: it "+
			"only reproduces a file built with it", r.changedBlocks,
			r.changedHeaders)
	}
	t.Logf("%s: witness %s, %d blocks, %d rewritten; %d headers without a "+
		"block, %d rewritten", filepath.Base(in), policy, len(r.blocks),
		r.changedBlocks, len(r.headersDone), r.changedHeaders)

	chain, err := chainSetup(t, chaincfg.SimNetParams())
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	write := func(format string, args ...any) {
		fmt.Fprintf(&out, format, args...)
		out.WriteByte('\n')
	}

	// Every block the file processed, in the order first accepted, for the
	// status lists of the operation rows.
	var processed []chainhash.Hash
	opTail := func() string {
		statuses := make([]string, len(processed))
		for i := range processed {
			statuses[i] = "-"
			if n := chain.index.LookupNode(&processed[i]); n != nil {
				statuses[i] = strconv.Itoa(int(chain.index.NodeStatus(n)))
			}
		}
		tip := chain.bestChain.Tip()
		return fmt.Sprintf("%s %d %s", exportOpsHashHex(tip.hash), tip.height,
			strings.Join(statuses, ","))
	}

	for _, row := range rows {
		f := row.f
		switch f[0] {
		case "u":
			exportOpsSeed(t, chain, f)
			write("%s", strings.Join(f, " "))

		case "bulk":
			chain.EnableBulkImportMode(f[1] == "1")
			write("%s", strings.Join(f, " "))

		case "hdr":
			err := chain.ProcessBlockHeader(row.header)
			raw, err2 := row.header.Bytes()
			if err2 != nil {
				t.Fatal(err2)
			}
			write("hdr %x %s", raw, exportOpsKind(err))
			processed = append(processed, row.header.BlockHash())

		case "pb":
			block := dcrutil.NewBlock(row.block)
			forkLen, err := chain.ProcessBlock(block)
			kind := exportOpsKind(err)
			status := "-"
			if n := chain.index.LookupNode(block.Hash()); n != nil {
				status = strconv.Itoa(int(chain.index.NodeStatus(n)))
			}
			best := chain.BestSnapshot()
			write("pb %x %s %d %s %s %d %d %d %d", exportOpsBytes(t, row.block),
				kind, forkLen, status, exportOpsHashHex(best.Hash), best.Height,
				best.NumTxns, best.TotalTxns, best.TotalSubsidy)
			if err == nil {
				processed = append(processed, *block.Hash())
			}

		case "blk":
			block := dcrutil.NewBlock(row.block)
			parent := chain.index.LookupNode(&row.block.Header.PrevBlock)
			if parent == nil {
				t.Fatalf("block %v: parent %v is not in the block index",
					block.Hash(), row.block.Header.PrevBlock)
			}
			node := newBlockNode(&row.block.Header, parent)
			node.status = statusDataStored | statusValidated
			node.isFullyLinked = true
			chain.index.AddNode(node)
			chain.index.Lock()
			chain.index.addBestChainCandidate(node)
			chain.index.Unlock()
			err := chain.db.Update(func(dbTx database.Tx) error {
				return dbMaybeStoreBlock(dbTx, block)
			})
			if err != nil {
				t.Fatal(err)
			}
			write("blk %x", exportOpsBytes(t, row.block))

		case "reorg":
			hash := r.mapHash(t, f[1])
			target := chain.index.LookupNode(&hash)
			if target == nil {
				t.Fatalf("reorganization target %v is not in the block index", hash)
			}
			chain.chainLock.Lock()
			err := chain.reorganizeChain(target)
			chain.chainLock.Unlock()
			write("reorg %s %s", exportOpsHashHex(hash), exportOpsKind(err))

		case "state":
			b := chain.BestSnapshot()
			write("state %s %s %d %d %d %d %d %d %d %d %d %x",
				exportOpsHashHex(b.Hash), exportOpsHashHex(b.PrevHash), b.Height,
				b.Bits, b.BlockSize, b.NumTxns, b.TotalTxns, b.MedianTime.Unix(),
				b.TotalSubsidy, b.NextPoolSize, b.NextStakeDiff,
				b.NextFinalState[:])

		case "frg":
			pair := strings.Split(f[1], "/")
			if len(pair) != 2 {
				t.Fatalf("bad force reorganization pair %q", f[1])
			}
			former := r.mapHash(t, pair[0])
			newBest := r.mapHash(t, pair[1])
			err := chain.ForceHeadReorganization(former, newBest)
			write("frg %s/%s %s %s", exportOpsHashHex(former),
				exportOpsHashHex(newBest), exportOpsKind(err), opTail())

		case "inv", "rec":
			hash := r.mapHash(t, f[1])
			var err error
			if f[0] == "inv" {
				err = chain.InvalidateBlock(&hash)
			} else {
				err = chain.ReconsiderBlock(&hash)
			}
			write("%s %s %s %s", f[0], exportOpsHashHex(hash),
				exportOpsKind(err), opTail())

		case "uc":
			write("%s", exportOpsUtxoRow(t, chain, f))
		}
	}
	if err := os.WriteFile(outPath, out.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}
