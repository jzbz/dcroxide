// SPDX-License-Identifier: ISC

//go:build dcroxide_export

// The generator of crates/dcroxide-blockchain/tests/data/disapproval_vectors.txt.
// It runs as a test inside dcrd's own internal/blockchain package, so every
// expectation it writes is what dcrd's chain did with the blocks; run.sh in
// this directory arranges that without touching the dcrd checkout.  The rows
// it writes are those the replay in
// crates/dcroxide-blockchain/tests/disapproval_vectors.rs reads.
//
// It plays dcrd's TestDisapprovalScenarios (utxoviewpoint_test.go:259-755 at
// the parity pin) call for call, once with the utxo cache flushing and once
// with flushing turned off, and records each block the chain processes, the
// tip and spendability checks, the forced flushes, every flush the cache
// made, and the utxo set state the backend records after each step.  The
// harness methods are called through a recorder that runs the same checks
// they do; a block is processed by the recorder itself, with the checks of
// AcceptTipBlock and AcceptedToSideChainWithExpectedTip, so that the fork
// length can be written down.
//
// chaingen stamps block one with the wall clock, draws coinbase extra nonces
// from crypto/rand and takes whichever proof of work solution one of its
// threads finds first, and the chain judges timestamps and whether it is
// current against its time source.  run.sh overlays a copy of chaingen's
// generator.go in which ExportReset sets block one's time and restarts a
// fixed stream in place of crypto/rand, and which searches on one thread;
// each run starts with ExportReset, so both runs generate the same blocks,
// and the chain gets a time source fixed at block one's time.  A run at an
// unchanged parity pin therefore writes the same file byte for byte.  This
// file calls ExportReset, so the generator cannot be built against an
// unseamed chaingen.

package blockchain

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/decred/dcrd/blockchain/stake/v5"
	"github.com/decred/dcrd/blockchain/v5/chaingen"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/dcrutil/v4"
	"github.com/decred/dcrd/wire"
)

// exportNow is block one's timestamp and the chain's adjusted time: the time
// of the parity pin's commit, 2026-10-13 22:36:39 UTC.
var exportNow = time.Unix(1791930999, 0)

// exportTimeSource is a MedianTimeSource fixed at exportNow.
type exportTimeSource struct{}

func (exportTimeSource) AdjustedTime() time.Time         { return exportNow }
func (exportTimeSource) AddTimeSample(string, time.Time) {}
func (exportTimeSource) Offset() time.Duration           { return 0 }

// exportRecorder wraps a chaingen harness and writes a row for each call the
// scenarios make that the replay must repeat or check.
type exportRecorder struct {
	t       *testing.T
	g       *chaingenHarness
	rows    []string
	flushes []chainhash.Hash
	blocks  *exportBlocks
}

// exportBlocks holds every block either run processed, by name in the order
// first seen, and refuses a name that stands for two blocks.
type exportBlocks struct {
	names  []string
	byName map[string]*wire.MsgBlock
}

func (b *exportBlocks) add(t *testing.T, name string, block *wire.MsgBlock) {
	t.Helper()
	if prev, ok := b.byName[name]; ok {
		if prev.BlockHash() != block.BlockHash() {
			t.Fatalf("block %q differs between the runs", name)
		}
		return
	}
	b.names = append(b.names, name)
	b.byName[name] = block
}

func (r *exportRecorder) row(format string, args ...any) {
	r.rows = append(r.rows, fmt.Sprintf(format, args...))
}

// endStep writes the flushes the cache made during the step just recorded,
// then the utxo set state its backend records.
func (r *exportRecorder) endStep() {
	r.t.Helper()
	for _, hash := range r.flushes {
		node := r.g.chain.index.LookupNode(&hash)
		if node == nil {
			r.t.Fatalf("flush at unknown block %s", hash)
		}
		r.row("flushed %s %d", hash, node.height)
	}
	r.flushes = r.flushes[:0]
	state, err := r.g.chain.utxoCache.FetchBackendState()
	if err != nil {
		r.t.Fatal(err)
	}
	r.row("state %s %d", state.lastFlushHash, state.lastFlushHeight)
}

// process hands the named block to the chain as AcceptBlock does, with the
// main chain check when mainChain is set and the side chain check otherwise.
func (r *exportRecorder) process(name string, mainChain bool) {
	r.t.Helper()
	msgBlock := r.g.BlockByName(name)
	r.blocks.add(r.t, name, msgBlock)
	forkLen, err := r.g.chain.ProcessBlock(dcrutil.NewBlock(msgBlock))
	if err != nil {
		r.t.Fatalf("block %q should have been accepted: %v", name, err)
	}
	if isMainChain := forkLen == 0; isMainChain != mainChain {
		r.t.Fatalf("block %q unexpected main chain flag -- got %v, want %v",
			name, isMainChain, mainChain)
	}
	r.row("process %s %d", name, forkLen)
	r.endStep()
}

func (r *exportRecorder) AcceptTipBlock() {
	r.t.Helper()
	r.process(r.g.TipName(), true)
}

func (r *exportRecorder) AcceptedToSideChainWithExpectedTip(tipName string) {
	r.t.Helper()
	r.process(r.g.TipName(), false)
	r.ExpectTip(tipName)
}

func (r *exportRecorder) ExpectTip(tipName string) {
	r.t.Helper()
	r.g.ExpectTip(tipName)
	r.row("tip %s", tipName)
}

func (r *exportRecorder) AssertTipDisapprovesPrevious() {
	r.t.Helper()
	r.g.AssertTipDisapprovesPrevious()
	r.row("disapproves %s", r.g.TipName())
}

func (r *exportRecorder) ExpectUtxoSpendable(outpoint wire.OutPoint) {
	r.t.Helper()
	r.g.ExpectUtxoSpendable(outpoint)
	r.row("spendable %s %d %d", outpoint.Hash, outpoint.Index, outpoint.Tree)
}

func (r *exportRecorder) ExpectUtxoUnspendable(outpoint wire.OutPoint) {
	r.t.Helper()
	r.g.ExpectUtxoUnspendable(outpoint)
	r.row("unspendable %s %d %d", outpoint.Hash, outpoint.Index, outpoint.Tree)
}

func (r *exportRecorder) ForceUtxoCacheFlush() {
	r.t.Helper()
	r.g.ForceUtxoCacheFlush()
	r.row("forceflush")
	r.endStep()
}

func (r *exportRecorder) DisableUtxoCacheFlushes() {
	r.t.Helper()
	r.g.DisableUtxoCacheFlushes()
	r.row("disableflushes")
}

// AdvanceToStakeValidationHeight runs the harness's own, which accepts every
// block it generates, then writes those blocks as processed, each with the
// flushes made at it, and the state the advance ends in.
func (r *exportRecorder) AdvanceToStakeValidationHeight() {
	r.t.Helper()
	r.g.AdvanceToStakeValidationHeight()
	flushes := make(map[chainhash.Hash]int)
	for _, hash := range r.flushes {
		flushes[hash]++
	}
	r.flushes = r.flushes[:0]
	best := r.g.chain.BestSnapshot()
	for height := int64(1); height <= best.Height; height++ {
		block, err := r.g.chain.BlockByHeight(height)
		if err != nil {
			r.t.Fatal(err)
		}
		name := r.g.BlockName(block.Hash())
		r.blocks.add(r.t, name, block.MsgBlock())
		r.row("process %s 0", name)
		for ; flushes[*block.Hash()] > 0; flushes[*block.Hash()]-- {
			r.row("flushed %s %d", block.Hash(), height)
		}
		delete(flushes, *block.Hash())
	}
	if len(flushes) != 0 {
		r.t.Fatalf("flushes not at a block of the advance: %v", flushes)
	}
	r.flushes = r.flushes[:0]
	r.endStep()
}

// exportScenarios is testDisapprovalScenarios (utxoviewpoint_test.go:259-733)
// with the harness calls the replay repeats or checks made through the
// recorder.  The generator calls are dcrd's.
func exportScenarios(t *testing.T, flushUtxoCache bool, blocks *exportBlocks) []string {
	chaingen.ExportReset(exportNow)
	params := chaincfg.RegNetParams()
	g := newChaingenHarness(t, params)
	g.chain.timeSource = exportTimeSource{}
	r := &exportRecorder{t: t, g: g, blocks: blocks}
	cache := g.chain.utxoCache.(*testUtxoCache).UtxoCache
	cache.timeNow = func() time.Time {
		// The cache stamps every completed flush, right after it records
		// the hash flushed through (utxocache.go:768-769).
		r.flushes = append(r.flushes, cache.lastFlushHash)
		return time.Now()
	}
	mode := "flush-enabled"
	if !flushUtxoCache {
		mode = "flush-disabled"
	}
	r.row("test %s", mode)
	r.row("params regnet")
	r.row("now %d", exportNow.Unix())

	r.AdvanceToStakeValidationHeight()
	r.ForceUtxoCacheFlush()

	if !flushUtxoCache {
		r.DisableUtxoCacheFlushes()
	}

	outpoint := func(tx *wire.MsgTx, index uint32) wire.OutPoint {
		hash := tx.TxHash()
		return *wire.NewOutPoint(&hash, index, wire.TxTreeRegular)
	}
	stakeOutpoint := func(tx *wire.MsgTx, index uint32) wire.OutPoint {
		hash := tx.TxHash()
		return *wire.NewOutPoint(&hash, index, wire.TxTreeStake)
	}
	findSpendingTicket := func(b *wire.MsgBlock, out wire.OutPoint) *wire.MsgTx {
		t.Helper()
		for _, tx := range b.STransactions {
			if !stake.IsSStx(tx) {
				continue
			}
			for _, txIn := range tx.TxIn {
				if txIn.PreviousOutPoint == out {
					return tx
				}
			}
		}
		t.Fatalf("no ticket spends outpoint %v (tree %d)", out, out.Tree)
		return nil
	}
	disapproveParent := func(b *wire.MsgBlock) {
		const (
			voteBitNo  = 0x0000
			voteBitYes = 0x0001
		)
		b.Header.VoteBits &^= voteBitYes
		g.ReplaceVoteBits(voteBitNo)(b)
	}
	addTx := func(tx *wire.MsgTx) func(b *wire.MsgBlock) {
		return func(b *wire.MsgBlock) {
			b.AddTransaction(tx)
		}
	}
	addZeroConfSpend := func(txIndex, txOutIndex uint32) func(b *wire.MsgBlock) {
		return func(b *wire.MsgBlock) {
			const fee = dcrutil.Amount(1)
			spend := chaingen.MakeSpendableOut(b, txIndex, txOutIndex)
			b.AddTransaction(g.CreateSpendTx(&spend, fee))
		}
	}

	// s1: a disapproval followed by spending a resurrected output in a
	// different regular transaction (:334-366).
	{
		outs := g.OldestCoinbaseOuts()
		sharedSpend := outs[0]
		b0 := g.NextBlock("s1b0", &sharedSpend, outs[1:])
		r.AcceptTipBlock()
		txA := b0.Transactions[1]
		r.ExpectUtxoUnspendable(txA.TxIn[0].PreviousOutPoint)
		r.ExpectUtxoSpendable(outpoint(txA, 0))

		ticketOuts := g.OldestCoinbaseOuts()
		b1 := g.NextBlock("s1b1", &sharedSpend, ticketOuts[1:], disapproveParent)
		r.AssertTipDisapprovesPrevious()
		r.AcceptTipBlock()
		r.ExpectTip("s1b1")
		txB := b1.Transactions[1]
		r.ExpectUtxoUnspendable(txA.TxIn[0].PreviousOutPoint)
		r.ExpectUtxoUnspendable(outpoint(txA, 0))
		r.ExpectUtxoSpendable(outpoint(txB, 0))
	}

	// s2: the same, spent by a ticket (:368-404).
	{
		outs := g.OldestCoinbaseOuts()
		sharedSpend := outs[0]
		b0 := g.NextBlock("s2b0", &sharedSpend, outs[1:])
		r.AcceptTipBlock()
		txA := b0.Transactions[1]
		r.ExpectUtxoUnspendable(txA.TxIn[0].PreviousOutPoint)
		r.ExpectUtxoSpendable(outpoint(txA, 0))

		outs = g.OldestCoinbaseOuts()
		outs[1] = sharedSpend
		b1 := g.NextBlock("s2b1", nil, outs[1:], disapproveParent)
		r.AssertTipDisapprovesPrevious()
		r.AcceptTipBlock()
		r.ExpectTip("s2b1")
		ticket := findSpendingTicket(b1, sharedSpend.PrevOut())
		r.ExpectUtxoUnspendable(txA.TxIn[0].PreviousOutPoint)
		r.ExpectUtxoUnspendable(outpoint(txA, 0))
		r.ExpectUtxoSpendable(stakeOutpoint(ticket, 0))
	}

	// s3: a disapproved zero conf chain with only the creating transaction
	// reincluded (:406-441).
	{
		outs := g.OldestCoinbaseOuts()
		b0 := g.NextBlock("s3b0", &outs[0], outs[1:], addZeroConfSpend(1, 0))
		r.AcceptTipBlock()
		txA := b0.Transactions[1]
		txB := b0.Transactions[2]
		r.ExpectUtxoUnspendable(txA.TxIn[0].PreviousOutPoint)
		r.ExpectUtxoUnspendable(outpoint(txA, 0))
		r.ExpectUtxoSpendable(outpoint(txB, 0))

		outs = g.OldestCoinbaseOuts()
		g.NextBlock("s3b1", nil, outs[1:], disapproveParent, addTx(txA))
		r.AssertTipDisapprovesPrevious()
		r.AcceptTipBlock()
		r.ExpectTip("s3b1")
		r.ExpectUtxoUnspendable(txA.TxIn[0].PreviousOutPoint)
		r.ExpectUtxoSpendable(outpoint(txA, 0))
		r.ExpectUtxoUnspendable(outpoint(txB, 0))
	}

	// s4: a reincluded transaction with a new zero conf spend of its output
	// (:443-477).
	{
		outs := g.OldestCoinbaseOuts()
		b0 := g.NextBlock("s4b0", &outs[0], outs[1:])
		r.AcceptTipBlock()
		txA := b0.Transactions[1]
		r.ExpectUtxoUnspendable(txA.TxIn[0].PreviousOutPoint)
		r.ExpectUtxoSpendable(outpoint(txA, 0))

		outs = g.OldestCoinbaseOuts()
		b1 := g.NextBlock("s4b1", nil, outs[1:], disapproveParent, addTx(txA),
			addZeroConfSpend(1, 0))
		r.AssertTipDisapprovesPrevious()
		r.AcceptTipBlock()
		r.ExpectTip("s4b1")
		txB := b1.Transactions[2]
		r.ExpectUtxoUnspendable(txA.TxIn[0].PreviousOutPoint)
		r.ExpectUtxoUnspendable(outpoint(txA, 0))
		r.ExpectUtxoSpendable(outpoint(txB, 0))
	}

	// s5: a zero conf spend replaced in the disapproving block (:479-516).
	{
		outs := g.OldestCoinbaseOuts()
		b0 := g.NextBlock("s5b0", &outs[0], outs[1:], addZeroConfSpend(1, 0))
		r.AcceptTipBlock()
		txA := b0.Transactions[1]
		txB := b0.Transactions[2]
		r.ExpectUtxoUnspendable(txA.TxIn[0].PreviousOutPoint)
		r.ExpectUtxoUnspendable(outpoint(txA, 0))
		r.ExpectUtxoSpendable(outpoint(txB, 0))

		outs = g.OldestCoinbaseOuts()
		b1 := g.NextBlock("s5b1", nil, outs[1:], disapproveParent, addTx(txA),
			addZeroConfSpend(1, 0))
		r.AssertTipDisapprovesPrevious()
		r.AcceptTipBlock()
		r.ExpectTip("s5b1")
		txC := b1.Transactions[2]
		r.ExpectUtxoUnspendable(txA.TxIn[0].PreviousOutPoint)
		r.ExpectUtxoUnspendable(outpoint(txA, 0))
		r.ExpectUtxoUnspendable(outpoint(txB, 0))
		r.ExpectUtxoSpendable(outpoint(txC, 0))
	}

	// s6: a reorganization to a branch that approves the parent (:518-561).
	{
		outs := g.OldestCoinbaseOuts()
		b0 := g.NextBlock("s6b0", &outs[0], outs[1:], addZeroConfSpend(1, 0))
		r.AcceptTipBlock()
		txA := b0.Transactions[1]
		txB := b0.Transactions[2]
		r.ExpectUtxoUnspendable(txA.TxIn[0].PreviousOutPoint)
		r.ExpectUtxoUnspendable(outpoint(txA, 0))
		r.ExpectUtxoSpendable(outpoint(txB, 0))

		outs = g.OldestCoinbaseOuts()
		g.NextBlock("s6b1", nil, outs[1:], disapproveParent, addTx(txA))
		r.AssertTipDisapprovesPrevious()
		r.AcceptTipBlock()
		r.ExpectTip("s6b1")
		r.ExpectUtxoUnspendable(txA.TxIn[0].PreviousOutPoint)
		r.ExpectUtxoSpendable(outpoint(txA, 0))
		r.ExpectUtxoUnspendable(outpoint(txB, 0))

		g.SetTip("s6b0")
		g.NextBlock("s6b1a", nil, outs[1:])
		r.AcceptedToSideChainWithExpectedTip("s6b1")
		g.NextBlock("s6b2a", nil, nil)
		r.AcceptTipBlock()
		r.ExpectTip("s6b2a")
		r.ExpectUtxoUnspendable(txA.TxIn[0].PreviousOutPoint)
		r.ExpectUtxoUnspendable(outpoint(txA, 0))
		r.ExpectUtxoSpendable(outpoint(txB, 0))
	}

	// s7: a reorganization away from and back to a reinclusion branch, with a
	// forced flush first when flushes are off (:563-637).
	{
		outs := g.OldestCoinbaseOuts()
		b0 := g.NextBlock("s7b0", &outs[0], outs[1:], addZeroConfSpend(1, 0))
		r.AcceptTipBlock()
		txA := b0.Transactions[1]
		txB := b0.Transactions[2]
		r.ExpectUtxoUnspendable(txA.TxIn[0].PreviousOutPoint)
		r.ExpectUtxoUnspendable(outpoint(txA, 0))
		r.ExpectUtxoSpendable(outpoint(txB, 0))

		outs = g.OldestCoinbaseOuts()
		g.NextBlock("s7b1", nil, outs[1:], disapproveParent, addTx(txA))
		r.AssertTipDisapprovesPrevious()
		r.AcceptTipBlock()
		r.ExpectTip("s7b1")
		r.ExpectUtxoUnspendable(txA.TxIn[0].PreviousOutPoint)
		r.ExpectUtxoSpendable(outpoint(txA, 0))
		r.ExpectUtxoUnspendable(outpoint(txB, 0))

		if !flushUtxoCache {
			r.ForceUtxoCacheFlush()
		}

		g.SetTip("s7b0")
		g.NextBlock("s7b1a", &outs[0], outs[1:], disapproveParent)
		r.AssertTipDisapprovesPrevious()
		r.AcceptedToSideChainWithExpectedTip("s7b1")
		g.NextBlock("s7b2a", nil, nil)
		r.AcceptTipBlock()
		r.ExpectTip("s7b2a")
		r.ExpectUtxoSpendable(txA.TxIn[0].PreviousOutPoint)
		r.ExpectUtxoUnspendable(outpoint(txA, 0))
		r.ExpectUtxoUnspendable(outpoint(txB, 0))

		g.SetTip("s7b1")
		g.NextBlock("s7b2", nil, nil)
		r.AcceptedToSideChainWithExpectedTip("s7b2a")
		g.NextBlock("s7b3", nil, nil)
		r.AcceptTipBlock()
		r.ExpectTip("s7b3")
		r.ExpectUtxoUnspendable(txA.TxIn[0].PreviousOutPoint)
		r.ExpectUtxoSpendable(outpoint(txA, 0))
		r.ExpectUtxoUnspendable(outpoint(txB, 0))
	}

	// s8: longer zero conf chains across competing disapproving branches
	// (:639-732).
	{
		outs := g.OldestCoinbaseOuts()
		b0 := g.NextBlock("s8b0", &outs[0], outs[1:], addZeroConfSpend(1, 0),
			addZeroConfSpend(2, 0), addZeroConfSpend(3, 0))
		r.AcceptTipBlock()
		txA := b0.Transactions[1]
		txB := b0.Transactions[2]
		txC := b0.Transactions[3]
		txD := b0.Transactions[4]
		r.ExpectUtxoUnspendable(txA.TxIn[0].PreviousOutPoint)
		r.ExpectUtxoUnspendable(outpoint(txA, 0))
		r.ExpectUtxoUnspendable(outpoint(txB, 0))
		r.ExpectUtxoUnspendable(outpoint(txC, 0))
		r.ExpectUtxoSpendable(outpoint(txD, 0))

		outs = g.OldestCoinbaseOuts()
		b1 := g.NextBlock("s8b1", nil, outs[1:], disapproveParent, addTx(txA),
			addZeroConfSpend(1, 0), addZeroConfSpend(2, 0),
			addZeroConfSpend(3, 0))
		r.AssertTipDisapprovesPrevious()
		r.AcceptTipBlock()
		r.ExpectTip("s8b1")
		txE := b1.Transactions[2]
		txF := b1.Transactions[3]
		txG := b1.Transactions[4]
		r.ExpectUtxoUnspendable(txA.TxIn[0].PreviousOutPoint)
		r.ExpectUtxoUnspendable(outpoint(txA, 0))
		r.ExpectUtxoUnspendable(outpoint(txB, 0))
		r.ExpectUtxoUnspendable(outpoint(txC, 0))
		r.ExpectUtxoUnspendable(outpoint(txD, 0))
		r.ExpectUtxoUnspendable(outpoint(txE, 0))
		r.ExpectUtxoUnspendable(outpoint(txF, 0))
		r.ExpectUtxoSpendable(outpoint(txG, 0))

		g.SetTip("s8b0")
		g.NextBlock("s8b1a", &outs[0], outs[1:], disapproveParent)
		r.AssertTipDisapprovesPrevious()
		r.AcceptedToSideChainWithExpectedTip("s8b1")
		g.NextBlock("s8b2a", nil, nil)
		r.AcceptTipBlock()
		r.ExpectTip("s8b2a")
		r.ExpectUtxoSpendable(txA.TxIn[0].PreviousOutPoint)
		r.ExpectUtxoUnspendable(outpoint(txA, 0))
		r.ExpectUtxoUnspendable(outpoint(txB, 0))
		r.ExpectUtxoUnspendable(outpoint(txC, 0))
		r.ExpectUtxoUnspendable(outpoint(txD, 0))
		r.ExpectUtxoUnspendable(outpoint(txE, 0))
		r.ExpectUtxoUnspendable(outpoint(txF, 0))
		r.ExpectUtxoUnspendable(outpoint(txG, 0))

		g.SetTip("s8b1")
		g.NextBlock("s8b2", nil, nil)
		r.AcceptedToSideChainWithExpectedTip("s8b2a")
		g.NextBlock("s8b3", nil, nil)
		r.AcceptTipBlock()
		r.ExpectTip("s8b3")
		r.ExpectUtxoUnspendable(txA.TxIn[0].PreviousOutPoint)
		r.ExpectUtxoUnspendable(outpoint(txA, 0))
		r.ExpectUtxoUnspendable(outpoint(txB, 0))
		r.ExpectUtxoUnspendable(outpoint(txC, 0))
		r.ExpectUtxoUnspendable(outpoint(txD, 0))
		r.ExpectUtxoUnspendable(outpoint(txE, 0))
		r.ExpectUtxoUnspendable(outpoint(txF, 0))
		r.ExpectUtxoSpendable(outpoint(txG, 0))
	}

	if len(r.flushes) != 0 {
		t.Fatalf("flushes outside a recorded step: %v", r.flushes)
	}
	return r.rows
}

// TestExportDisapprovalVectors writes the vector file to the path in
// DCROXIDE_DISAPPROVAL_VECTORS: every block either run processed, in the
// order first seen, then one section per run.
func TestExportDisapprovalVectors(t *testing.T) {
	path := os.Getenv("DCROXIDE_DISAPPROVAL_VECTORS")
	if path == "" {
		t.Skip("DCROXIDE_DISAPPROVAL_VECTORS not set")
	}
	blocks := &exportBlocks{byName: make(map[string]*wire.MsgBlock)}
	var sections [][]string
	for _, flushUtxoCache := range []bool{true, false} {
		sections = append(sections, exportScenarios(t, flushUtxoCache, blocks))
	}

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := bufio.NewWriter(f)
	for _, name := range blocks.names {
		raw, err := blocks.byName[name].Bytes()
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(w, "block %s %s\n", name, hex.EncodeToString(raw))
	}
	for _, rows := range sections {
		for _, row := range rows {
			fmt.Fprintln(w, row)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}
