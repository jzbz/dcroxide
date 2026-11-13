// SPDX-License-Identifier: ISC

//go:build dcroxide_export

// The generator of crates/dcroxide-blockchain/tests/data/trsyboundary_vectors.txt.
// It runs as a test inside dcrd's own internal/blockchain package, so every
// expectation it writes is what dcrd's chain did with the blocks; run.sh in
// this directory arranges that without touching the dcrd checkout.
//
// The cases are chains that cross the treasury agenda's activation boundary
// with a block that disapproves its parent, the boundary 37fd3a3e corrects.
// isTreasuryAgendaActive(prev) is the agenda state of the block after prev,
// so the flag of a disapproved parent P is isTreasuryAgendaActive(P.parent),
// and it differs from its child's at one block only: the first block of the
// window in which the agenda is active, H_act, whose parent H_act-1 is still
// before it.  When H_act disapproves H_act-1, undoing H_act-1's regular tree
// with H_act's flag decodes its spend journal as if its first stake
// transaction were a treasurybase, and undoing or redoing it with that flag
// judges its version 1 coinbase under the treasury rules.
//
// Every case starts on a fresh chain under quickVoteActivationParams
// (validate_test.go), with the treasury agenda voted in through the
// harness's AdvanceFromSVHToActiveAgendas: its last block, bva19, is H_act-1
// at height 69, and every block from height 70 on is generated with the
// DCP0006 treasury semantics.  The cases:
//
//   - extend: H_act disapproves H_act-1 on the tip, and a child follows;
//   - reorg: a reorganization away from a disapproving H_act to a branch
//     forked below H_act-1, whose own H_act disapproves a sibling H_act-1
//     carrying a regular spend and is attached unvalidated, then back, so
//     the first H_act is attached again already validated;
//   - restart: the utxo cache restarts behind a disapproving H_act and
//     catches up across it, then restarts after an unclean reorganization
//     away from it and catches up by detaching it;
//   - templates: block templates checked on the tip H_act-1 and beside a
//     disapproving tip H_act, and the utxo view of the parent of the
//     template beside the tip, for templates that disapprove and approve
//     H_act-1;
//   - beyond: d71, the block after H_act, disapproves h70 on the tip, and a
//     reorganization to a branch on h70 that approves it detaches d71
//     again.  Both flags are active there, so the parent's flag is checked
//     where it is true as well as where it is false;
//   - fetchview: the utxo view FetchUtxoView gives the mempool without the
//     tip's regular tree, as the mempool asks for it once the votes it holds
//     for the tip disapprove that tree, on the tip H_act-1 and then on the
//     tip H_act.
//     The tip's regular tree is disconnected with the tip's own flag, which
//     on H_act-1 differs from the flag of the block after it.
//
// chaingen stamps block one with the wall clock, draws coinbase extra nonces
// from crypto/rand and takes whichever proof of work solution one of its
// threads finds first, and the chain judges timestamps and whether it is
// current against its time source.  run.sh overlays a copy of chaingen's
// generator.go in which ExportReset sets block one's time and restarts a
// fixed stream in place of crypto/rand, and which searches on one thread;
// each case starts with ExportReset, so every case generates the same
// blocks up to H_act-1.  The chain gets a time source fixed at block one's
// time, and every utxo cache a case makes gets a clock fixed there too, so
// a slow run does not flush it at a different block.  A run at an unchanged
// parity pin therefore writes the same file byte for byte.
//
// This file calls ExportReset, so the generator cannot be built against an
// unseamed chaingen.  A case that panics is failed with the panic's value
// and stack, so the others still run, and the file is written only when
// every case passes.  Built against a dcrd from before 37fd3a3e, every case
// panics at its first step across the boundary, when
// disconnectDisapprovedBlock finds one spent output fewer than H_act-1's
// transactions spend; in the fetchview case that step is the view on the tip
// H_act-1.
//
// Rows, after a `block <name> <hex>` row for every block any case processes
// or checks, in the order first seen:
//
//   - `test <case>`, `params quickvote`, `now <unix>`: a case on a fresh
//     chain under quickVoteActivationParams, with the adjusted time every
//     block is processed at and block one's timestamp;
//   - `process <name> <fork length>`: dcrd accepted the block with this
//     fork length, zero when it became the tip; the advance's blocks come
//     first, all with zero;
//   - `state <hash> <height>`: the utxo set state dcrd's backend records
//     after the step above, or after the whole advance for its blocks;
//   - `treasury <name> <true|false>`: IsTreasuryAgendaActive of the block,
//     the agenda state of the block after it;
//   - `tip <name>`, `disapproves <name>`: dcrd's ExpectTip and
//     AssertTipDisapprovesPrevious;
//   - `spendable` and `unspendable <hash> <index> <tree>`: dcrd's
//     ExpectUtxoSpendable and ExpectUtxoUnspendable, through the cache;
//   - `entry <hash> <index> <tree> <entry>`: the unspent entry
//     FetchUtxoEntry returns, written as in a `viewentry` row below;
//   - `forceflush`: dcrd's ForceUtxoCacheFlush;
//   - `disableflushes`: dcrd's DisableUtxoCacheFlushes;
//   - `restorejournal <name> <hex>`: the block's spend journal entry, which
//     the reorganization above removed although the cache was not flushed,
//     put back as an unclean shutdown before the flush would have left it;
//   - `restart`: a new utxo cache on the same backend, initialized as at
//     startup, which catches up from the backend's state to the tip;
//   - `template <name>`: CheckConnectBlockTemplate accepted the block;
//   - `parenttemplate <name>`: FetchUtxoViewParentTemplate returned a view
//     for the block, followed by a `viewentry <hash> <index> <tree> <entry>`
//     row for each output the template and the tip create or spend and each
//     the regular tree of the tip's parent creates or spends, where the
//     entry is `missing` (the view holds none), `spent`, or the amount,
//     block height, block index, transaction type, coinbase and expiry
//     flags, script version and script of the unspent entry;
//   - `fetchview <name> <index>`: FetchUtxoView, without the tip's regular
//     tree, returned a view for the named block's regular transaction at the
//     index, followed by a `viewentry` row for each output the regular tree
//     of the tip and the transaction create or spend.

package blockchain

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"runtime/debug"
	"testing"
	"time"

	"github.com/decred/dcrd/blockchain/v5/chaingen"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/database/v3"
	"github.com/decred/dcrd/dcrutil/v4"
	"github.com/decred/dcrd/wire"
)

// exportNow is block one's timestamp and the chain's adjusted time: the time
// of 46e9df48's commit, the parity pin when the generator was written,
// 2026-11-06 17:51:34 UTC.  It stays fixed when the pin moves.
var exportNow = time.Unix(1793987494, 0)

// exportTestCacheMaxSize is the maximum size of the utxo cache of dcrd's test
// chain (common_test.go's chainSetup), which a restart keeps.
const exportTestCacheMaxSize = 100 * 1024

// exportTimeSource is a MedianTimeSource fixed at exportNow.
type exportTimeSource struct{}

func (exportTimeSource) AdjustedTime() time.Time         { return exportNow }
func (exportTimeSource) AddTimeSample(string, time.Time) {}
func (exportTimeSource) Offset() time.Duration           { return 0 }

// exportClock is the utxo cache's clock, fixed at exportNow.  The cache
// starts with its last flush at the wall clock's time, which is later, and
// each flush sets it to exportNow, so the periodic flush never comes due.
func exportClock() time.Time { return exportNow }

// exportBlocks holds every block any case processed or checked, by name in
// the order first seen, and refuses a name that stands for two blocks.
type exportBlocks struct {
	names  []string
	byName map[string]*wire.MsgBlock
}

func (b *exportBlocks) add(t *testing.T, name string, block *wire.MsgBlock) {
	t.Helper()
	if prev, ok := b.byName[name]; ok {
		if prev.BlockHash() != block.BlockHash() {
			t.Fatalf("block %q differs between the cases", name)
		}
		return
	}
	b.names = append(b.names, name)
	b.byName[name] = block
}

// exportRecorder wraps a chaingen harness and writes a row for each call a
// case makes that the replay must repeat or check.
type exportRecorder struct {
	t      *testing.T
	g      *chaingenHarness
	rows   []string
	blocks *exportBlocks
}

func (r *exportRecorder) row(format string, args ...any) {
	r.rows = append(r.rows, fmt.Sprintf(format, args...))
}

// endStep writes the utxo set state the backend records.
func (r *exportRecorder) endStep() {
	r.t.Helper()
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

// ExpectUtxoEntry writes the entry the chain holds for an output, which must
// be unspent: the whole entry, so its coinbase flag is checked as well as its
// presence.
func (r *exportRecorder) ExpectUtxoEntry(outpoint wire.OutPoint) {
	r.t.Helper()
	entry, err := r.g.chain.FetchUtxoEntry(outpoint)
	if err != nil {
		r.t.Fatal(err)
	}
	if entry == nil || entry.IsSpent() {
		r.t.Fatalf("no unspent entry for %v", outpoint)
	}
	r.row("entry %s %d %d %s", outpoint.Hash, outpoint.Index, outpoint.Tree,
		exportEntry(entry))
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

// ExpectTreasury checks the agenda state IsTreasuryAgendaActive gives for
// the block after the named one.
func (r *exportRecorder) ExpectTreasury(name string, want bool) {
	r.t.Helper()
	hash := r.g.BlockByName(name).BlockHash()
	got, err := r.g.chain.IsTreasuryAgendaActive(&hash)
	if err != nil {
		r.t.Fatal(err)
	}
	if got != want {
		r.t.Fatalf("treasury agenda after %q: got %v, want %v", name, got,
			want)
	}
	r.row("treasury %s %v", name, got)
}

// spendJournal returns the named block's spend journal entry as stored, or
// nil when there is none.
func (r *exportRecorder) spendJournal(name string) []byte {
	r.t.Helper()
	hash := r.g.BlockByName(name).BlockHash()
	var serialized []byte
	err := r.g.chain.db.View(func(dbTx database.Tx) error {
		bucket := dbTx.Metadata().Bucket(spendJournalBucketName)
		if v := bucket.Get(hash[:]); v != nil {
			serialized = append([]byte(nil), v...)
		}
		return nil
	})
	if err != nil {
		r.t.Fatal(err)
	}
	return serialized
}

// RestoreSpendJournal puts back the named block's spend journal entry, as
// utxocache_test.go's TestInitialize does after a reorganization made with
// flushing off: dcrd removes the entry of a disconnected block only once the
// cache is flushed, and the test cache's disabled flush reports no error, so
// the removal goes ahead.
func (r *exportRecorder) RestoreSpendJournal(name string, serialized []byte) {
	r.t.Helper()
	if serialized == nil {
		r.t.Fatalf("no spend journal entry saved for %q", name)
	}
	if r.spendJournal(name) != nil {
		r.t.Fatalf("spend journal entry of %q was not removed", name)
	}
	hash := r.g.BlockByName(name).BlockHash()
	err := r.g.chain.db.Update(func(dbTx database.Tx) error {
		bucket := dbTx.Metadata().Bucket(spendJournalBucketName)
		return bucket.Put(hash[:], serialized)
	})
	if err != nil {
		r.t.Fatal(err)
	}
	r.row("restorejournal %s %x", name, serialized)
}

// Restart replaces the chain's utxo cache with a new one on the same backend
// and initializes it, as a restart does (utxocache_test.go's TestInitialize
// does the same): the new cache starts from the backend's state and catches
// up to the tip.  Flushing stays as it was.
func (r *exportRecorder) Restart() {
	r.t.Helper()
	old := r.g.chain.utxoCache.(*testUtxoCache)
	cache := newTestUtxoCache(&UtxoCacheConfig{
		Backend:      old.backend,
		FlushBlockDB: func() error { return nil },
		MaxSize:      exportTestCacheMaxSize,
	})
	cache.disableFlush = old.disableFlush
	cache.timeNow = exportClock
	r.g.chain.utxoCache = cache
	if err := cache.Initialize(context.Background(), r.g.chain); err != nil {
		r.t.Fatalf("utxo cache initialization: %v", err)
	}
	r.row("restart")
	r.endStep()
}

// CheckTemplate runs CheckConnectBlockTemplate on the named block, which
// must accept it.
func (r *exportRecorder) CheckTemplate(name string) {
	r.t.Helper()
	msgBlock := r.g.BlockByName(name)
	r.blocks.add(r.t, name, msgBlock)
	err := r.g.chain.CheckConnectBlockTemplate(dcrutil.NewBlock(msgBlock))
	if err != nil {
		r.t.Fatalf("template %q should have been accepted: %v", name, err)
	}
	r.row("template %s", name)
}

// ParentTemplateView runs FetchUtxoViewParentTemplate on the named block and
// writes the view's entry for every output the template and the tip create
// or spend, and every output the regular tree of the tip's parent creates or
// spends: the outputs the view's disconnection of the tip and connection of
// the template change.
func (r *exportRecorder) ParentTemplateView(name string) {
	r.t.Helper()
	msgBlock := r.g.BlockByName(name)
	r.blocks.add(r.t, name, msgBlock)
	view, err := r.g.chain.FetchUtxoViewParentTemplate(msgBlock)
	if err != nil {
		r.t.Fatalf("parent template view of %q: %v", name, err)
	}
	r.row("parenttemplate %s", name)

	tipHash := r.g.chain.BestSnapshot().Hash
	tip := r.g.BlockByHash(&tipHash)
	parent := r.g.BlockByHash(&tip.Header.PrevBlock)
	seen := make(map[wire.OutPoint]bool)
	var outpoints []wire.OutPoint
	for i, block := range []*wire.MsgBlock{parent, tip, msgBlock} {
		for _, op := range exportBlockOutpoints(block, i != 0) {
			if !seen[op] {
				seen[op] = true
				outpoints = append(outpoints, op)
			}
		}
	}
	for _, op := range outpoints {
		r.row("viewentry %s %d %d %s", op.Hash, op.Index, op.Tree,
			exportEntry(view.LookupEntry(op)))
	}
}

// FetchView runs FetchUtxoView, without the tip's regular tree, on the
// regular transaction at txIndex of the named block, and writes the view's
// entry for every output the regular tree of the tip and the transaction
// create or spend: the outputs the view's disconnection of the tip's regular
// tree changes, and the ones it fetches for the transaction.
func (r *exportRecorder) FetchView(name string, txIndex int) {
	r.t.Helper()
	msgBlock := r.g.BlockByName(name)
	r.blocks.add(r.t, name, msgBlock)
	msgTx := msgBlock.Transactions[txIndex]
	view, err := r.g.chain.FetchUtxoView(dcrutil.NewTx(msgTx), false)
	if err != nil {
		r.t.Fatalf("utxo view for %q transaction %d: %v", name, txIndex, err)
	}
	r.row("fetchview %s %d", name, txIndex)

	tipHash := r.g.chain.BestSnapshot().Hash
	tip := r.g.BlockByHash(&tipHash)
	txOnly := &wire.MsgBlock{Transactions: []*wire.MsgTx{msgTx}}
	seen := make(map[wire.OutPoint]bool)
	var outpoints []wire.OutPoint
	for _, block := range []*wire.MsgBlock{tip, txOnly} {
		for _, op := range exportBlockOutpoints(block, false) {
			if !seen[op] {
				seen[op] = true
				outpoints = append(outpoints, op)
			}
		}
	}
	for _, op := range outpoints {
		r.row("viewentry %s %d %d %s", op.Hash, op.Index, op.Tree,
			exportEntry(view.LookupEntry(op)))
	}
}

// exportEntry writes a utxo entry as the viewentry row does.
func exportEntry(entry *UtxoEntry) string {
	switch {
	case entry == nil:
		return "missing"
	case entry.IsSpent():
		return "spent"
	}
	return fmt.Sprintf("%d %d %d %d %v %v %d %x", entry.Amount(),
		entry.BlockHeight(), entry.BlockIndex(), entry.TransactionType(),
		entry.IsCoinBase(), entry.HasExpiry(), entry.ScriptVersion(),
		entry.PkScript())
}

// exportOutsideUtxoSet reports whether an output with this script never
// enters the utxo set: a provably unspendable OP_RETURN output, or a
// treasurybase's OP_TADD output, which adds to the treasury balance.
func exportOutsideUtxoSet(script []byte) bool {
	return len(script) > 0 && (script[0] == 0x6a || script[0] == 0xc1)
}

// exportBlockOutpoints returns, for the stake tree of a block when withStake
// is set and then its regular tree, the outpoints each transaction spends,
// other than null ones, and the outputs it creates that can enter the utxo
// set.
func exportBlockOutpoints(block *wire.MsgBlock, withStake bool) []wire.OutPoint {
	var outpoints []wire.OutPoint
	type txTree struct {
		txns []*wire.MsgTx
		tree int8
	}
	var trees []txTree
	if withStake {
		trees = append(trees, txTree{block.STransactions, wire.TxTreeStake})
	}
	trees = append(trees, txTree{block.Transactions, wire.TxTreeRegular})
	for _, tree := range trees {
		for _, tx := range tree.txns {
			for _, txIn := range tx.TxIn {
				prev := txIn.PreviousOutPoint
				if prev.Hash == (chainhash.Hash{}) {
					continue
				}
				outpoints = append(outpoints, prev)
			}
			hash := tx.TxHash()
			for i, txOut := range tx.TxOut {
				if exportOutsideUtxoSet(txOut.PkScript) {
					continue
				}
				outpoints = append(outpoints,
					*wire.NewOutPoint(&hash, uint32(i), tree.tree))
			}
		}
	}
	return outpoints
}

// exportRegularOutputs returns the outputs of a block's regular tree that can
// enter the utxo set.
func exportRegularOutputs(block *wire.MsgBlock) []wire.OutPoint {
	var outpoints []wire.OutPoint
	for _, tx := range block.Transactions {
		hash := tx.TxHash()
		for i, txOut := range tx.TxOut {
			if exportOutsideUtxoSet(txOut.PkScript) {
				continue
			}
			outpoints = append(outpoints,
				*wire.NewOutPoint(&hash, uint32(i), wire.TxTreeRegular))
		}
	}
	return outpoints
}

// exportCase holds what every case shares: the recorder, the harness, the
// spendable outputs left after the advance, and the mungers for blocks from
// H_act on.
type exportCase struct {
	*exportRecorder
	pool [][]chaingen.SpendableOut

	// actHeight is H_act's height.
	actHeight uint32

	// replaceVers sets the block, stake and vote versions of the treasury
	// deployment.
	replaceVers func(*wire.MsgBlock)

	// disapproveParent makes every vote and the header vote against the
	// parent's regular tree.
	disapproveParent func(*wire.MsgBlock)
}

// exportPreActivationName is H_act-1, the last block
// AdvanceFromSVHToActiveAgendas generates.
const exportPreActivationName = "bva19"

// newExportCase starts a case on a fresh chain: block one at exportNow,
// the advance through stake validation height and the treasury vote to
// H_act-1, each block written as processed, and the agenda states either
// side of H_act-1.
func newExportCase(t *testing.T, name string, blocks *exportBlocks) *exportCase {
	t.Helper()
	chaingen.ExportReset(exportNow)
	params := quickVoteActivationParams()
	const voteID = chaincfg.VoteIDTreasury
	version, _ := findDeployment(t, params, voteID)
	g := newChaingenHarness(t, params)
	g.chain.timeSource = exportTimeSource{}
	g.chain.utxoCache.(*testUtxoCache).timeNow = exportClock
	r := &exportRecorder{t: t, g: g, blocks: blocks}
	r.row("test %s", name)
	r.row("params quickvote")
	r.row("now %d", exportNow.Unix())

	g.AdvanceToStakeValidationHeight()
	g.AdvanceFromSVHToActiveAgendas(voteID)
	best := g.chain.BestSnapshot()
	for height := int64(1); height <= best.Height; height++ {
		block, err := g.chain.BlockByHeight(height)
		if err != nil {
			t.Fatal(err)
		}
		name := g.BlockName(block.Hash())
		blocks.add(t, name, block.MsgBlock())
		r.row("process %s 0", name)
	}
	r.endStep()
	if g.TipName() != exportPreActivationName {
		t.Fatalf("the advance ended at %q, not %q", g.TipName(),
			exportPreActivationName)
	}
	r.ExpectTip(exportPreActivationName)
	r.ExpectTreasury("bva18", false)
	r.ExpectTreasury(exportPreActivationName, true)

	// The spendable outputs left from the advance, each set paying one
	// block's regular spend and ticket purchases.  They are taken here so
	// that a block at a given height spends the same set on every branch.
	// Every branch forks at bva18 or later, so only sets from bva18 and
	// before are taken.
	var pool [][]chaingen.SpendableOut
	forkHeight := uint32(best.Height) - 1
	for g.NumSpendableCoinbaseOuts() > 0 {
		outs := g.OldestCoinbaseOuts()
		if outs[0].BlockHeight() > forkHeight {
			break
		}
		pool = append(pool, outs)
	}

	replaceVers := func(b *wire.MsgBlock) {
		chaingen.ReplaceBlockVersion(int32(version))(b)
		chaingen.ReplaceStakeVersion(version)(b)
		chaingen.ReplaceVoteVersions(version)(b)
	}
	disapproveParent := func(b *wire.MsgBlock) {
		const voteBitYes = 0x0001
		b.Header.VoteBits &^= voteBitYes
		g.ReplaceVoteBits(0)(b)
	}
	return &exportCase{
		exportRecorder:   r,
		pool:             pool,
		actHeight:        uint32(best.Height) + 1,
		replaceVers:      replaceVers,
		disapproveParent: disapproveParent,
	}
}

// outs returns the spendable outputs for a block at the given height on any
// branch.
func (c *exportCase) outs(height uint32) []chaingen.SpendableOut {
	c.t.Helper()
	i := int(height) - int(c.actHeight-1)
	if i < 0 || i >= len(c.pool) {
		c.t.Fatalf("no spendable outputs for height %d (%d sets)", height,
			len(c.pool))
	}
	outs := c.pool[i]
	maturity := uint32(c.g.Params().CoinbaseMaturity)
	if outs[0].BlockHeight()+maturity > height {
		c.t.Fatalf("the outputs for height %d, from height %d, are immature",
			height, outs[0].BlockHeight())
	}
	return outs
}

// next generates the named block on the generator's tip with a regular
// spend and ticket purchases from the outputs for its height, under the
// treasury deployment's versions.  A block from H_act on carries a
// treasurybase and a version 3 coinbase.
func (c *exportCase) next(name string, disapprove bool) *wire.MsgBlock {
	c.t.Helper()
	height := c.g.Tip().Header.Height + 1
	semantics := chaingen.TSOriginal
	if height >= c.actHeight {
		semantics = chaingen.TSDCP0006
	}
	c.g.UseTreasurySemantics(semantics)
	outs := c.outs(height)
	mungers := []func(*wire.MsgBlock){c.replaceVers}
	if disapprove {
		mungers = append(mungers, c.disapproveParent)
	}
	return c.g.NextBlock(name, &outs[0], outs[1:], mungers...)
}

// spendOutput is the output of a block's regular spend.
func spendOutput(block *wire.MsgBlock) wire.OutPoint {
	hash := block.Transactions[1].TxHash()
	return *wire.NewOutPoint(&hash, 0, wire.TxTreeRegular)
}

// spendInput is the output a block's regular spend spends.
func spendInput(block *wire.MsgBlock) wire.OutPoint {
	return block.Transactions[1].TxIn[0].PreviousOutPoint
}

// expectRegularTree checks every utxo-set output of a block's regular tree
// spendable or not.
func (c *exportCase) expectRegularTree(name string, spendable bool) {
	c.t.Helper()
	for _, op := range exportRegularOutputs(c.g.BlockByName(name)) {
		if spendable {
			c.ExpectUtxoSpendable(op)
		} else {
			c.ExpectUtxoUnspendable(op)
		}
	}
}

// disapprovingAct generates h70, the H_act every case starts from: a block
// on H_act-1 that disapproves it.  Each case generates it from the same
// state, so it is the same block in every case.
func (c *exportCase) disapprovingAct() *wire.MsgBlock {
	c.t.Helper()
	h70 := c.next("h70", true)
	c.AssertTipDisapprovesPrevious()
	return h70
}

// exportExtend: H_act disapproves H_act-1 on the tip, through
// checkConnectBlock and connectBlock, and an approving child follows.
func exportExtend(c *exportCase) {
	pre := c.g.BlockByName(exportPreActivationName)
	h70 := c.disapprovingAct()
	c.AcceptTipBlock()
	c.ExpectTip("h70")
	c.expectRegularTree(exportPreActivationName, false)
	c.ExpectUtxoSpendable(spendOutput(h70))
	c.ExpectUtxoUnspendable(spendInput(h70))
	for i, stx := range pre.STransactions {
		if i >= int(pre.Header.Voters) {
			hash := stx.TxHash()
			c.ExpectUtxoSpendable(*wire.NewOutPoint(&hash, 0,
				wire.TxTreeStake))
		}
	}

	c.next("h71", false)
	c.AcceptTipBlock()
	c.ExpectTip("h71")
	c.expectRegularTree(exportPreActivationName, false)
	c.ExpectUtxoSpendable(spendOutput(h70))
}

// exportReorg: a reorganization from h70 to a branch forked at bva18 whose
// H_act, p70, disapproves a sibling H_act-1, p69, that carries a regular
// spend; p70 is attached unvalidated.  Then back, which detaches p70 and
// attaches h70 again, validated before.
func exportReorg(c *exportCase) {
	h70 := c.disapprovingAct()
	c.AcceptTipBlock()
	c.ExpectTip("h70")
	c.expectRegularTree(exportPreActivationName, false)

	c.g.SetTip("bva18")
	p69 := c.next("p69", false)
	c.AcceptedToSideChainWithExpectedTip("h70")
	p70 := c.next("p70", true)
	c.AssertTipDisapprovesPrevious()
	c.AcceptedToSideChainWithExpectedTip("h70")
	c.next("p71", false)
	c.AcceptTipBlock()
	c.ExpectTip("p71")
	c.expectRegularTree("p69", false)
	c.ExpectUtxoSpendable(spendInput(p69))
	c.ExpectUtxoSpendable(spendOutput(p70))
	c.expectRegularTree(exportPreActivationName, false)
	c.ExpectUtxoUnspendable(spendOutput(h70))

	c.g.SetTip("h70")
	c.next("q71", false)
	c.AcceptedToSideChainWithExpectedTip("p71")
	c.next("q72", false)
	c.AcceptTipBlock()
	c.ExpectTip("q72")
	c.expectRegularTree(exportPreActivationName, false)
	c.ExpectUtxoSpendable(spendOutput(h70))
	c.ExpectUtxoUnspendable(spendInput(h70))
	c.expectRegularTree("p69", false)
	c.ExpectUtxoUnspendable(spendOutput(p70))
}

// exportRestart: with flushing off, h70 and its child h71 are processed,
// and a restart catches the cache up across both from H_act-1.  Then an
// unclean reorganization to a branch whose H_act, r70, approves H_act-1
// leaves the backend at h71, and a restart detaches h71 and h70 before it
// attaches the new branch, which leaves H_act-1's regular tree as the
// detach of h70 redid it.
func exportRestart(c *exportCase) {
	c.ForceUtxoCacheFlush()
	c.DisableUtxoCacheFlushes()
	h70 := c.disapprovingAct()
	c.AcceptTipBlock()
	c.next("h71", false)
	c.AcceptTipBlock()
	c.ExpectTip("h71")
	c.Restart()
	c.ExpectTip("h71")
	c.expectRegularTree(exportPreActivationName, false)
	c.ExpectUtxoSpendable(spendOutput(h70))
	c.ForceUtxoCacheFlush()

	journals := []string{"h70", "h71"}
	saved := make(map[string][]byte)
	for _, name := range journals {
		saved[name] = c.spendJournal(name)
	}
	c.g.SetTip(exportPreActivationName)
	r70 := c.next("r70", false)
	c.AcceptedToSideChainWithExpectedTip("h71")
	c.next("r71", false)
	c.AcceptedToSideChainWithExpectedTip("h71")
	c.next("r72", false)
	c.AcceptTipBlock()
	c.ExpectTip("r72")
	for _, name := range journals {
		c.RestoreSpendJournal(name, saved[name])
	}
	c.Restart()
	c.ExpectTip("r72")
	c.expectRegularTree(exportPreActivationName, true)
	// Detaching h70 redid H_act-1's regular tree, so its entries carry the
	// coinbase flag that redo gave them.
	pre := c.g.BlockByName(exportPreActivationName)
	for _, op := range exportRegularOutputs(pre) {
		c.ExpectUtxoEntry(op)
	}
	c.ExpectUtxoSpendable(spendOutput(r70))
	c.ExpectUtxoUnspendable(spendOutput(h70))
	c.ForceUtxoCacheFlush()
}

// exportTemplates: h70 checked as a template on the tip H_act-1, through
// the extend-tip branch of CheckConnectBlockTemplate.  Then, with h70 as
// the tip, templates beside it that disapprove (s70d) and approve (s70a)
// H_act-1, checked through the branch that disconnects the tip first, and
// the utxo view of their parent.
func exportTemplates(c *exportCase) {
	c.disapprovingAct()
	c.CheckTemplate("h70")
	c.AcceptTipBlock()
	c.ExpectTip("h70")

	for _, sibling := range []struct {
		name       string
		disapprove bool
	}{{"s70d", true}, {"s70a", false}} {
		c.g.SetTip(exportPreActivationName)
		c.next(sibling.name, sibling.disapprove)
		c.g.SetTip("h70")
		c.CheckTemplate(sibling.name)
		c.ParentTemplateView(sibling.name)
	}
	c.ExpectTip("h70")
}

// exportBeyond: h70 on the tip, then d71 on h70 disapproving it, where
// isTreasuryAgendaActive is true for h70's parent and for h70 itself, so
// h70 is undone with an active flag.  A reorganization to e72, on a branch
// from h70 whose e71 approves it, then detaches d71, which redoes h70's
// regular tree with that flag, and the entries left are the redo's.
func exportBeyond(c *exportCase) {
	h70 := c.disapprovingAct()
	c.AcceptTipBlock()
	c.ExpectTip("h70")
	c.ExpectTreasury("h70", true)

	d71 := c.next("d71", true)
	c.AssertTipDisapprovesPrevious()
	c.AcceptTipBlock()
	c.ExpectTip("d71")
	c.expectRegularTree("h70", false)
	c.ExpectUtxoSpendable(spendInput(h70))
	c.ExpectUtxoSpendable(spendOutput(d71))
	c.expectRegularTree(exportPreActivationName, false)

	c.g.SetTip("h70")
	c.next("e71", false)
	c.AcceptedToSideChainWithExpectedTip("d71")
	c.next("e72", false)
	c.AcceptTipBlock()
	c.ExpectTip("e72")
	// Detaching d71 redid h70's regular tree, so its entries carry the
	// coinbase flag that redo gave them.
	for _, op := range exportRegularOutputs(h70) {
		c.ExpectUtxoEntry(op)
	}
	c.ExpectUtxoUnspendable(spendInput(h70))
	c.ExpectUtxoUnspendable(spendOutput(d71))
	c.expectRegularTree(exportPreActivationName, false)
}

// exportFetchView: the mempool's view without the tip's regular tree, for
// h70's regular spend on the tip H_act-1, whose own flag is inactive while
// the flag of the block after it is active, and then for h71's on the tip
// h70, where both are active.  h70 disapproves H_act-1 and h71 approves h70,
// as in the extend case, but neither vote matters to FetchUtxoView, which
// leaves the tip's regular tree out for the caller.
func exportFetchView(c *exportCase) {
	c.disapprovingAct()
	c.FetchView("h70", 1)
	c.AcceptTipBlock()
	c.ExpectTip("h70")
	c.ExpectTreasury("h70", true)

	c.next("h71", false)
	c.FetchView("h71", 1)
	c.ExpectTip("h70")
}

// exportCases are the cases in the order the file holds them.
var exportCases = []struct {
	name string
	run  func(*exportCase)
}{
	{"extend", exportExtend},
	{"reorg", exportReorg},
	{"restart", exportRestart},
	{"templates", exportTemplates},
	{"beyond", exportBeyond},
	{"fetchview", exportFetchView},
}

// TestExportTrsyBoundaryVectors writes the vector file to the path in
// DCROXIDE_TRSYBOUNDARY_VECTORS: every block any case processed or checked,
// in the order first seen, then one section per case.
func TestExportTrsyBoundaryVectors(t *testing.T) {
	path := os.Getenv("DCROXIDE_TRSYBOUNDARY_VECTORS")
	if path == "" {
		t.Skip("DCROXIDE_TRSYBOUNDARY_VECTORS not set")
	}
	blocks := &exportBlocks{byName: make(map[string]*wire.MsgBlock)}
	sections := make([][]string, len(exportCases))
	for i, ec := range exportCases {
		t.Run(ec.name, func(t *testing.T) {
			defer func() {
				if p := recover(); p != nil {
					t.Fatalf("case %s panicked: %v\n%s", ec.name, p,
						debug.Stack())
				}
			}()
			c := newExportCase(t, ec.name, blocks)
			ec.run(c)
			sections[i] = c.rows
		})
	}
	if t.Failed() {
		return
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
