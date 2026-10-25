// SPDX-License-Identifier: ISC

// This file dumps dcroxide's three mempool vector files from dcrd's own
// mempool test harness (`newPoolHarness` and its fake chain): the scripted
// sessions are run against dcrd's real `TxPool`, and every chain mutation,
// pool call and resulting pool state is written as one row, so the
// expectations in the files are dcrd's at the parity pin, not this
// project's reading of them.
//
// It is an overlay, not a module: it belongs to dcrd's `internal/mempool`
// package and uses the harness that package's tests define.  To regenerate,
// copy it into `internal/mempool` of a dcrd checkout at the parity pin and
// run, from the checkout's root,
//
//	MEMPOOL_VECTORS_DIR=<dir> go test -run TestExportMempoolVectors ./internal/mempool/
//
// which writes txpool_vectors.txt, txstake_vectors.txt and
// review_agenda_vectors.txt into <dir>, ready to replace the files in
// crates/dcroxide-mempool/tests/data.  Without MEMPOOL_VECTORS_DIR the test
// is skipped, so the overlay does not disturb dcrd's own test runs.
//
// The output does not depend on the clock or on randomness: each session's
// median time is fixed to the one the files have carried since they were
// first dumped, and the treasury spends' uniqueness nonce, which dcrd's
// `createTSpend` draws from math/rand, is replaced by the nonces those files
// carry.  So a run at an unchanged parity pin reproduces the files byte for
// byte, and a run after a move shows exactly what the move changed.
//
// The stake and agenda files are sections, each opened by a `net <name>` row
// and a harness built fresh for it (`init`); the transaction pool file is one
// session with no `net` row.  The rows that follow are the ones the Rust
// replays read:
//
//	init <median time> <best height> <best hash> <best header> <coinbase>
//	pikeys <pubkey>                    the harness's replaced Pi keys
//	sethgt <height>                    SetHeight
//	block <hash> <header>              AddMockBlock: the chain knows the block
//	besthash <hash>                    SetBestHash
//	winner <block hash> <ticket hash>  AddWinningTicket
//	utxo <tx> <height> <block index>   a fake mined transaction
//	utxotime <hash> <index> <unix>     AddFakeUtxoMedianTime
//	setsdiff <atoms>                   SetNextStakeDifficulty
//	treasury|autorev|ss|ssr2 <0|1>     an agenda the harness answers
//	oldvotes <0|1>                     the AllowOldVotes policy
//	tspendmined <hash>                 SetTSpendMinedOnAncestor
//	pt <tx> <allow orphan> <allow high fees> <tag> (ok <accepted>|<kind> -)
//	mat <tx> <is new> (ok <missing parents>|<kind> -)
//	mats <txs> <ok|kind|multi>         MaybeAcceptTransactions
//	mad <tx> <treasury> <accepted>     MaybeAcceptDependents
//	rmtx <tx> <remove redeemers>       RemoveTransaction
//	rmds <tx>                          RemoveDoubleSpends
//	rmorph <tx>                        RemoveOrphan
//	rmtag <tag> <evicted>              RemoveOrphansByTag
//	prune <stake difficulty> <height>  PruneStakeTx
//	pruneexp <height>                  PruneExpiredTx
//	state <count> <pool> <orphans> <staged> <tspends>
//	vhb <block hash> <vote hashes>     VoteHashesForBlock
//	disap <block hash> <bool>          IsRegTxTreeKnownDisapproved
//	tsh <tspend hashes>                TSpendHashes
//	have <hash> <bool>                 HaveTransaction
//	spent <hash> <index> <tree> <bool> IsSpent
//	chainspend <hash> <index> <tree>   the fake chain's entry marked spent
//	log <level> <text>                 a line the pool logged
//
// The pool logs through the package logger at trace, the lowest level, as
// the daemon's `TXMP` logger does under `--debuglevel=TXMP=trace`, and each
// line it logs is a `log` row after the row of the call that logged it:
// the level as slog abbreviates it (`TRC`, `DBG`) and the text as slog
// formats it, to the end of the row.  A call's lines are in the order the
// pool logged them, but for those it logs while ranging over a Go map, whose
// order changes from run to run, which are sorted: the lines of a `prune` or
// `pruneexp` call, whose walks over the pool, the stage pool and the vote
// tracker log, are sorted whole, and each run of consecutive `Removing orphan
// transaction` lines, the one line the walks over the orphans log (the
// expiry scan, the cascade into an orphan's redeemers, and the removal of a
// peer's orphans and of the orphans an accepted transaction double spends),
// is sorted.  No session gives an output more than one orphan redeeming it,
// where the order processOrphans tries them in would vary as well.
//
// Hashes are hex in internal byte order and transactions and headers hex of
// their serialization.  Lists are comma-separated, `-` when empty: the hashes
// in a `state`, `vhb` or `tsh` row in ascending byte order, accepted
// transactions and missing parents in the order dcrd returns them.  A kind is
// the mempool error kind, `chain:` and the blockchain error kind for a wrapped
// chain rule error, or `plain` for any other error.

package mempool

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/decred/dcrd/blockchain/stake/v5"
	"github.com/decred/dcrd/blockchain/standalone/v2"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrutil/v4"
	"github.com/decred/dcrd/internal/blockchain"
	"github.com/decred/dcrd/txscript/v4"
	"github.com/decred/dcrd/txscript/v4/sign"
	"github.com/decred/dcrd/txscript/v4/stdscript"
	"github.com/decred/dcrd/wire"
	"github.com/decred/slog"
)

// The median times the sessions run at: the ones the files were first dumped
// with, kept so a regeneration changes only what moving the pin changes.
const (
	vdTxPoolMedianTime = 1783313288
	vdStakeMedianTime  = 1783314311
	vdAgendaMedianTime = 1790367743
)

// vdTSpendNonces are the uniqueness nonces of the treasury section's fifteen
// treasury spends, in creation order (see the file comment).
var vdTSpendNonces = [15]uint64{
	2846321142816109626, 2859169904720013017, 885314935445091464,
	1092383457502636598, 2038999009861723521, 5725059044768646764,
	8665776240295541802, 7615977804203413164, 6595266484392572928,
	6408511562634217274, 365676131171835342, 7122534323979371974,
	1171828243539116311, 6159988815291292413, 1547981397033169910,
}

// vdLogLines collects the lines the pool logs, each a whole slog write,
// until the next row is written and flushes them as `log` rows.
type vdLogLines struct {
	lines []string
}

func (l *vdLogLines) Write(p []byte) (int, error) {
	l.lines = append(l.lines, string(p))
	return len(p), nil
}

// vdLog is the writer behind the package logger while the vectors are
// dumped.
var vdLog vdLogLines

// vdDump records one section of rows over a harness built for it.
type vdDump struct {
	t       *testing.T
	out     *strings.Builder
	harness *poolHarness
	outs    []spendableOutput
}

func vdHash(hash *chainhash.Hash) string {
	return hex.EncodeToString(hash[:])
}

func vdTx(t *testing.T, tx *dcrutil.Tx) string {
	t.Helper()
	b, err := tx.MsgTx().Bytes()
	if err != nil {
		t.Fatalf("serialize %v: %v", tx.Hash(), err)
	}
	return hex.EncodeToString(b)
}

func vdHeader(t *testing.T, header *wire.BlockHeader) string {
	t.Helper()
	b, err := header.Bytes()
	if err != nil {
		t.Fatalf("serialize header: %v", err)
	}
	return hex.EncodeToString(b)
}

// vdSorted is the list of the hashes in ascending byte order.
func vdSorted(hashes []chainhash.Hash) string {
	if len(hashes) == 0 {
		return "-"
	}
	strs := make([]string, 0, len(hashes))
	for i := range hashes {
		strs = append(strs, vdHash(&hashes[i]))
	}
	sort.Strings(strs)
	return strings.Join(strs, ",")
}

// vdTxList is the list of the transactions' hashes in the given order.
func vdTxList(txns []*dcrutil.Tx) string {
	if len(txns) == 0 {
		return "-"
	}
	strs := make([]string, 0, len(txns))
	for _, tx := range txns {
		strs = append(strs, vdHash(tx.Hash()))
	}
	return strings.Join(strs, ",")
}

// vdKind names the error as the replays compare it.
func vdKind(err error) string {
	var rerr RuleError
	if errors.As(err, &rerr) {
		var kind ErrorKind
		if errors.As(rerr.Err, &kind) {
			return string(kind)
		}
		var cerr blockchain.RuleError
		if errors.As(rerr.Err, &cerr) {
			var ckind blockchain.ErrorKind
			if errors.As(cerr.Err, &ckind) {
				return "chain:" + string(ckind)
			}
		}
	}
	return "plain"
}

// vdNewSection opens a section: the `net` row unless the name is empty, the
// preamble rows, a harness for the given network at the given median time,
// and its `init` row.
func vdNewSection(t *testing.T, out *strings.Builder, name string, params *chaincfg.Params, medianTime int64, preamble ...string) *vdDump {
	t.Helper()
	harness, outs, err := newPoolHarness(params)
	if err != nil {
		t.Fatalf("unable to create test pool: %v", err)
	}
	harness.chain.SetPastMedianTime(time.Unix(medianTime, 0))

	// The harness's funding coinbase, rebuilt as newPoolHarness built it so
	// the row can carry it.
	coinbase, err := harness.CreateCoinbaseTx(1, 1)
	if err != nil {
		t.Fatalf("unable to create coinbase: %v", err)
	}
	if *coinbase.Hash() != outs[0].outPoint.Hash {
		t.Fatalf("rebuilt coinbase %v is not the harness's %v", coinbase.Hash(),
			outs[0].outPoint.Hash)
	}

	d := &vdDump{t: t, out: out, harness: harness, outs: outs}
	if name != "" {
		d.row("net", name)
	}
	for _, row := range preamble {
		d.out.WriteString(row)
		d.out.WriteByte('\n')
	}
	bestHash := harness.chain.BestHash()
	bestHeader, err := harness.chain.HeaderByHash(bestHash)
	if err != nil {
		t.Fatalf("best header: %v", err)
	}
	d.row("init", fmt.Sprint(medianTime), fmt.Sprint(harness.chain.BestHeight()),
		vdHash(bestHash), vdHeader(t, &bestHeader), vdTx(t, coinbase))
	return d
}

func (d *vdDump) row(fields ...string) {
	d.out.WriteString(strings.Join(fields, " "))
	d.out.WriteByte('\n')
	d.logRows(fields[0])
}

// vdOrphanRemoval is the `log` row the pool's walks over its orphans write
// for each orphan they remove.
const vdOrphanRemoval = "log TRC Removing orphan transaction "

// logRows writes a `log` row for each line the pool has logged since the
// last row, which is the row of the call that logged them, with the lines
// logged while ranging over a Go map sorted (see the comment at the top).
// slog's backend writes each line whole, as the bracketed level, the
// subsystem tag, a colon and space, the text and a newline (the backend runs
// without the date and time).
func (d *vdDump) logRows(call string) {
	const tagged = "[TRC] TXMP: "
	rows := make([]string, 0, len(vdLog.lines))
	for _, line := range vdLog.lines {
		if len(line) < len(tagged) || line[0] != '[' || line[4:len(tagged)] != "] TXMP: " ||
			!strings.HasSuffix(line, "\n") {

			d.t.Fatalf("unexpected log write %q", line)
		}
		text := strings.TrimSuffix(line[len(tagged):], "\n")
		if strings.Contains(text, "\n") {
			d.t.Fatalf("a logged line spans rows: %q", line)
		}
		rows = append(rows, "log "+line[1:4]+" "+text)
	}
	vdLog.lines = nil
	if call == "prune" || call == "pruneexp" {
		sort.Strings(rows)
	} else {
		for start := 0; start < len(rows); {
			end := start + 1
			if strings.HasPrefix(rows[start], vdOrphanRemoval) {
				for end < len(rows) && strings.HasPrefix(rows[end], vdOrphanRemoval) {
					end++
				}
				sort.Strings(rows[start:end])
			}
			start = end
		}
	}
	for _, row := range rows {
		d.out.WriteString(row)
		d.out.WriteByte('\n')
	}
}

func (d *vdDump) must(tx *dcrutil.Tx, err error) *dcrutil.Tx {
	d.t.Helper()
	if err != nil {
		d.t.Fatalf("unable to create transaction: %v", err)
	}
	return tx
}

// Chain mutations.

func (d *vdDump) setHeight(height int64) {
	d.harness.chain.SetHeight(height)
	d.row("sethgt", fmt.Sprint(height))
}

func (d *vdDump) block() *dcrutil.Block {
	block := d.harness.chain.AddMockBlock()
	d.row("block", vdHash(block.Hash()), vdHeader(d.t, &block.MsgBlock().Header))
	return block
}

func (d *vdDump) bestHash(hash *chainhash.Hash) {
	d.harness.chain.SetBestHash(hash)
	d.row("besthash", vdHash(hash))
}

func (d *vdDump) winner(block, ticket *chainhash.Hash) {
	d.harness.chain.AddWinningTicket(block, ticket)
	d.row("winner", vdHash(block), vdHash(ticket))
}

func (d *vdDump) utxo(tx *dcrutil.Tx, height int64, blockIndex uint32) {
	d.harness.AddFakeUTXO(tx, height, blockIndex)
	d.row("utxo", vdTx(d.t, tx), fmt.Sprint(height), fmt.Sprint(blockIndex))
}

// chainSpend marks the fake chain's entry for the output spent, as the view
// of a block spending it holds it.
func (d *vdDump) chainSpend(op wire.OutPoint) {
	entry := d.harness.chain.utxos.LookupEntry(op)
	if entry == nil {
		d.t.Fatalf("the fake chain has no entry for %v", op)
	}
	entry.Spend()
	d.row("chainspend", vdHash(&op.Hash), fmt.Sprint(op.Index), fmt.Sprint(op.Tree))
}

func (d *vdDump) utxoTime(tx *dcrutil.Tx, index uint32) {
	medianTime := d.harness.chain.PastMedianTime()
	d.harness.chain.AddFakeUtxoMedianTime(tx, index, medianTime)
	d.row("utxotime", vdHash(tx.Hash()), fmt.Sprint(index),
		fmt.Sprint(medianTime.Unix()))
}

func (d *vdDump) setStakeDiff(sdiff int64) {
	d.harness.chain.SetNextStakeDifficulty(sdiff)
	d.row("setsdiff", fmt.Sprint(sdiff))
}

func vdFlag(active bool) string {
	if active {
		return "1"
	}
	return "0"
}

func (d *vdDump) treasury(active bool) {
	d.harness.SetTreasuryAgendaActive(active)
	d.row("treasury", vdFlag(active))
}

func (d *vdDump) autoRevocations(active bool) {
	d.harness.autoRevocationsActive = active
	d.row("autorev", vdFlag(active))
}

func (d *vdDump) subsidySplit(active bool) {
	d.harness.subsidySplitActive = active
	d.row("ss", vdFlag(active))
}

func (d *vdDump) subsidySplitR2(active bool) {
	d.harness.subsidySplitR2Active = active
	d.row("ssr2", vdFlag(active))
}

func (d *vdDump) allowOldVotes(allow bool) {
	d.harness.txPool.cfg.Policy.AllowOldVotes = allow
	d.row("oldvotes", vdFlag(allow))
}

func (d *vdDump) tspendMined(tx *dcrutil.Tx) {
	d.harness.chain.SetTSpendMinedOnAncestor(*tx.Hash(), true)
	d.row("tspendmined", vdHash(tx.Hash()))
}

// Pool calls.  Each that can change the pool is followed by a `state` row.

// vdFresh is the transaction as the pool receives it from a peer or the RPC
// server, in a wrapper that hashes the transaction it carries.  A session
// that changes a transaction after wrapping it (the auto revocation section
// lowers an output's value) leaves the wrapper's cached hash stale, and the
// pool would log that hash for the transaction.
func vdFresh(tx *dcrutil.Tx) *dcrutil.Tx {
	if *tx.Hash() == tx.MsgTx().TxHash() {
		return tx
	}
	fresh := dcrutil.NewTx(tx.MsgTx())
	fresh.SetTree(tx.Tree())
	return fresh
}

func (d *vdDump) pt(tx *dcrutil.Tx, allowOrphan, allowHighFees bool, tag Tag) {
	tx = vdFresh(tx)
	accepted, err := d.harness.txPool.ProcessTransaction(tx, allowOrphan,
		allowHighFees, tag)
	fields := []string{"pt", vdTx(d.t, tx), fmt.Sprint(allowOrphan),
		fmt.Sprint(allowHighFees), fmt.Sprint(tag)}
	if err != nil {
		d.row(append(fields, vdKind(err), "-")...)
	} else {
		d.row(append(fields, "ok", vdTxList(accepted))...)
	}
	d.state()
}

func (d *vdDump) mat(tx *dcrutil.Tx, isNew bool) {
	tx = vdFresh(tx)
	missing, err := d.harness.txPool.MaybeAcceptTransaction(tx, isNew)
	fields := []string{"mat", vdTx(d.t, tx), fmt.Sprint(isNew)}
	switch {
	case err != nil:
		d.row(append(fields, vdKind(err), "-")...)
	case len(missing) == 0:
		d.row(append(fields, "ok", "-")...)
	default:
		strs := make([]string, 0, len(missing))
		for i := range missing {
			strs = append(strs, fmt.Sprintf("%s:%d:%d",
				vdHash(&missing[i].Hash), missing[i].Index, missing[i].Tree))
		}
		d.row(append(fields, "ok", strings.Join(strs, ","))...)
	}
	d.state()
}

func (d *vdDump) mats(txns []*dcrutil.Tx) {
	fresh := make([]*dcrutil.Tx, 0, len(txns))
	for _, tx := range txns {
		fresh = append(fresh, vdFresh(tx))
	}
	txns = fresh
	err := d.harness.txPool.MaybeAcceptTransactions(txns)
	hexes := make([]string, 0, len(txns))
	for _, tx := range txns {
		hexes = append(hexes, vdTx(d.t, tx))
	}
	verdict := "ok"
	var multi blockchain.MultiError
	switch {
	case errors.As(err, &multi):
		verdict = "multi"
	case err != nil:
		verdict = vdKind(err)
	}
	d.row("mats", strings.Join(hexes, ","), verdict)
	d.state()
}

func (d *vdDump) mad(tx *dcrutil.Tx, isTreasuryEnabled bool) {
	tx = vdFresh(tx)
	accepted := d.harness.txPool.MaybeAcceptDependents(tx, isTreasuryEnabled)
	d.row("mad", vdTx(d.t, tx), fmt.Sprint(isTreasuryEnabled), vdTxList(accepted))
	d.state()
}

func (d *vdDump) rmtx(tx *dcrutil.Tx, removeRedeemers bool) {
	tx = vdFresh(tx)
	d.harness.txPool.RemoveTransaction(tx, removeRedeemers)
	d.row("rmtx", vdTx(d.t, tx), fmt.Sprint(removeRedeemers))
}

func (d *vdDump) rmds(tx *dcrutil.Tx) {
	tx = vdFresh(tx)
	d.harness.txPool.RemoveDoubleSpends(tx)
	d.row("rmds", vdTx(d.t, tx))
	d.state()
}

func (d *vdDump) rmorph(tx *dcrutil.Tx) {
	tx = vdFresh(tx)
	d.harness.txPool.RemoveOrphan(tx)
	d.row("rmorph", vdTx(d.t, tx))
	d.state()
}

func (d *vdDump) rmtag(tag Tag) {
	evicted := d.harness.txPool.RemoveOrphansByTag(tag)
	d.row("rmtag", fmt.Sprint(tag), fmt.Sprint(evicted))
	d.state()
}

func (d *vdDump) prune(sdiff, height int64) {
	d.harness.txPool.PruneStakeTx(sdiff, height)
	d.row("prune", fmt.Sprint(sdiff), fmt.Sprint(height))
	d.state()
}

func (d *vdDump) pruneExpired(height int64) {
	d.harness.txPool.PruneExpiredTx(height)
	d.row("pruneexp", fmt.Sprint(height))
	d.state()
}

// Pool queries.

func (d *vdDump) state() {
	mp := d.harness.txPool
	var pool, orphans, staged []chainhash.Hash
	for _, hash := range mp.TxHashes() {
		pool = append(pool, *hash)
	}
	mp.mtx.RLock()
	for hash := range mp.orphans {
		orphans = append(orphans, hash)
	}
	for hash := range mp.staged {
		staged = append(staged, hash)
	}
	mp.mtx.RUnlock()
	d.row("state", fmt.Sprint(mp.Count()), vdSorted(pool), vdSorted(orphans),
		vdSorted(staged), vdSorted(mp.TSpendHashes()))
}

func (d *vdDump) vhb(block *chainhash.Hash) {
	d.row("vhb", vdHash(block),
		vdSorted(d.harness.txPool.VoteHashesForBlock(block)))
}

// vhbOf records the metadata of the block the vote votes on, where dcrd's
// tests assert the vote's membership in it (testVoteMetadataMembership).
func (d *vdDump) vhbOf(vote *dcrutil.Tx) {
	votedHash, _ := stake.SSGenBlockVotedOn(vote.MsgTx())
	d.vhb(&votedHash)
}

func (d *vdDump) disap(block *chainhash.Hash) {
	d.row("disap", vdHash(block),
		fmt.Sprint(d.harness.txPool.IsRegTxTreeKnownDisapproved(block)))
}

func (d *vdDump) tsh() {
	d.row("tsh", vdSorted(d.harness.txPool.TSpendHashes()))
}

func (d *vdDump) have(hash *chainhash.Hash) {
	d.row("have", vdHash(hash),
		fmt.Sprint(d.harness.txPool.HaveTransaction(hash)))
}

func (d *vdDump) spent(op wire.OutPoint) {
	d.row("spent", vdHash(&op.Hash), fmt.Sprint(op.Index), fmt.Sprint(op.Tree),
		fmt.Sprint(d.harness.txPool.IsSpent(op)))
}

// Transaction builders beyond the harness's own.

func (d *vdDump) spend(tx *dcrutil.Tx, index uint32) spendableOutput {
	return txOutToSpendableOut(tx, index, wire.TxTreeRegular)
}

// voteBits sets the vote bits of a vote before it is signed.
func (d *vdDump) voteBits(bits uint16) func(*wire.MsgTx) {
	return func(tx *wire.MsgTx) {
		script, err := newVoteScript(stake.VoteBits{Bits: bits})
		if err != nil {
			d.t.Fatalf("vote script: %v", err)
		}
		tx.TxOut[1].PkScript = script
	}
}

// vdExportTxPool is the transaction pool session: chained acceptance,
// orphans and their policy, duplicates and double spends, the fee policy,
// sequence locks, expiry, ticket staging and the stake difficulty, batch
// acceptance and removals, an input the chain holds spent, and a ticket moved
// to the stage pool.

func vdExportTxPool(t *testing.T) string {
	// This file holds a single session, without a `net` row.
	var out strings.Builder
	d := vdNewSection(t, &out, "", chaincfg.MainNetParams(), vdTxPoolMedianTime)
	h := d.harness

	// Chained acceptance of five transactions.
	chain5, err := h.CreateTxChain(d.outs[0], 5)
	if err != nil {
		t.Fatal(err)
	}
	for _, tx := range chain5 {
		d.pt(tx, true, false, 0)
	}

	// An orphan chain, linked last.
	orphans, err := h.CreateTxChain(d.spend(chain5[4], 0), 4)
	if err != nil {
		t.Fatal(err)
	}
	for _, tx := range orphans[1:] {
		d.pt(tx, true, false, 3)
	}
	d.pt(orphans[0], true, false, 3)

	// Orphan policy: refusal, duplicates, removal by tag and by hash, and
	// the size limit.
	unknown := spendableOutput{
		outPoint: wire.OutPoint{Hash: chainhash.Hash{0xaa}},
		amount:   1e9,
	}
	orphan := d.must(h.CreateSignedTx([]spendableOutput{unknown}, 1))
	d.pt(orphan, false, false, 0)
	d.pt(orphan, true, false, 5)
	d.pt(orphan, true, false, 5)
	d.rmtag(5)
	d.pt(orphan, true, false, 6)
	d.rmorph(orphan)
	d.pt(d.must(h.CreateSignedTx([]spendableOutput{unknown}, 30)), true, false, 0)

	// A duplicate, a double spend, and a transaction already in the chain.
	d.pt(chain5[2], true, false, 0)
	d.pt(d.must(h.CreateSignedTx([]spendableOutput{d.spend(chain5[1], 0)}, 2)),
		true, false, 0)
	d.utxo(orphan, 100, 1)
	d.pt(orphan, true, false, 0)

	// Fee policy in both directions.
	funding := d.must(h.CreateCoinbaseTx(1, 8))
	d.utxo(funding, 1, 0)
	highFee := d.must(h.CreateSignedTx([]spendableOutput{d.spend(funding, 0)}, 1,
		func(tx *wire.MsgTx) { tx.TxOut[0].Value /= 2 }))
	d.pt(highFee, true, false, 0)
	d.pt(highFee, true, true, 0)
	noFee := d.must(h.CreateSignedTx([]spendableOutput{d.spend(funding, 1)}, 1,
		func(tx *wire.MsgTx) { tx.TxOut[0].Value = int64(d.spend(funding, 1).amount) }))
	d.pt(noFee, true, false, 0)

	// Sequence locks by height and by time.
	seqLock := func(sequence uint32) func(*wire.MsgTx) {
		return func(tx *wire.MsgTx) {
			tx.Version = 2
			tx.TxIn[0].Sequence = sequence
		}
	}
	d.pt(d.must(h.CreateSignedTx([]spendableOutput{d.spend(orphans[3], 0)}, 1,
		seqLock(2))), true, false, 0)
	d.pt(d.must(h.CreateSignedTx([]spendableOutput{d.spend(funding, 2)}, 1,
		seqLock(10))), true, false, 0)
	d.utxoTime(funding, 3)
	d.pt(d.must(h.CreateSignedTx([]spendableOutput{d.spend(funding, 3)}, 1,
		seqLock(wire.SequenceLockTimeIsSeconds|2))), true, false, 0)

	// Expiry, and pruning expired transactions.
	expiry := func(expiry uint32) func(*wire.MsgTx) {
		return func(tx *wire.MsgTx) { tx.Expiry = expiry }
	}
	d.pt(d.must(h.CreateSignedTx([]spendableOutput{d.spend(funding, 4)}, 1,
		expiry(257))), true, false, 0)
	d.pt(d.must(h.CreateSignedTx([]spendableOutput{d.spend(funding, 4)}, 1,
		expiry(266))), true, false, 0)
	d.pruneExpired(265)

	// Ticket staging and unstaging, and the stake difficulty.
	mined := d.must(h.CreateTx(d.spend(funding, 5)))
	d.utxo(mined, 200, 0)
	ticket := d.must(h.CreateTicketPurchaseFromTx(mined, 1e8))
	d.pt(ticket, true, false, 0)
	parent := d.must(h.CreateTx(d.spend(funding, 6)))
	d.pt(parent, true, false, 0)
	staged := d.must(h.CreateTicketPurchaseFromTx(parent, 1e8))
	d.pt(staged, true, false, 0)
	d.have(staged.Hash())
	d.spent(d.spend(parent, 0).outPoint)
	d.rmtx(parent, false)
	d.state()
	d.utxo(parent, 256, 1)
	d.mad(parent, false)
	d.setStakeDiff(2e8)
	d.pt(d.must(h.CreateTicketPurchaseFromTx(mined, 9e7)), true, false, 0)
	d.prune(2e8, 256)
	d.setStakeDiff(0)

	// Batch acceptance, double spend removal, and an orphan through
	// MaybeAcceptTransaction.
	batch, err := h.CreateTxChain(d.spend(funding, 7), 3)
	if err != nil {
		t.Fatal(err)
	}
	d.mats(batch)
	d.mats(batch[2:])
	d.rmds(d.must(h.CreateSignedTx([]spendableOutput{d.spend(funding, 7)}, 2)))
	d.mat(d.must(h.CreateSignedTx([]spendableOutput{unknown}, 2)), true)

	// Removal with redeemers.
	d.rmtx(chain5[1], true)
	d.state()

	// A transaction spending an output the chain holds spent is an orphan,
	// and a ticket in the pool whose input's transaction comes back to the
	// pool, as after the block that mined it is disconnected, moves to the
	// stage pool.
	back := d.must(h.CreateCoinbaseTx(1, 2))
	d.utxo(back, 1, 0)
	spentTx := d.must(h.CreateTx(d.spend(back, 0)))
	d.utxo(spentTx, 200, 0)
	d.chainSpend(d.spend(spentTx, 0).outPoint)
	d.pt(d.must(h.CreateTx(d.spend(spentTx, 0))), true, false, 0)
	returned := d.must(h.CreateTx(d.spend(back, 1)))
	d.utxo(returned, 200, 0)
	d.pt(d.must(h.CreateTicketPurchaseFromTx(returned, 1e8)), true, false, 0)
	d.chainSpend(d.spend(returned, 0).outPoint)
	d.mat(returned, false)
	return out.String()
}

// vdVotes is the main votes session: the vote orphan flow, a second vote by
// a ticket on a block, the five-vote limit across blocks with recovery, the
// height policy's precedence, the vote and revocation stake validation
// height gates, revocations, the disapproval tally and the metadata pruning.
func vdVotes(t *testing.T, out *strings.Builder) {
	params := chaincfg.MainNetParams()
	d := vdNewSection(t, out, "votes", params, vdStakeMedianTime)
	h := d.harness
	svh := params.StakeValidationHeight

	// The vote orphan flow (TestVoteOrphan).
	tx := d.must(h.CreateTx(d.outs[0]))
	ticket := d.must(h.CreateTicketPurchaseFromTx(tx, 40000))
	d.setHeight(svh)
	first := d.block()
	d.bestHash(first.Hash())
	d.winner(first.Hash(), ticket.Hash())
	vote := d.must(h.CreateVote(ticket))
	d.pt(vote, false, true, 0)
	d.pt(ticket, true, true, 0)
	d.pt(tx, false, true, 0)
	d.utxo(ticket, int64(ticket.MsgTx().TxIn[0].BlockHeight), wire.NullBlockIndex)
	d.pt(vote, false, true, 0)
	d.vhb(first.Hash())
	d.disap(first.Hash())

	// A second vote by the ticket on the same block.
	d.pt(d.must(h.CreateVote(ticket, d.voteBits(0x0001))), false, true, 0)

	// The five-vote limit on one ticket across blocks
	// (TestMaxVoteDoubleSpendRejection).
	funding := d.must(h.CreateCoinbaseTx(1, 6))
	d.utxo(funding, 1, 0)
	tx2 := d.must(h.CreateTx(d.spend(funding, 0)))
	d.utxo(tx2, 1, 0)
	ticket2 := d.must(h.CreateTicketPurchaseFromTx(tx2, 40000))
	d.setHeight(params.StakeEnabledHeight + 1)
	d.utxo(ticket2, h.chain.BestHeight(), wire.NullBlockIndex)
	d.setHeight(svh)
	votes := make([]*dcrutil.Tx, 0, maxVoteDoubleSpends*2)
	for range maxVoteDoubleSpends * 2 {
		block := d.block()
		d.bestHash(block.Hash())
		d.winner(block.Hash(), ticket2.Hash())
		votes = append(votes, d.must(h.CreateVote(ticket2)))
	}
	for _, vote := range votes {
		d.pt(vote, false, true, 0)
		d.vhbOf(vote)
	}
	d.rmtx(votes[2], true)
	d.state()
	d.vhbOf(votes[2])
	d.pt(votes[maxVoteDoubleSpends], false, true, 0)
	d.vhbOf(votes[maxVoteDoubleSpends])
	d.pt(votes[maxVoteDoubleSpends+1], false, true, 0)
	d.vhbOf(votes[maxVoteDoubleSpends+1])

	// The height policy runs before the double-vote checks: a vote too old
	// for the tip is refused as old even when its ticket is over the limit,
	// and one before stake validation height by that gate.
	old := d.must(h.CreateVote(ticket))
	d.setHeight(svh + 257)
	d.pt(old, false, true, 0)
	d.pt(votes[maxVoteDoubleSpends+2], false, true, 0)
	d.setHeight(svh - 2)
	d.pt(old, false, true, 0)
	d.setHeight(svh)

	// Revocations: one per ticket, and none before the height after stake
	// validation height.
	revocation := d.must(h.CreateRevocation(ticket2, 2550))
	d.pt(revocation, false, true, 0)
	second := d.must(h.CreateRevocation(ticket2, 2551))
	d.pt(second, false, true, 0)
	d.setHeight(svh - 1)
	d.pt(second, false, true, 0)
	d.setHeight(svh)

	// A block whose regular tree three votes disapprove, and the pruning of
	// the votes and their metadata.
	tickets := make([]*dcrutil.Tx, 0, 3)
	for i := uint32(1); i <= 3; i++ {
		spent := d.must(h.CreateTx(d.spend(funding, i)))
		d.utxo(spent, 1, 0)
		ticket := d.must(h.CreateTicketPurchaseFromTx(spent, 40000))
		d.utxo(ticket, params.StakeEnabledHeight+1, wire.NullBlockIndex)
		tickets = append(tickets, ticket)
	}
	disapproved := d.block()
	d.bestHash(disapproved.Hash())
	for _, ticket := range tickets {
		d.winner(disapproved.Hash(), ticket.Hash())
		d.pt(d.must(h.CreateVote(ticket, d.voteBits(0xfffe))), false, true, 0)
	}
	d.vhb(disapproved.Hash())
	d.disap(disapproved.Hash())
	d.prune(0, svh+heightDiffToPruneVotes)
	d.vhb(disapproved.Hash())
	d.prune(0, svh+heightDiffToPruneVotes+1)
	d.vhb(disapproved.Hash())
}

// vdDuplicateVote is TestDuplicateVoteRejection.
func vdDuplicateVote(t *testing.T, out *strings.Builder) {
	params := chaincfg.MainNetParams()
	d := vdNewSection(t, out, "dupvote", params, vdStakeMedianTime)
	h := d.harness

	tx := d.must(h.CreateTx(d.outs[0]))
	ticket := d.must(h.CreateTicketPurchaseFromTx(tx, 40000))
	d.setHeight(params.StakeEnabledHeight + 1)
	d.utxo(ticket, h.chain.BestHeight(), 0)
	d.setHeight(params.StakeValidationHeight)
	block := d.block()
	d.bestHash(block.Hash())
	d.winner(block.Hash(), ticket.Hash())
	vote := d.must(h.CreateVote(ticket))
	d.pt(vote, false, true, 0)
	d.vhbOf(vote)

	dupVote := d.must(h.CreateVote(ticket, d.voteBits(0x03)))
	d.pt(dupVote, false, true, 0)
	d.vhbOf(dupVote)

	d.rmtx(vote, true)
	d.state()
	d.vhbOf(vote)
	d.pt(dupVote, false, true, 0)
	d.vhbOf(dupVote)
}

// vdVoteHeight is TestVoteHeightPolicy.
func vdVoteHeight(t *testing.T, out *strings.Builder) {
	params := chaincfg.MainNetParams()
	d := vdNewSection(t, out, "voteheight", params, vdStakeMedianTime)
	h := d.harness

	const numVotes = 2
	multi := d.must(h.CreateSignedTx([]spendableOutput{d.outs[0]}, numVotes))
	tickets := make([]*dcrutil.Tx, 0, numVotes)
	for i := uint32(0); i < numVotes; i++ {
		tickets = append(tickets, d.must(h.CreateTicketPurchase(d.spend(multi, i),
			40000+int64(i))))
	}
	d.setHeight(params.StakeEnabledHeight + 1)
	for i := uint32(0); i < numVotes; i++ {
		d.utxo(tickets[i], h.chain.BestHeight(), i)
	}

	votedHeight := params.StakeValidationHeight + maxFutureVoteAge + 1
	d.setHeight(votedHeight)
	future := d.block()
	d.bestHash(future.Hash())
	votes := make([]*dcrutil.Tx, 0, numVotes)
	for i := uint32(0); i < numVotes; i++ {
		d.winner(future.Hash(), tickets[i].Hash())
		votes = append(votes, d.must(h.CreateVote(tickets[i])))
	}

	d.setHeight(votedHeight - maxFutureVoteAge - 1)
	d.pt(votes[0], false, true, 0)
	d.vhbOf(votes[0])
	d.setHeight(votedHeight - maxFutureVoteAge)
	d.pt(votes[0], false, true, 0)
	d.vhbOf(votes[0])

	maxVoteAge := int64(h.txPool.cfg.Policy.MaxVoteAge)
	d.setHeight(votedHeight + maxVoteAge)
	d.pt(votes[1], false, true, 0)
	d.vhbOf(votes[1])
	d.setHeight(votedHeight + maxVoteAge - 1)
	d.pt(votes[1], false, true, 0)
	d.vhbOf(votes[1])
}

// vdVoteValidity is TestVoteValidity.
func vdVoteValidity(t *testing.T, out *strings.Builder) {
	params := chaincfg.MainNetParams()
	d := vdNewSection(t, out, "votevalidity", params, vdStakeMedianTime)
	h := d.harness

	tx := d.must(h.CreateTx(d.outs[0]))
	ticket := d.must(h.CreateTicketPurchaseFromTx(tx, 40000))
	d.setHeight(params.StakeEnabledHeight + 1)
	d.utxo(ticket, h.chain.BestHeight(), 0)

	// A vote on a block the chain does not know.
	d.setHeight(params.StakeValidationHeight)
	origHash := *h.chain.BestHash()
	d.bestHash(&chainhash.Hash{})
	unknown := d.must(h.CreateVote(ticket))
	d.bestHash(&origHash)
	d.pt(unknown, false, true, 0)
	d.vhbOf(unknown)

	// A vote that claims the wrong height for its block.
	d.setHeight(params.StakeValidationHeight)
	block := d.block()
	d.bestHash(block.Hash())
	d.winner(block.Hash(), ticket.Hash())
	badHeight := d.must(h.CreateVote(ticket, func(tx *wire.MsgTx) {
		script, _ := txscript.GenerateSSGenBlockRef(*h.chain.BestHash(),
			uint32(h.chain.BestHeight()-1))
		tx.TxOut[0].PkScript = script
	}))
	d.pt(badHeight, false, true, 0)
	d.vhbOf(badHeight)

	// A vote whose ticket is not one of the block's winners.
	d.setHeight(params.StakeValidationHeight + 1)
	block = d.block()
	d.bestHash(block.Hash())
	badTicket := d.must(h.CreateVote(ticket))
	d.pt(badTicket, false, true, 0)
	d.vhbOf(badTicket)
}

// vdVotePruning is TestVotePruning.
func vdVotePruning(t *testing.T, out *strings.Builder) {
	params := chaincfg.MainNetParams()
	d := vdNewSection(t, out, "votepruning", params, vdStakeMedianTime)
	h := d.harness

	const numVotes = 4
	multi := d.must(h.CreateSignedTx([]spendableOutput{d.outs[0]}, numVotes))
	tickets := make([]*dcrutil.Tx, 0, numVotes)
	for i := uint32(0); i < numVotes; i++ {
		tickets = append(tickets, d.must(h.CreateTicketPurchase(d.spend(multi, i),
			40000+int64(i))))
	}
	d.setHeight(params.StakeEnabledHeight + 1)
	for i := uint32(0); i < numVotes; i++ {
		d.utxo(tickets[i], h.chain.BestHeight(), i)
	}

	const numBlocks = 2
	const votesPerBlock = numVotes / numBlocks
	offsets := [numBlocks]int64{0, 6}
	heights := make([]int64, numBlocks)
	hashes := make([]chainhash.Hash, numBlocks)
	for j, offset := range offsets {
		heights[j] = params.StakeValidationHeight + offset
		d.setHeight(heights[j])
		block := d.block()
		d.bestHash(block.Hash())
		hashes[j] = *block.Hash()
		for i := 0; i < votesPerBlock; i++ {
			ticket := tickets[j*votesPerBlock+i]
			d.winner(block.Hash(), ticket.Hash())
			vote := d.must(h.CreateVote(ticket))
			d.pt(vote, false, true, 0)
			d.vhbOf(vote)
		}
	}

	firstPrune := heights[0] + heightDiffToPruneVotes + 1
	secondPrune := heights[1] + heightDiffToPruneVotes + 1
	setHeightAndPrune := func(height int64) {
		d.setHeight(height)
		sdiff, err := h.chain.NextStakeDifficulty()
		if err != nil {
			t.Fatal(err)
		}
		d.prune(sdiff, height)
		d.vhb(&hashes[0])
		d.vhb(&hashes[1])
	}
	setHeightAndPrune(firstPrune - 2)
	setHeightAndPrune(firstPrune - 1)
	setHeightAndPrune(firstPrune)
	setHeightAndPrune(firstPrune)
	setHeightAndPrune(firstPrune + offsets[1] - 1)
	setHeightAndPrune(secondPrune)
	setHeightAndPrune(secondPrune + 100)
}

// vdVoteClocks shows the two clocks of the stake pruning: a vote accepted
// three blocks after the block it votes on outlives the metadata, which goes
// ten blocks past the block, by three blocks, and in between a second vote by
// its ticket on that block is accepted.
func vdVoteClocks(t *testing.T, out *strings.Builder) {
	params := chaincfg.MainNetParams()
	d := vdNewSection(t, out, "voteclocks", params, vdStakeMedianTime)
	h := d.harness
	svh := params.StakeValidationHeight

	tx := d.must(h.CreateTx(d.outs[0]))
	ticket := d.must(h.CreateTicketPurchaseFromTx(tx, 40000))
	d.setHeight(params.StakeEnabledHeight + 1)
	d.utxo(ticket, h.chain.BestHeight(), 0)
	d.setHeight(svh)
	block := d.block()
	d.bestHash(block.Hash())
	d.winner(block.Hash(), ticket.Hash())
	vote := d.must(h.CreateVote(ticket))
	again := d.must(h.CreateVote(ticket, d.voteBits(0x0001)))

	d.setHeight(svh + 3)
	d.pt(vote, false, true, 0)
	d.vhb(block.Hash())
	d.pt(again, false, true, 0)
	d.setHeight(svh + heightDiffToPruneVotes + 1)
	d.prune(0, svh+heightDiffToPruneVotes+1)
	d.vhb(block.Hash())
	d.pt(again, false, true, 0)
	d.vhb(block.Hash())
	d.setHeight(svh + heightDiffToPruneVotes + 3)
	d.prune(0, svh+heightDiffToPruneVotes+3)
	d.setHeight(svh + heightDiffToPruneVotes + 4)
	d.prune(0, svh+heightDiffToPruneVotes+4)
}

// vdVoteOrder pins where the vote checks sit among the others: the stake
// validation height gate runs before the height policy and the voted block
// lookup, the height policy before the lookup, the winners are looked up
// only after the scripts are checked, and not at all for a vote older than
// the cutoff when old votes are allowed.
func vdVoteOrder(t *testing.T, out *strings.Builder) {
	params := chaincfg.MainNetParams()
	d := vdNewSection(t, out, "voteorder", params, vdStakeMedianTime)
	h := d.harness
	svh := params.StakeValidationHeight

	tx := d.must(h.CreateTx(d.outs[0]))
	ticket := d.must(h.CreateTicketPurchaseFromTx(tx, 40000))
	d.setHeight(params.StakeEnabledHeight + 1)
	d.utxo(ticket, h.chain.BestHeight(), 0)
	d.setHeight(svh)

	// A vote on a block the chain does not know is refused as too old
	// when it is.
	origHash := *h.chain.BestHash()
	d.bestHash(&chainhash.Hash{0x01})
	unknown := d.must(h.CreateVote(ticket))
	d.bestHash(&origHash)
	d.setHeight(svh + 257)
	d.pt(unknown, false, true, 0)
	d.setHeight(svh)

	// A vote claiming a height past the future limit for a block the chain
	// knows at another height is refused as a future vote.
	block := d.block()
	d.bestHash(block.Hash())
	d.winner(block.Hash(), ticket.Hash())
	future := d.must(h.CreateVote(ticket, func(tx *wire.MsgTx) {
		script, _ := txscript.GenerateSSGenBlockRef(*block.Hash(),
			uint32(svh+maxFutureVoteAge+1))
		tx.TxOut[0].PkScript = script
	}))
	d.pt(future, false, true, 0)

	// Before stake validation height both votes are refused by that gate,
	// which runs ahead of the vote checks.
	d.setHeight(svh - 2)
	d.pt(unknown, false, true, 0)
	d.pt(future, false, true, 0)
	d.setHeight(svh)

	// A vote whose ticket is not a winner of its block and whose signature
	// does not verify is refused by the script check.
	loser := d.block()
	d.bestHash(loser.Hash())
	unsigned := d.must(h.CreateVote(ticket)).MsgTx()
	bits, err := newVoteScript(stake.VoteBits{Bits: 0x0001})
	if err != nil {
		t.Fatal(err)
	}
	unsigned.TxOut[1].PkScript = bits
	d.pt(dcrutil.NewTx(unsigned), false, true, 0)

	// An old vote whose ticket is not a winner of its block: refused as old,
	// and accepted once old votes are allowed, the winners unread.
	old := d.must(h.CreateVote(ticket))
	d.setHeight(svh + 257)
	d.pt(old, false, true, 0)
	d.allowOldVotes(true)
	d.pt(old, false, true, 0)
	d.vhbOf(old)
}

// tspend is dcrd's createTSpend with the given nonce in place of the
// math/rand draw, signed with the given key.
func (d *vdDump) tspend(expiry uint32, nonce uint64, key []byte) *dcrutil.Tx {
	piKey, _ := hex.DecodeString(vdPiKey)
	msgTx := createTSpend(d.t, expiry, 1e8, 2550, piKey)
	binary.LittleEndian.PutUint64(msgTx.TxOut[0].PkScript[25:], nonce)
	sigScript, err := sign.TSpendSignatureScript(msgTx, key)
	if err != nil {
		d.t.Fatalf("unable to sign tspend: %v", err)
	}
	msgTx.TxIn[0].SignatureScript = sigScript
	return dcrutil.NewTx(msgTx)
}

// vdPiKey is TestHandlesTSpends' Pi private key.
const vdPiKey = "62deae1ab2b1ebd96a28c80e870aee325bed359e83d8db2464ef999e616a9eef"

// vdTreasury is the treasury battery: TestHandlesTSpends with each rejection
// on a treasury spend of its own, TestHandlesTAdds' fee policy, and
// TestRejectTreasurybases.
func vdTreasury(t *testing.T, out *strings.Builder) {
	piKey, _ := hex.DecodeString(vdPiKey)
	piPubKey := secp256k1.PrivKeyFromBytes(piKey).PubKey().SerializeCompressed()
	net := chaincfg.MainNetParams()
	net.PiKeys = [][]byte{piPubKey, piPubKey}
	d := vdNewSection(t, out, "treasury", net, vdStakeMedianTime,
		"pikeys "+hex.EncodeToString(piPubKey))
	h := d.harness
	tvi := net.TreasuryVoteInterval
	mul := net.TreasuryVoteIntervalMultiplier

	d.treasury(true)
	nextHeight := net.StakeValidationHeight + int64(tvi) -
		net.StakeValidationHeight%int64(tvi)
	d.setHeight(nextHeight - 1)
	d.tsh()

	expiry := standalone.CalcTSpendExpiry(nextHeight-int64(tvi), tvi, mul)
	const maxTSpends = 7
	nonce := 0
	next := func(expiry uint32, key []byte) *dcrutil.Tx {
		tx := d.tspend(expiry, vdTSpendNonces[nonce], key)
		nonce++
		return tx
	}
	tspends := make([]*dcrutil.Tx, 0, maxTSpends+1)
	for i := 0; i < maxTSpends+1; i++ {
		tspends = append(tspends, next(expiry, piKey))
	}
	for _, tx := range tspends[:maxTSpends] {
		d.pt(tx, true, true, 0)
	}
	d.tsh()
	d.pt(tspends[maxTSpends], true, true, 0)
	d.rmtx(tspends[0], true)
	d.state()
	d.tsh()
	d.pt(tspends[maxTSpends], true, true, 0)
	for _, tx := range tspends[1 : maxTSpends+1] {
		d.rmtx(tx, true)
	}
	d.state()
	d.tsh()

	d.tspendMined(tspends[0])
	d.pt(tspends[0], true, true, 0)
	d.pt(next(expiry+1, piKey), true, true, 0)
	d.pt(next(uint32(tvi), piKey), true, true, 0)
	d.pt(next(expiry+uint32(tvi*mul*2), piKey), true, true, 0)
	badSig := next(expiry, piKey)
	badSig.MsgTx().TxIn[0].SignatureScript[1] ^= 0xff
	d.pt(badSig, true, true, 0)
	nonPiKey, _ := hex.DecodeString(
		"ffff1ab2b1ebd96a28c80e870aee325bed359e83d8db2464ef999e616a0000")
	d.pt(next(expiry, nonPiKey), true, true, 0)

	_, endVote, err := standalone.CalcTSpendWindow(expiry, tvi, mul)
	if err != nil {
		t.Fatal(err)
	}
	d.setHeight(int64(endVote - 1))
	d.pt(next(expiry, piKey), true, true, 0)
	d.setHeight(net.StakeValidationHeight - 2)
	d.pt(next(expiry, piKey), true, true, 0)
	d.setHeight(nextHeight - 1)

	// Treasury adds under the fee policy, the change to the harness's
	// address.
	funding := d.must(h.CreateCoinbaseTx(1, 2))
	d.utxo(funding, 1, 0)
	for i, fee := range []dcrutil.Amount{2550, 0} {
		spend := d.spend(funding, uint32(i))
		d.pt(dcrutil.NewTx(createTAdd(t, &spend, h.payScript, h.signKey, 1e8,
			fee, h.payAddr)), true, true, 0)
	}

	// A standalone treasurybase.
	d.setHeight(10)
	d.pt(vdTreasurybase(t, h, 10), false, true, 0)
	d.setHeight(nextHeight - 1)
}

// vdTreasurybase is TestRejectTreasurybases' createTreasurybase.
func vdTreasurybase(t *testing.T, h *poolHarness, blockHeight int64) *dcrutil.Tx {
	extraNonce := uint64(0)
	opRetData := make([]byte, 12)
	binary.LittleEndian.PutUint32(opRetData[0:4], uint32(blockHeight))
	binary.LittleEndian.PutUint64(opRetData[4:12], extraNonce)
	opReturnTreasury, err := stdscript.ProvablyPruneableScriptV0(opRetData)
	if err != nil {
		t.Fatal(err)
	}
	trsySubsidy := h.txPool.cfg.SubsidyCache.CalcTreasurySubsidy(blockHeight, 5,
		true)
	tx := wire.NewMsgTx()
	tx.Version = wire.TxVersionTreasury
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: *wire.NewOutPoint(&chainhash.Hash{},
			wire.MaxPrevOutIndex, wire.TxTreeRegular),
		Sequence:        wire.MaxTxInSequenceNum,
		ValueIn:         trsySubsidy,
		BlockHeight:     wire.NullBlockHeight,
		BlockIndex:      wire.NullBlockIndex,
		SignatureScript: nil,
	})
	tx.AddTxOut(newTxOut(trsySubsidy, 0, []byte{txscript.OP_TADD}))
	tx.AddTxOut(newTxOut(0, 0, opReturnTreasury))
	return dcrutil.NewTx(tx)
}

func vdExportStake(t *testing.T) string {
	var out strings.Builder
	vdVotes(t, &out)
	vdDuplicateVote(t, &out)
	vdVoteHeight(t, &out)
	vdVoteValidity(t, &out)
	vdVotePruning(t, &out)
	vdVoteClocks(t, &out)
	vdVoteOrder(t, &out)
	vdTreasury(t, &out)
	return out.String()
}

// vdAutoRevocations is TestRevocationsWithAutoRevocationsEnabled.
func vdAutoRevocations(t *testing.T, out *strings.Builder) {
	params := chaincfg.MainNetParams()
	d := vdNewSection(t, out, "autorev", params, vdAgendaMedianTime)
	h := d.harness

	d.autoRevocations(true)
	tx := d.must(h.CreateTx(d.outs[0]))
	ticket := d.must(h.CreateTicketPurchaseFromTx(tx, 40000))
	d.setHeight(params.StakeValidationHeight + 1)
	d.pt(tx, false, true, 0)
	d.pt(ticket, false, true, 0)
	d.utxo(ticket, int64(ticket.MsgTx().TxIn[0].BlockHeight), wire.NullBlockIndex)

	revocation := d.must(h.CreateRevocation(ticket, 0))
	revocation.MsgTx().TxOut[0].Value--
	d.pt(revocation, false, true, 0)
	revocation = d.must(h.CreateRevocation(ticket, 0))
	revocation.SetVersion(1)
	d.pt(revocation, false, true, 0)
	revocation.SetVersion(stake.TxVersionAutoRevocations)
	d.pt(revocation, false, true, 0)
	sdiff, err := h.chain.NextStakeDifficulty()
	if err != nil {
		t.Fatal(err)
	}
	d.prune(sdiff, h.chain.BestHeight()+1)
}

// vdSubsidySplit is TestSubsidySplitSemantics (r2 false) or
// TestSubsidySplitR2Semantics (r2 true).
func vdSubsidySplit(t *testing.T, out *strings.Builder, r2 bool) {
	params := chaincfg.MainNetParams()
	name, toggle := "ss", (*vdDump).subsidySplit
	if r2 {
		name, toggle = "ssr2", (*vdDump).subsidySplitR2
	}
	d := vdNewSection(t, out, name, params, vdAgendaMedianTime)
	h := d.harness

	tx := d.must(h.CreateTx(d.outs[0]))
	ticket := d.must(h.CreateTicketPurchaseFromTx(tx, 40000))
	d.setHeight(params.StakeEnabledHeight + 1)
	d.utxo(ticket, h.chain.BestHeight(), 0)

	toggle(d, false)
	d.setHeight(params.StakeValidationHeight)
	block := d.block()
	d.bestHash(block.Hash())
	d.winner(block.Hash(), ticket.Hash())
	preVote := d.must(h.CreateVote(ticket))
	toggle(d, true)
	postVote := d.must(h.CreateVote(ticket))

	toggle(d, false)
	d.pt(postVote, false, true, 0)
	d.pt(preVote, false, true, 0)
	d.rmtx(preVote, true)
	d.state()
	toggle(d, true)
	d.pt(preVote, false, true, 0)
	d.pt(postVote, false, true, 0)
}

func vdExportAgendas(t *testing.T) string {
	var out strings.Builder
	vdAutoRevocations(t, &out)
	vdSubsidySplit(t, &out, false)
	vdSubsidySplit(t, &out, true)
	return out.String()
}

// TestExportMempoolVectors writes the three vector files into the directory
// MEMPOOL_VECTORS_DIR names, and is skipped without it.
func TestExportMempoolVectors(t *testing.T) {
	dir := os.Getenv("MEMPOOL_VECTORS_DIR")
	if dir == "" {
		t.Skip("MEMPOOL_VECTORS_DIR is not set")
	}
	backend := slog.NewBackend(&vdLog, slog.WithFlags(slog.Lnodatetime))
	logger := backend.Logger("TXMP")
	logger.SetLevel(slog.LevelTrace)
	UseLogger(logger)
	defer UseLogger(slog.Disabled)
	files := []struct {
		name string
		gen  func(*testing.T) string
	}{
		{"txpool_vectors.txt", vdExportTxPool},
		{"txstake_vectors.txt", vdExportStake},
		{"review_agenda_vectors.txt", vdExportAgendas},
	}
	for _, f := range files {
		data := f.gen(t)
		if !bytes.HasSuffix([]byte(data), []byte("\n")) {
			t.Fatalf("%s: no final newline", f.name)
		}
		path := filepath.Join(dir, f.name)
		if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
}
