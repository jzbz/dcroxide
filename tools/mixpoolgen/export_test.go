// SPDX-License-Identifier: ISC

//go:build dcroxide_export

// The generator of crates/dcroxide-mixing/tests/data/mixpool_vectors.txt.  It
// runs as a test inside dcrd's own mixing/mixpool package, so every
// expectation it writes is what dcrd's pool did with the scripted messages;
// run.sh in this directory arranges that without touching the dcrd checkout.
// The rows it writes are those the replay in
// crates/dcroxide-mixing/tests/mixpool_vectors.rs reads.
//
// dcrd's mixpool reads time.Now() and time.Since() directly, and the script
// is time-sensitive: key exchange epochs are judged against the wall clock
// (too early, too late, not on a minute), and the orphan sweep against both
// clocks.  run.sh therefore overlays a copy of mixpool.go whose calls go
// through exportNow and exportSince below, which answer the scenario's
// recorded time.  That copy also declares exportSeamed, which this file
// names, so the generator cannot be built against an unseamed pool and write
// vectors on the real clock.
//
// Every message is built here and signed with a private key made of one
// repeated byte, so the inputs are reproducible.  DCROXIDE_MIXPOOL_SCRIPT
// picks the script: "6f6cf21b" is the one the file held at that parity pin
// (key exchange epochs an hour old, which dcrd now refuses as too late), and
// anything else, or nothing, is the current one, whose epochs are whole
// minutes inside dcrd's twenty-minute window and which adds a scenario for
// the key exchange rules dcrd gained after 6f6cf21b.

package mixpool

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/crypto/blake256"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/mixing"
	"github.com/decred/dcrd/mixing/utxoproof"
	"github.com/decred/dcrd/txscript/v4/stdaddr"
	"github.com/decred/dcrd/wire"
)

// The clock seam the overlaid mixpool.go calls.
var exportClock time.Time

func exportNow() time.Time                  { return exportClock }
func exportSince(t time.Time) time.Duration { return exportClock.Sub(t) }

// Fails to compile unless mixpool.go is the seamed copy run.sh writes.
var _ = exportSeamed

// recordedNow is the wall time every scenario runs at, in Unix seconds: the
// time the file's earlier exporter ran at, kept so that the file changes only
// where the script does.
const recordedNow = 1783328690

// epochs holds the key exchange epochs a script uses.
type epochs struct {
	main     uint64 // every ordinary session
	second   uint64 // the observer's second epoch
	early    uint64 // more than five seconds ahead: too early
	badSID   uint64 // stated by a key exchange whose sid is main's
	extended bool   // whether the script has the key exchange rules scenario
}

func scriptEpochs(legacy bool) epochs {
	if legacy {
		return epochs{
			main:   recordedNow - 3600,
			second: recordedNow - 3000,
			early:  recordedNow + 3600,
			badSID: recordedNow - 3595,
		}
	}
	// The earliest whole minute dcrd's late gate accepts, and minute
	// multiples from there.
	main := uint64(recordedNow-20*60+59) / 60 * 60
	return epochs{
		main:     main,
		second:   main + 600,
		early:    uint64(recordedNow+3600) / 60 * 60,
		badSID:   main + 60,
		extended: true,
	}
}

func privKey(n byte) *secp256k1.PrivateKey {
	return secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{n}, 32))
}

func identity(n byte) [33]byte {
	var id [33]byte
	copy(id[:], privKey(n).PubKey().SerializeCompressed())
	return id
}

func opHash(b byte) chainhash.Hash {
	return chainhash.Hash{b}
}

// exportChain is the mock chain; the fetcher variant also answers UTXOs.
type exportChain struct {
	params *chaincfg.Params
	height int64
}

func (c *exportChain) ChainParams() *chaincfg.Params       { return c.params }
func (c *exportChain) CurrentTip() (chainhash.Hash, int64) { return chainhash.Hash{1}, c.height }

type exportUtxo struct {
	pkScript []byte
	ver      uint16
	height   int64
	amount   int64
	spent    bool
}

func (u *exportUtxo) IsSpent() bool         { return u.spent }
func (u *exportUtxo) PkScript() []byte      { return u.pkScript }
func (u *exportUtxo) ScriptVersion() uint16 { return u.ver }
func (u *exportUtxo) BlockHeight() int64    { return u.height }
func (u *exportUtxo) Amount() int64         { return u.amount }

type fetcherChain struct {
	exportChain
	utxos map[wire.OutPoint]*exportUtxo
}

func (c *fetcherChain) FetchUtxoEntry(op wire.OutPoint) (UtxoEntry, error) {
	u, ok := c.utxos[op]
	if !ok {
		return nil, errors.New("no utxo entry")
	}
	return u, nil
}

type gen struct {
	t   *testing.T
	w   *bufio.Writer
	p   *Pool
	fc  *fetcherChain
	src Uint64Source
	ep  epochs
}

func (g *gen) printf(format string, args ...any) {
	fmt.Fprintf(g.w, format, args...)
}

func csv(items []string) string {
	if len(items) == 0 {
		return "-"
	}
	sort.Strings(items)
	return strings.Join(items, ",")
}

func hashList(hs []chainhash.Hash) string {
	s := make([]string, len(hs))
	for i, h := range hs {
		s[i] = h.String()
	}
	return csv(s)
}

func (g *gen) scenario(name string, params *chaincfg.Params, fetcher bool, height int64, src Uint64Source) {
	exportClock = time.Unix(recordedNow, 0)
	g.src = src
	f := 0
	var bc BlockChain
	if fetcher {
		f = 1
		g.fc = &fetcherChain{
			exportChain: exportChain{params: params, height: height},
			utxos:       make(map[wire.OutPoint]*exportUtxo),
		}
		bc = g.fc
	} else {
		g.fc = nil
		bc = &exportChain{params: params, height: height}
	}
	g.p = NewPool(bc)
	g.printf("scenario %s %s %d %d %d\n", name, params.Name, f, height, recordedNow)
}

func (g *gen) state() {
	p := g.p
	var prs, pool, orphans, sessions []string
	for h := range p.prs {
		prs = append(prs, h.String())
	}
	for h, e := range p.pool {
		pool = append(pool, fmt.Sprintf("%s:%s", h, e.msgtype))
	}
	for h := range p.orphans {
		orphans = append(orphans, h.String())
	}
	for sid, ses := range p.sessions {
		counts := make([]string, len(ses.counts))
		for i, c := range ses.counts {
			counts[i] = fmt.Sprint(c)
		}
		sessions = append(sessions, fmt.Sprintf("%x:%d:%d:%s", sid[:], ses.expiry,
			len(ses.hashes), strings.Join(counts, ".")))
	}
	g.printf("prs %s\npool %s\norphans %s\nsessions %s\n", csv(prs), csv(pool),
		csv(orphans), csv(sessions))
	g.printf("counts %d %d\nendstate\n", len(p.outPoints), len(p.latestKE))
}

func errCode(err error) string {
	named := []struct {
		err  error
		code string
	}{
		{ErrChangeDust, "changedust"},
		{ErrMixDust, "mixdust"},
		{ErrLowInput, "lowinput"},
		{ErrHighFee, "highfee"},
		{ErrInvalidMessageCount, "msgcount"},
		{ErrInvalidScript, "invalidscript"},
		{ErrInvalidSessionID, "sessionid"},
		{ErrInvalidSignature, "signature"},
		{ErrInvalidTotalMixAmount, "totalmix"},
		{ErrInvalidUTXOProof, "utxoproof"},
		{ErrMissingUTXOs, "missingutxos"},
		{ErrPeerPositionOutOfBounds, "posbounds"},
		{ErrSecretsRevealed, "secretsrevealed"},
	}
	for _, n := range named {
		if errors.Is(err, n.err) {
			return n.code
		}
	}
	var missing *MissingOwnPRError
	if errors.As(err, &missing) {
		return "missingownpr"
	}
	var re *RuleError
	if errors.As(err, &re) {
		return "rule:" + err.Error()
	}
	return "err:" + err.Error()
}

func (g *gen) accept(msg mixing.Message) {
	msg.WriteHash(blake256.New())
	var buf bytes.Buffer
	if err := msg.BtcEncode(&buf, wire.MixVersion); err != nil {
		g.t.Fatal(err)
	}
	g.printf("accept %s %x %d\n", msg.Command(), buf.Bytes(), uint64(g.src))
	accepted, err := g.p.AcceptMessage(msg, g.src)
	if err != nil {
		g.printf("res err %s\n", errCode(err))
	} else {
		hs := make([]chainhash.Hash, len(accepted))
		for i, m := range accepted {
			hs[i] = m.Hash()
		}
		g.printf("res ok %s\n", hashList(hs))
	}
	g.state()
}

func sign[M mixing.Signed](g *gen, n byte, m M) M {
	if err := mixing.SignMessage(m, privKey(n)); err != nil {
		g.t.Fatal(err)
	}
	return m
}

func hashOf(m mixing.Message) chainhash.Hash {
	m.WriteHash(blake256.New())
	return m.Hash()
}

// A pair request in the shape every scenario starts from.
func basePR(n byte, outpoint byte, expiry uint32) *wire.MsgMixPairReq {
	return &wire.MsgMixPairReq{
		Identity:     identity(n),
		Expiry:       expiry,
		MixAmount:    1 << 18,
		ScriptClass:  string(mixing.ScriptClassP2PKHv0),
		MessageCount: 1,
		InputValue:   1<<18 + 3000,
		UTXOs: []wire.MixPairReqUTXO{{
			OutPoint: wire.OutPoint{Hash: opHash(outpoint)},
		}},
	}
}

// A key exchange by identity n for the session the pair requests form in
// epoch, at the unmixed position of own.
func keyExchange(n byte, prs []*wire.MsgMixPairReq, own *wire.MsgMixPairReq, epoch uint64) *wire.MsgMixKeyExchange {
	sorted := append([]*wire.MsgMixPairReq(nil), prs...)
	for _, pr := range sorted {
		pr.WriteHash(blake256.New())
	}
	sid := mixing.SortPRsForSession(sorted, epoch)
	ke := &wire.MsgMixKeyExchange{
		Identity:  identity(n),
		SessionID: sid,
		Epoch:     epoch,
	}
	ownHash := hashOf(own)
	for i, pr := range sorted {
		h := hashOf(pr)
		ke.SeenPRs = append(ke.SeenPRs, h)
		if h == ownHash {
			ke.Pos = uint32(i)
		}
	}
	return ke
}

func ciphertexts(n byte, sid [32]byte, count int, seen []chainhash.Hash) *wire.MsgMixCiphertexts {
	return &wire.MsgMixCiphertexts{
		Identity:         identity(n),
		SessionID:        sid,
		Ciphertexts:      make([][1047]byte, count),
		SeenKeyExchanges: seen,
	}
}

func slotReserve(n byte, sid [32]byte, seen []chainhash.Hash) *wire.MsgMixSlotReserve {
	return &wire.MsgMixSlotReserve{
		Identity:        identity(n),
		SessionID:       sid,
		DCMix:           [][][]byte{{bytes.Repeat([]byte{0x0a}, 16)}},
		SeenCiphertexts: seen,
	}
}

func dcNet(n byte, sid [32]byte, seen []chainhash.Hash) *wire.MsgMixDCNet {
	var v [wire.MixMsgSize]byte
	for i := range v {
		v[i] = 0x0d
	}
	return &wire.MsgMixDCNet{
		Identity:         identity(n),
		SessionID:        sid,
		DCNet:            []wire.MixVect{{v}},
		SeenSlotReserves: seen,
	}
}

// mixTx spends output 0 of the outpoint hash each input byte names and pays
// 1<<18 atoms to a 25-byte script of one repeated byte.
func mixTx(inputs []byte, script byte) *wire.MsgTx {
	tx := wire.NewMsgTx()
	for _, in := range inputs {
		tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: opHash(in)}})
	}
	tx.AddTxOut(wire.NewTxOut(1<<18, bytes.Repeat([]byte{script}, 25)))
	return tx
}

func confirm(n byte, sid [32]byte, tx *wire.MsgTx, seen []chainhash.Hash) *wire.MsgMixConfirm {
	return &wire.MsgMixConfirm{
		Identity:   identity(n),
		SessionID:  sid,
		Mix:        *tx.Copy(),
		SeenDCNets: seen,
	}
}

func txHex(tx *wire.MsgTx) string {
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buf.Bytes())
}

// A pair request the pool never sees, referenced only for its hash.
func unknownPR(n uint32) *wire.MsgMixPairReq {
	return &wire.MsgMixPairReq{
		ScriptClass:  string(mixing.ScriptClassP2PKHv0),
		MessageCount: 1,
		LockTime:     n,
	}
}

func TestExportMixpoolVectors(t *testing.T) {
	out := os.Getenv("DCROXIDE_MIXPOOL_VECTORS")
	if out == "" {
		t.Fatal("DCROXIDE_MIXPOOL_VECTORS must name the output file")
	}
	legacy := os.Getenv("DCROXIDE_MIXPOOL_SCRIPT") == "6f6cf21b"
	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	g := &gen{t: t, w: bufio.NewWriter(f), ep: scriptEpochs(legacy)}

	g.noFetcher()
	g.fetcher()
	g.removals()
	g.receive()
	g.observer()
	if g.ep.extended {
		g.keyExchangeRules()
	}
	g.printf("done\n")
	if err := g.w.Flush(); err != nil {
		t.Fatal(err)
	}
}

// noFetcher runs every rule rejection a pool without a UTXO fetcher reaches,
// an orphan cascade, and expiry.
func (g *gen) noFetcher() {
	g.scenario("nofetcher", chaincfg.TestNet3Params(), false, 100, 7)
	ep := g.ep

	pr1 := sign(g, 17, basePR(17, 0xa1, 110))
	ke1 := keyExchange(17, []*wire.MsgMixPairReq{pr1}, pr1, ep.main)
	sid1 := ke1.SessionID

	// An FP and a KE before their pair request: both orphaned, and both
	// accepted when it arrives.
	fp := &wire.MsgMixFactoredPoly{
		Identity:  identity(17),
		SessionID: sid1,
		Roots:     [][]byte{bytes.Repeat([]byte{0x0b}, 16)},
	}
	g.accept(sign(g, 17, fp))
	g.accept(sign(g, 17, ke1))
	g.accept(pr1)
	g.accept(pr1)

	ke1Hash := hashOf(ke1)
	g.accept(sign(g, 17, ciphertexts(17, sid1, 1, []chainhash.Hash{ke1Hash})))
	g.accept(sign(g, 17, ciphertexts(17, sid1, 2, []chainhash.Hash{ke1Hash, {0x77}})))
	rerun := ciphertexts(17, sid1, 1, []chainhash.Hash{ke1Hash})
	rerun.Run = 1
	g.accept(sign(g, 17, rerun))

	// Signed, then changed.
	ct1 := ciphertexts(17, sid1, 1, []chainhash.Hash{ke1Hash})
	sign(g, 17, ct1)
	sr := sign(g, 17, slotReserve(17, sid1, []chainhash.Hash{hashOf(ct1)}))
	sr.SeenCiphertexts = append(sr.SeenCiphertexts, chainhash.Hash{0x88})
	g.accept(sr)

	g.accept(sign(g, 17, basePR(17, 0xa2, 111)))
	g.accept(sign(g, 18, basePR(18, 0xa1, 110)))
	g.accept(sign(g, 18, basePR(18, 0xa1, 115)))

	pr := basePR(19, 0xa3, 110)
	pr.Change = &wire.TxOut{Value: 1, PkScript: bytes.Repeat([]byte{0x76}, 25)}
	g.accept(sign(g, 19, pr))
	pr = basePR(19, 0xa3, 110)
	pr.UTXOs = nil
	g.accept(sign(g, 19, pr))
	pr = basePR(19, 0xa3, 110)
	pr.MessageCount = 0
	g.accept(sign(g, 19, pr))
	pr = basePR(19, 0xa3, 110)
	pr.MixAmount = 1
	pr.InputValue = 1 << 18
	g.accept(sign(g, 19, pr))
	pr = basePR(19, 0xa3, 110)
	pr.InputValue = 1 << 17
	g.accept(sign(g, 19, pr))
	g.accept(sign(g, 19, basePR(19, 0xa3, 100)))
	g.accept(sign(g, 19, basePR(19, 0xa3, 132)))
	pr = basePR(19, 0xa3, 110)
	pr.ScriptClass = "P2SH-not-supported"
	g.accept(sign(g, 19, pr))
	pr = basePR(19, 0xa3, 110)
	pr.InputValue = 1<<18 + 1000
	g.accept(sign(g, 19, pr))
	pr = basePR(19, 0xa3, 110)
	pr.InputValue = 1<<18 + 3e9
	g.accept(sign(g, 19, pr))
	pr = basePR(19, 0xa3, 110)
	pr.MessageCount = 17
	pr.InputValue = 10 << 20
	g.accept(sign(g, 19, pr))
	pr16 := sign(g, 19, basePR(19, 0xa3, 110))
	g.accept(pr16)

	prs := []*wire.MsgMixPairReq{pr16}
	ke := keyExchange(19, prs, pr16, ep.main)
	ke.Pos = 5
	g.accept(sign(g, 19, ke))
	g.accept(sign(g, 19, keyExchange(19, prs, pr16, ep.early)))
	ke = keyExchange(19, prs, pr16, ep.main)
	ke.Epoch = ep.badSID
	g.accept(sign(g, 19, ke))
	g.accept(sign(g, 18, keyExchange(18, prs, pr16, ep.main)))

	pr1Hash := hashOf(pr1)
	g.printf("havemessage %s %v\n", pr1Hash, g.p.HaveMessage(&pr1Hash))
	code := ""
	if _, err := g.p.Message(&pr1Hash); err != nil {
		code = errCode(err)
	}
	g.printf("message %s %s\n", pr1Hash, code)
	g.expire(109)
	g.expire(110)
	_, recent := g.p.RecentMessage(&pr1Hash)
	g.printf("recentmessage %s %v\n", pr1Hash, recent)
	g.expire(120)
}

func (g *gen) expire(height uint32) {
	g.printf("expire %d\n", height)
	g.p.ExpireMessages(height)
	g.state()
}

// fetcher runs the pair request UTXO checks over a mocked fetcher.
func (g *gen) fetcher() {
	g.scenario("fetcher", chaincfg.SimNetParams(), true, 1000, 9)

	owner := privKey(33)
	ownerPub := owner.PubKey().SerializeCompressed()
	p2pkh := append([]byte{0x76, 0xa9, 0x14}, stdaddr.Hash160(ownerPub)...)
	p2pkh = append(p2pkh, 0x88, 0xac)
	kp := utxoproof.Secp256k1KeyPair{Pub: ownerPub, Priv: owner}
	proof := func(expires uint32) []byte {
		sig, err := kp.SignUtxoProof(expires)
		if err != nil {
			g.t.Fatal(err)
		}
		return sig
	}

	utxo := func(i byte, prefix []byte, height, amount int64, spent bool, ver uint16) {
		op := wire.OutPoint{Hash: opHash(i), Index: uint32(i)}
		script := append(append([]byte(nil), prefix...), p2pkh...)
		g.fc.utxos[op] = &exportUtxo{pkScript: script, ver: ver, height: height,
			amount: amount, spent: spent}
		g.printf("utxo %s %d %x %d %d %v %d\n", op.Hash, op.Index, script, height,
			amount, spent, ver)
	}
	utxo(0x31, nil, 900, 2e9, false, 0)
	utxo(0x32, nil, 900, 2e9, true, 0)
	utxo(0x33, nil, 1000, 2e9, false, 0)
	utxo(0x34, nil, 900, 2e9, false, 1)
	utxo(0x35, []byte{0xbb}, 900, 1e9, false, 0)
	utxo(0x36, []byte{0xbc}, 900, 5e8, false, 0)
	utxo(0x37, []byte{0xc3}, 900, 5e8, false, 0)

	in := func(i byte, opcode byte) wire.MixPairReqUTXO {
		return wire.MixPairReqUTXO{
			OutPoint:  wire.OutPoint{Hash: opHash(i), Index: uint32(i)},
			PubKey:    ownerPub,
			Signature: proof(1010),
			Opcode:    opcode,
		}
	}
	pr := func(n byte, utxos ...wire.MixPairReqUTXO) *wire.MsgMixPairReq {
		return &wire.MsgMixPairReq{
			Identity:     identity(n),
			Expiry:       1010,
			MixAmount:    2e9 - 3000,
			ScriptClass:  string(mixing.ScriptClassP2PKHv0),
			MessageCount: 1,
			InputValue:   2e9,
			UTXOs:        utxos,
		}
	}

	g.accept(sign(g, 34, pr(34, in(0x31, 0))))
	g.accept(sign(g, 35, pr(35, in(0x35, 0xbb), in(0x36, 0xbc), in(0x37, 0xc3))))
	missing := in(0x99, 0)
	missing.OutPoint.Index = 0
	g.accept(sign(g, 36, pr(36, missing)))
	g.accept(sign(g, 36, pr(36, in(0x32, 0))))
	g.accept(sign(g, 36, pr(36, in(0x33, 0))))
	g.accept(sign(g, 36, pr(36, in(0x34, 0))))
	g.accept(sign(g, 36, pr(36, in(0x31, 0x51))))
	m := pr(36, in(0x31, 0), in(0x31, 0))
	m.InputValue = 4e9
	g.accept(sign(g, 36, m))
	p2sh := in(0x31, 0)
	p2sh.Script = []byte{0x51}
	g.accept(sign(g, 36, pr(36, p2sh)))
	wrongExpiry := in(0x31, 0)
	wrongExpiry.Signature = proof(1011)
	g.accept(sign(g, 36, pr(36, wrongExpiry)))
	m = pr(36, in(0x31, 0))
	m.MixAmount = 1e9 - 3000
	m.InputValue = 1e9
	g.accept(sign(g, 36, m))
}

// removals runs the pairing queries and every removal path.
func (g *gen) removals() {
	g.scenario("removals", chaincfg.TestNet3Params(), false, 100, 3)
	ep := g.ep

	pr28 := sign(g, 65, basePR(65, 0xb1, 110))
	pr29 := sign(g, 66, basePR(66, 0xb2, 112))
	g.accept(pr28)
	g.accept(pr29)
	prs := []*wire.MsgMixPairReq{pr28, pr29}
	ke6 := sign(g, 65, keyExchange(65, prs, pr28, ep.main))
	ke7 := sign(g, 66, keyExchange(66, prs, pr29, ep.main))
	g.accept(ke6)
	g.accept(ke7)

	pairing, err := pr28.Pairing()
	if err != nil {
		g.t.Fatal(err)
	}
	var kes []chainhash.Hash
	for _, ke := range g.p.ReceiveKEsByPairing(pairing, ep.main) {
		kes = append(kes, ke.Hash())
	}
	g.printf("receivekes %x %d %s\n", pairing, ep.main, hashList(kes))
	var compat []string
	for _, pr := range g.p.CompatiblePRs(pairing) {
		compat = append(compat, pr.Hash().String())
	}
	if len(compat) == 0 {
		compat = []string{"-"}
	}
	g.printf("compatibleprs %x %s\n", pairing, strings.Join(compat, ","))
	var mixPRs []chainhash.Hash
	for _, pr := range g.p.MixPRs() {
		mixPRs = append(mixPRs, pr.Hash())
	}
	g.printf("mixprs %s\n", hashList(mixPRs))

	tx := mixTx([]byte{0xb1, 0xb2}, 0x51)
	g.accept(sign(g, 65, confirm(65, ke6.SessionID, tx, []chainhash.Hash{ke6.Hash()})))
	g.accept(sign(g, 66, confirm(66, ke7.SessionID, tx, []chainhash.Hash{ke7.Hash()})))
	spend := wire.NewMsgTx()
	spend.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: opHash(0xb1)}})
	g.printf("nonmix %s %v\n", txHex(spend), g.p.NonMixSpendsPR(spend))
	g.printf("nonmix %s %v\n", txHex(tx), g.p.NonMixSpendsPR(tx))
	g.printf("removespentprs %s\n", txHex(tx))
	g.p.RemoveSpentPRs([]*wire.MsgTx{tx})
	g.state()

	pr30 := sign(g, 67, basePR(67, 0xb3, 110))
	g.accept(pr30)
	ke8 := sign(g, 67, keyExchange(67, []*wire.MsgMixPairReq{pr30}, pr30, ep.main))
	g.accept(ke8)
	g.printf("removesession %x\n", ke8.SessionID[:])
	g.p.RemoveSession(ke8.SessionID)
	g.state()

	pr31 := sign(g, 68, basePR(68, 0xb4, 110))
	g.accept(pr31)
	g.printf("removemessage %s\n", pr31.Hash())
	g.p.RemoveMessage(pr31)
	g.state()

	confirmed := mixTx([]byte{0xb5}, 0x52)
	pr32 := sign(g, 69, basePR(69, 0xb5, 110))
	g.accept(pr32)
	ke9 := sign(g, 69, keyExchange(69, []*wire.MsgMixPairReq{pr32}, pr32, ep.main))
	g.accept(ke9)
	g.accept(sign(g, 69, confirm(69, ke9.SessionID, confirmed, []chainhash.Hash{ke9.Hash()})))
	txHash := confirmed.TxHash()
	g.printf("removeconfirmedmixes %s\n", txHash)
	g.p.RemoveConfirmedMixes([]chainhash.Hash{txHash})
	g.state()

	pr33 := sign(g, 70, basePR(70, 0xb6, 110))
	g.accept(pr33)
	ke10 := sign(g, 70, keyExchange(70, []*wire.MsgMixPairReq{pr33}, pr33, ep.main))
	g.accept(ke10)
	g.accept(sign(g, 70, confirm(70, ke10.SessionID, confirmed, []chainhash.Hash{ke10.Hash()})))
	g.printf("removeconfirmedsessions\n")
	g.p.RemoveConfirmedSessions()
	g.state()

	pr34 := sign(g, 71, basePR(71, 0xb7, 110))
	g.accept(pr34)
	g.printf("removeunresponsive %d %s\n", ep.main, pr34.Hash())
	g.p.RemoveUnresponsiveDuringEpoch([]*wire.MsgMixPairReq{pr34}, ep.main)
	g.state()
}

// receive runs the receive collection semantics.  The capacity-misuse row
// stays the last operation on its pool: dcrd returns that error with the
// read lock still held, so any later write would deadlock (QK-0003).
func (g *gen) receive() {
	g.scenario("receive", chaincfg.TestNet3Params(), false, 100, 5)
	ep := g.ep

	pr35 := sign(g, 81, basePR(81, 0xc1, 110))
	pr36 := sign(g, 82, basePR(82, 0xc2, 110))
	g.accept(pr35)
	g.accept(pr36)
	prs := []*wire.MsgMixPairReq{pr35, pr36}
	ke11 := sign(g, 81, keyExchange(81, prs, pr35, ep.main))
	ke12 := sign(g, 82, keyExchange(82, prs, pr36, ep.main))
	g.accept(ke11)
	g.accept(ke12)
	sid := ke11.SessionID
	g.accept(sign(g, 81, ciphertexts(81, sid, 2, []chainhash.Hash{ke11.Hash(), ke12.Hash()})))

	g.receiveRow(sid, "all")
	g.receiveRow(sid, "kes")
	g.receiveRow([32]byte{0x99}, "unknown")
	g.accept(sign(g, 81, &wire.MsgMixSecrets{
		Identity:    identity(81),
		SessionID:   sid,
		SeenSecrets: []chainhash.Hash{ke11.Hash()},
	}))
	g.receiveRow(sid, "kes")
	g.receiveRow(sid, "rss")
	g.receiveRow(sid, "twocaps")
}

func (g *gen) receiveRow(sid [32]byte, kind string) {
	r := &Received{Sid: sid}
	switch kind {
	case "all":
		r.KEs = make([]*wire.MsgMixKeyExchange, 0, 8)
		r.CTs = make([]*wire.MsgMixCiphertexts, 0, 8)
		r.SRs = make([]*wire.MsgMixSlotReserve, 0, 8)
		r.DCs = make([]*wire.MsgMixDCNet, 0, 8)
		r.CMs = make([]*wire.MsgMixConfirm, 0, 8)
		r.FPs = make([]*wire.MsgMixFactoredPoly, 0, 8)
		r.RSs = make([]*wire.MsgMixSecrets, 0, 8)
		r.ReceiveAll = true
	case "kes", "unknown":
		r.KEs = make([]*wire.MsgMixKeyExchange, 0, 8)
	case "rss":
		r.RSs = make([]*wire.MsgMixSecrets, 0, 8)
	case "twocaps":
		r.KEs = make([]*wire.MsgMixKeyExchange, 0, 8)
		r.CTs = make([]*wire.MsgMixCiphertexts, 0, 8)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	code := ""
	if err := g.p.Receive(cancelled, r); err != nil {
		code = errCode(err)
	}
	g.printf("receive %x %s %s\n", sid[:], kind, code)
	hashes := func(n int, get func(i int) chainhash.Hash) string {
		hs := make([]chainhash.Hash, n)
		for i := range hs {
			hs[i] = get(i)
		}
		return hashList(hs)
	}
	g.printf("rcvkes %s\n", hashes(len(r.KEs), func(i int) chainhash.Hash { return r.KEs[i].Hash() }))
	g.printf("rcvcts %s\n", hashes(len(r.CTs), func(i int) chainhash.Hash { return r.CTs[i].Hash() }))
	g.printf("rcvsrs %s\n", hashes(len(r.SRs), func(i int) chainhash.Hash { return r.SRs[i].Hash() }))
	g.printf("rcvdcs %s\n", hashes(len(r.DCs), func(i int) chainhash.Hash { return r.DCs[i].Hash() }))
	g.printf("rcvcms %s\n", hashes(len(r.CMs), func(i int) chainhash.Hash { return r.CMs[i].Hash() }))
	g.printf("rcvfps %s\n", hashes(len(r.FPs), func(i int) chainhash.Hash { return r.FPs[i].Hash() }))
	g.printf("rcvrss %s\n", hashes(len(r.RSs), func(i int) chainhash.Hash { return r.RSs[i].Hash() }))
}

func (g *gen) strikes() string {
	o := g.p.Observer()
	var s []string
	for op, ss := range o.strikes {
		s = append(s, fmt.Sprintf("%s:%d:%d", op.Hash, op.Index, len(ss.strikes)))
	}
	return "strikes " + csv(s)
}

// observer runs two strike rounds over an eight-peer pairing: one session
// completes, and in the other one peer times out before its slot
// reservation in each of two epochs.
func (g *gen) observer() {
	g.scenario("observer", chaincfg.TestNet3Params(), false, 100, 11)
	ep := g.ep

	var prs []*wire.MsgMixPairReq
	for i := byte(0); i < 8; i++ {
		pr := sign(g, 97+i, basePR(97+i, 0xd1+i, 110))
		g.accept(pr)
		prs = append(prs, pr)
	}

	// session runs ids through the session their pair requests form in
	// epoch: key exchanges and ciphertexts from all of them, slot
	// reservations from srs, and, when complete, DC-nets and confirmations
	// from all of them.
	session := func(peers []*wire.MsgMixPairReq, ids []byte, epoch uint64, srs []byte, complete bool) {
		var keHashes []chainhash.Hash
		var sid [32]byte
		for i, id := range ids {
			ke := sign(g, id, keyExchange(id, peers, peers[i], epoch))
			g.accept(ke)
			keHashes = append(keHashes, ke.Hash())
			sid = ke.SessionID
		}
		var ctHashes []chainhash.Hash
		for _, id := range ids {
			ct := sign(g, id, ciphertexts(id, sid, len(ids), keHashes))
			g.accept(ct)
			ctHashes = append(ctHashes, ct.Hash())
		}
		var srHashes []chainhash.Hash
		for _, id := range srs {
			sr := sign(g, id, slotReserve(id, sid, ctHashes))
			g.accept(sr)
			srHashes = append(srHashes, sr.Hash())
		}
		if !complete {
			return
		}
		var dcHashes []chainhash.Hash
		for _, id := range ids {
			dc := sign(g, id, dcNet(id, sid, srHashes))
			g.accept(dc)
			dcHashes = append(dcHashes, dc.Hash())
		}
		tx := mixTx(nil, 0x53)
		for _, id := range ids {
			g.accept(sign(g, id, confirm(id, sid, tx, dcHashes)))
		}
	}

	session(prs[:4], []byte{97, 98, 99, 100}, ep.main, []byte{97, 98, 99, 100}, true)
	session(prs[4:], []byte{101, 102, 103, 104}, ep.main, []byte{101, 102, 103}, false)

	misbehaving := mixTx([]byte{0xd8}, 0x54)
	g.checkPrevEpoch(ep.main)
	g.printf("misbehavingtx %s %v\n", txHex(misbehaving), g.p.Observer().MisbehavingTx(misbehaving))

	session(prs[4:], []byte{101, 102, 103, 104}, ep.second, []byte{101, 102, 103}, false)
	g.checkPrevEpoch(ep.second)
	g.printf("misbehavingtx %s %v\n", txHex(misbehaving), g.p.Observer().MisbehavingTx(misbehaving))

	var given []string
	for _, pr := range prs {
		given = append(given, pr.Hash().String())
	}
	var kept []string
	for _, pr := range g.p.Observer().ExcludePRs(prs) {
		kept = append(kept, pr.Hash().String())
	}
	g.printf("excludeprs %s %s\n", strings.Join(given, ","), csv(kept))
	g.printf("removespentprs %s\n", txHex(misbehaving))
	g.p.RemoveSpentPRs([]*wire.MsgTx{misbehaving})
	g.state()
	g.printf("%s\n", g.strikes())
}

func (g *gen) checkPrevEpoch(epoch uint64) {
	g.printf("checkprevepoch %d\n", epoch)
	if err := g.p.Observer().CheckPrevEpoch(epoch); err != nil {
		g.t.Fatal(err)
	}
	g.printf("%s\n", g.strikes())
}

// keyExchangeRules runs the key exchange rules dcrd added after 6f6cf21b:
// the late gate and the minute rule (3ce5cc41, 874f6772), one key exchange
// per identity and session (ffb42adf) with its plain error for a session
// that records a removed message, and seen lists past mixing.MaxPeers
// (6b65e0d1).
func (g *gen) keyExchangeRules() {
	g.scenario("kerules", chaincfg.TestNet3Params(), false, 100, 13)
	ep := g.ep

	pr := sign(g, 113, basePR(113, 0xe1, 110))
	g.accept(pr)
	prs := []*wire.MsgMixPairReq{pr}

	// A minute before the earliest epoch the late gate accepts, an epoch
	// whose int64 reading is in the far past, and an epoch inside the
	// window that is not a whole minute.
	g.accept(sign(g, 113, keyExchange(113, prs, pr, ep.main-60)))
	g.accept(sign(g, 113, keyExchange(113, prs, pr, 1<<63+4e9)))
	g.accept(sign(g, 113, keyExchange(113, prs, pr, ep.main+30)))

	// A second key exchange by the identity in its session.
	ke := sign(g, 113, keyExchange(113, prs, pr, ep.main))
	g.accept(ke)
	second := keyExchange(113, prs, pr, ep.main)
	second.Commitment[0] = 1
	g.accept(sign(g, 113, second))

	// The session still records the removed key exchange.
	g.printf("removemessage %s\n", ke.Hash())
	g.p.RemoveMessage(ke)
	g.state()
	third := keyExchange(113, prs, pr, ep.main)
	third.Commitment[0] = 2
	g.accept(sign(g, 113, third))

	// Sixty-five seen pair requests: the identity's own and 64 the pool
	// does not know.
	pr114 := sign(g, 114, basePR(114, 0xe2, 110))
	g.accept(pr114)
	seen := []*wire.MsgMixPairReq{pr114}
	for i := uint32(0); i < 64; i++ {
		seen = append(seen, unknownPR(i))
	}
	g.accept(sign(g, 114, keyExchange(114, seen, pr114, ep.main)))
}
