// Copyright (c) 2026 The dcroxide developers
// Use of this source code is governed by an ISC license that can be found in
// the LICENSE file.

// Command dcrd-oracle exposes dcrd's reference implementations over a
// line-delimited JSON protocol on stdin/stdout, for dcroxide's vector
// generation and differential tests.
//
// Every dcrd module dependency in go.mod is pinned to the exact version
// required by dcrd release-v2.1.5 — the project's parity target. Do not bump
// them independently of a parity-target change.
//
// Protocol: one JSON object per line in, one per line out. Every command
// takes a single "data" argument holding hex-encoded bytes; responses carry
// {"error": "..."} on failure or command-specific fields on success:
//
//	blake256           → {"result": "<hex 32-byte digest>"}
//	newhashfromstr     → data is the hex of the string bytes;
//	                     {"result": "<hex 32-byte hash, natural order>"}
//	hash_string        → data is 32 hash bytes; {"result": "<display string>"}
//	msgtx_decode       → {"txid": ..., "witness_hash": ..., "full_hash": ...,
//	                      "reencoded": "<hex>"}
//	blockheader_decode → {"block_hash": ..., "reencoded": "<hex>"}
//	ecdsa_parse_der    → {"result": "<hex 64-byte R||S>"} or
//	                     {"error": ..., "kind": "ErrSig..."}
//	ecdsa_sign         → data is 32-byte privkey || 32-byte hash;
//	                     {"result": "<hex DER signature>"}
//	ecdsa_verify       → data is 33-byte compressed pubkey || 32-byte hash ||
//	                     DER signature; {"result": "true"|"false"}
//	pubkey_parse       → {"result": "<hex uncompressed>",
//	                      "compressed": "<hex compressed>"} or
//	                     {"error": ..., "kind": "ErrPubKey..."}
//	schnorr_parse      → {"result": "<hex 64-byte r||s>"} or
//	                     {"error": ..., "kind": "ErrSig..."}
//	schnorr_sign       → data is 32-byte privkey || 32-byte hash;
//	                     {"result": "<hex 64-byte signature>"}
//	schnorr_verify     → data is 33-byte compressed pubkey || 32-byte hash ||
//	                     64-byte signature; {"result": "true"|"false"}
//	schnorr_pubkey_parse → {"result": "<hex compressed>"} or {"error": ...}
//	ed25519_pubkey_parse → {"result": "<hex canonical 32 bytes>"} or
//	                       {"error": ...}
//	ed25519_parse      → {"result": "<hex 64-byte R||S>"} or {"error": ...}
//	ed25519_sign       → data is 32-byte seed || message;
//	                     {"result": "<hex 64-byte sig>",
//	                      "compressed": "<hex pubkey>"}
//	ed25519_verify     → data is 32-byte pubkey || 64-byte raw sig || message;
//	                     R/S are taken raw (no ParseSignature) to expose the
//	                     verify-layer semantics; {"result": "true"|"false"}
//	uint256_op         → data is op(1) || a(32 BE) || b(32 BE) || aux(8 BE);
//	                     {"result": "<hex 32-byte BE>"} for value ops or the
//	                     plain string for bitlen/cmp/text ops (see handler)
//	wire_msg           → data is pver(4 BE) || magic(4 BE) || framed message;
//	                     {"result": "<hex re-encoded frame>",
//	                      "compressed": "<command>"} or
//	                     {"error": ..., "kind": "Err..." when a wire
//	                      MessageError}
//	chaincfg_dump      → data is the network name bytes ("mainnet",
//	                     "testnet3", "simnet", or "regnet");
//	                     {"result": "<hex of the canonical params dump>"}
//	                     (line format defined by dumpParams below, mirrored
//	                     byte-for-byte by dcroxide's Params::dump)
package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"math/big"

	"github.com/decred/dcrd/chaincfg/chainhash"
	chaincfg "github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/crypto/blake256"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/math/uint256"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/schnorr"
	"github.com/decred/dcrd/wire"
)

type request struct {
	Cmd  string `json:"cmd"`
	Data string `json:"data,omitempty"`
}

type response struct {
	Result      string `json:"result,omitempty"`
	Error       string `json:"error,omitempty"`
	Kind        string `json:"kind,omitempty"`
	Compressed  string `json:"compressed,omitempty"`
	TxID        string `json:"txid,omitempty"`
	WitnessHash string `json:"witness_hash,omitempty"`
	FullHash    string `json:"full_hash,omitempty"`
	BlockHash   string `json:"block_hash,omitempty"`
	Reencoded   string `json:"reencoded,omitempty"`
}

func errResp(format string, args ...any) response {
	return response{Error: fmt.Sprintf(format, args...)}
}

// littleEndianToBigInt interprets 32 little-endian bytes as a big integer,
// like the edwards package's unexported encodedBytesToBigInt.
func littleEndianToBigInt(le []byte) *big.Int {
	be := make([]byte, len(le))
	for i, b := range le {
		be[len(le)-1-i] = b
	}
	return new(big.Int).SetBytes(be)
}

// errKindResp builds an error response carrying the dcrd error kind name
// (e.g. "ErrSigTooShort") when the error wraps a known kind type.
func errKindResp(err error) response {
	resp := response{Error: err.Error()}
	var sigErr ecdsa.Error
	if errors.As(err, &sigErr) {
		resp.Kind = sigErr.Err.Error()
		return resp
	}
	var keyErr secp256k1.Error
	if errors.As(err, &keyErr) {
		resp.Kind = keyErr.Err.Error()
		return resp
	}
	var schnorrErr schnorr.Error
	if errors.As(err, &schnorrErr) {
		resp.Kind = schnorrErr.Err.Error()
		return resp
	}
	var wireErr *wire.MessageError
	if errors.As(err, &wireErr) {
		resp.Kind = wireErr.ErrorCode.String()
	}
	return resp
}

func handle(req request) response {
	data, err := hex.DecodeString(req.Data)
	if err != nil {
		return errResp("%s: bad hex argument: %v", req.Cmd, err)
	}

	switch req.Cmd {
	case "blake256":
		digest := blake256.Sum256(data)
		return response{Result: hex.EncodeToString(digest[:])}

	case "newhashfromstr":
		hash, err := chainhash.NewHashFromStr(string(data))
		if err != nil {
			return errResp("%v", err)
		}
		return response{Result: hex.EncodeToString(hash[:])}

	case "hash_string":
		var hash chainhash.Hash
		if err := hash.SetBytes(data); err != nil {
			return errResp("%v", err)
		}
		return response{Result: hash.String()}

	case "msgtx_decode":
		var tx wire.MsgTx
		if err := tx.FromBytes(data); err != nil {
			return errResp("%v", err)
		}
		reencoded, err := tx.Bytes()
		if err != nil {
			return errResp("re-encode: %v", err)
		}
		txid := tx.TxHash()
		witnessHash := tx.TxHashWitness()
		fullHash := tx.TxHashFull()
		return response{
			TxID:        txid.String(),
			WitnessHash: witnessHash.String(),
			FullHash:    fullHash.String(),
			Reencoded:   hex.EncodeToString(reencoded),
		}

	case "blockheader_decode":
		var h wire.BlockHeader
		if err := h.FromBytes(data); err != nil {
			return errResp("%v", err)
		}
		reencoded, err := h.Bytes()
		if err != nil {
			return errResp("re-encode: %v", err)
		}
		blockHash := h.BlockHash()
		return response{
			BlockHash: blockHash.String(),
			Reencoded: hex.EncodeToString(reencoded),
		}

	case "ecdsa_parse_der":
		sig, err := ecdsa.ParseDERSignature(data)
		if err != nil {
			return errKindResp(err)
		}
		r, s := sig.R(), sig.S()
		var buf [64]byte
		r.PutBytesUnchecked(buf[:32])
		s.PutBytesUnchecked(buf[32:])
		return response{Result: hex.EncodeToString(buf[:])}

	case "ecdsa_sign":
		if len(data) != 64 {
			return errResp("ecdsa_sign: want 64 bytes (privkey || hash), got %d",
				len(data))
		}
		privKey := secp256k1.PrivKeyFromBytes(data[:32])
		sig := ecdsa.Sign(privKey, data[32:])
		return response{Result: hex.EncodeToString(sig.Serialize())}

	case "ecdsa_verify":
		if len(data) < 33+32 {
			return errResp("ecdsa_verify: want >= 65 bytes, got %d", len(data))
		}
		pubKey, err := secp256k1.ParsePubKey(data[:33])
		if err != nil {
			return errKindResp(err)
		}
		hash := data[33 : 33+32]
		sig, err := ecdsa.ParseDERSignature(data[33+32:])
		if err != nil {
			return errKindResp(err)
		}
		if sig.Verify(hash, pubKey) {
			return response{Result: "true"}
		}
		return response{Result: "false"}

	case "pubkey_parse":
		pubKey, err := secp256k1.ParsePubKey(data)
		if err != nil {
			return errKindResp(err)
		}
		return response{
			Result:     hex.EncodeToString(pubKey.SerializeUncompressed()),
			Compressed: hex.EncodeToString(pubKey.SerializeCompressed()),
		}

	case "schnorr_parse":
		sig, err := schnorr.ParseSignature(data)
		if err != nil {
			return errKindResp(err)
		}
		return response{Result: hex.EncodeToString(sig.Serialize())}

	case "schnorr_sign":
		if len(data) != 64 {
			return errResp("schnorr_sign: want 64 bytes (privkey || hash), got %d",
				len(data))
		}
		privKey := secp256k1.PrivKeyFromBytes(data[:32])
		sig, err := schnorr.Sign(privKey, data[32:])
		if err != nil {
			return errKindResp(err)
		}
		return response{Result: hex.EncodeToString(sig.Serialize())}

	case "schnorr_verify":
		if len(data) != 33+32+64 {
			return errResp("schnorr_verify: want 129 bytes, got %d", len(data))
		}
		pubKey, err := secp256k1.ParsePubKey(data[:33])
		if err != nil {
			return errKindResp(err)
		}
		sig, err := schnorr.ParseSignature(data[33+32:])
		if err != nil {
			return errKindResp(err)
		}
		if sig.Verify(data[33:33+32], pubKey) {
			return response{Result: "true"}
		}
		return response{Result: "false"}

	case "schnorr_pubkey_parse":
		pubKey, err := schnorr.ParsePubKey(data)
		if err != nil {
			return errKindResp(err)
		}
		return response{Result: hex.EncodeToString(pubKey.SerializeCompressed())}

	case "ed25519_pubkey_parse":
		pubKey, err := edwards.ParsePubKey(data)
		if err != nil {
			return errResp("%v", err)
		}
		return response{Result: hex.EncodeToString(pubKey.Serialize())}

	case "ed25519_parse":
		sig, err := edwards.ParseSignature(data)
		if err != nil {
			return errResp("%v", err)
		}
		return response{Result: hex.EncodeToString(sig.Serialize())}

	case "ed25519_sign":
		if len(data) < 32 {
			return errResp("ed25519_sign: want >= 32 bytes (seed || msg), got %d",
				len(data))
		}
		privKey, pubKey := edwards.PrivKeyFromSecret(data[:32])
		if privKey == nil {
			return errResp("ed25519_sign: bad secret")
		}
		r, s, err := edwards.Sign(privKey, data[32:])
		if err != nil {
			return errResp("%v", err)
		}
		sig := edwards.NewSignature(r, s)
		return response{
			Result:     hex.EncodeToString(sig.Serialize()),
			Compressed: hex.EncodeToString(pubKey.Serialize()),
		}

	case "ed25519_verify":
		if len(data) < 32+64 {
			return errResp("ed25519_verify: want >= 96 bytes, got %d", len(data))
		}
		pubKey, err := edwards.ParsePubKey(data[:32])
		if err != nil {
			return errResp("%v", err)
		}
		// R and S are taken from the raw bytes without ParseSignature,
		// exposing the verify-layer (agl) semantics for differential
		// testing; consensus always parses first.
		r := littleEndianToBigInt(data[32 : 32+32])
		s := littleEndianToBigInt(data[64 : 64+32])
		if edwards.Verify(pubKey, data[96:], r, s) {
			return response{Result: "true"}
		}
		return response{Result: "false"}

	case "uint256_op":
		if len(data) != 1+32+32+8 {
			return errResp("uint256_op: want 73 bytes, got %d", len(data))
		}
		op := data[0]
		var aBytes, bBytes [32]byte
		copy(aBytes[:], data[1:33])
		copy(bBytes[:], data[33:65])
		a := new(uint256.Uint256).SetBytes(&aBytes)
		b := new(uint256.Uint256).SetBytes(&bBytes)
		var aux uint64
		for _, by := range data[65:73] {
			aux = aux<<8 | uint64(by)
		}

		hexResult := func(n *uint256.Uint256) response {
			nb := n.Bytes()
			return response{Result: hex.EncodeToString(nb[:])}
		}
		switch op {
		case 0:
			return hexResult(a.Add(b))
		case 1:
			return hexResult(a.Sub(b))
		case 2:
			return hexResult(a.Mul(b))
		case 3:
			if b.IsZero() {
				return errResp("uint256_op: division by zero")
			}
			return hexResult(a.Div(b))
		case 4:
			return hexResult(a.Square())
		case 5:
			return hexResult(a.Negate())
		case 6:
			return hexResult(a.Not())
		case 7:
			return hexResult(a.And(b))
		case 8:
			return hexResult(a.Or(b))
		case 9:
			return hexResult(a.Xor(b))
		case 10:
			return hexResult(a.Lsh(uint32(aux)))
		case 11:
			return hexResult(a.Rsh(uint32(aux)))
		case 12:
			return response{Result: fmt.Sprintf("%d", a.BitLen())}
		case 13:
			return response{Result: fmt.Sprintf("%d", a.Cmp(b))}
		case 14:
			return response{Result: a.Text(uint256.OutputBaseBinary)}
		case 15:
			return response{Result: a.Text(uint256.OutputBaseOctal)}
		case 16:
			return response{Result: a.Text(uint256.OutputBaseDecimal)}
		case 17:
			return response{Result: a.Text(uint256.OutputBaseHex)}
		case 18:
			return hexResult(a.AddUint64(aux))
		case 19:
			return hexResult(a.SubUint64(aux))
		case 20:
			return hexResult(a.MulUint64(aux))
		case 21:
			if aux == 0 {
				return errResp("uint256_op: division by zero")
			}
			return hexResult(a.DivUint64(aux))
		default:
			return errResp("uint256_op: unknown op %d", op)
		}

	case "wire_msg":
		if len(data) < 8 {
			return errResp("wire_msg: want >= 8 bytes, got %d", len(data))
		}
		pver := binary.BigEndian.Uint32(data[0:4])
		net := wire.CurrencyNet(binary.BigEndian.Uint32(data[4:8]))
		msg, _, err := wire.ReadMessage(bytes.NewReader(data[8:]), pver, net)
		if err != nil {
			return errKindResp(err)
		}
		var buf bytes.Buffer
		if err := wire.WriteMessage(&buf, msg, pver, net); err != nil {
			return errKindResp(err)
		}
		return response{
			Result:     hex.EncodeToString(buf.Bytes()),
			Compressed: msg.Command(),
		}

	case "chaincfg_dump":
		var params *chaincfg.Params
		switch string(data) {
		case "mainnet":
			params = chaincfg.MainNetParams()
		case "testnet3":
			params = chaincfg.TestNet3Params()
		case "simnet":
			params = chaincfg.SimNetParams()
		case "regnet":
			params = chaincfg.RegNetParams()
		default:
			return errResp("chaincfg_dump: unknown network %q", string(data))
		}
		dump, err := dumpParams(params)
		if err != nil {
			return errResp("chaincfg_dump: %v", err)
		}
		return response{Result: hex.EncodeToString([]byte(dump))}

	default:
		return errResp("unknown cmd: %s", req.Cmd)
	}
}

// dumpParams renders every network parameter as canonical line-oriented
// text. The format must stay byte-identical to dcroxide's Params::dump —
// that equality across all four networks is the chaincfg parity test.
func dumpParams(p *chaincfg.Params) (string, error) {
	var w strings.Builder
	fmt.Fprintf(&w, "name=%s\n", p.Name)
	fmt.Fprintf(&w, "net=0x%08x\n", uint32(p.Net))
	fmt.Fprintf(&w, "defaultport=%s\n", p.DefaultPort)
	for _, seed := range p.DNSSeeds {
		fmt.Fprintf(&w, "dnsseed=%s %t\n", seed.Host, seed.HasFiltering)
	}
	for _, seeder := range p.Seeders() {
		fmt.Fprintf(&w, "seeder=%s\n", seeder)
	}
	fmt.Fprintf(&w, "genesishash=%s\n", p.GenesisHash.String())
	blockBytes, err := p.GenesisBlock.Bytes()
	if err != nil {
		return "", fmt.Errorf("serialize genesis block: %w", err)
	}
	fmt.Fprintf(&w, "genesisblock=%s\n", hex.EncodeToString(blockBytes))
	fmt.Fprintf(&w, "powlimit=%064x\n", p.PowLimit)
	fmt.Fprintf(&w, "powlimitbits=0x%08x\n", p.PowLimitBits)
	fmt.Fprintf(&w, "reducemindifficulty=%t\n", p.ReduceMinDifficulty)
	fmt.Fprintf(&w, "mindiffreductiontime=%d\n", int64(p.MinDiffReductionTime/time.Second))
	fmt.Fprintf(&w, "generatesupported=%t\n", p.GenerateSupported)
	sizes := make([]string, 0, len(p.MaximumBlockSizes))
	for _, s := range p.MaximumBlockSizes {
		sizes = append(sizes, strconv.Itoa(s))
	}
	fmt.Fprintf(&w, "maximumblocksizes=%s\n", strings.Join(sizes, ","))
	fmt.Fprintf(&w, "maxtxsize=%d\n", p.MaxTxSize)
	fmt.Fprintf(&w, "targettimeperblock=%d\n", int64(p.TargetTimePerBlock/time.Second))
	fmt.Fprintf(&w, "workdiffalpha=%d\n", p.WorkDiffAlpha)
	fmt.Fprintf(&w, "workdiffwindowsize=%d\n", p.WorkDiffWindowSize)
	fmt.Fprintf(&w, "workdiffwindows=%d\n", p.WorkDiffWindows)
	fmt.Fprintf(&w, "targettimespan=%d\n", int64(p.TargetTimespan/time.Second))
	fmt.Fprintf(&w, "retargetadjustmentfactor=%d\n", p.RetargetAdjustmentFactor)
	fmt.Fprintf(&w, "workdiffv2blake3startbits=0x%08x\n", p.WorkDiffV2Blake3StartBits)
	fmt.Fprintf(&w, "workdiffv2halflifesecs=%d\n", p.WorkDiffV2HalfLifeSecs)
	fmt.Fprintf(&w, "basesubsidy=%d\n", p.BaseSubsidy)
	fmt.Fprintf(&w, "mulsubsidy=%d\n", p.MulSubsidy)
	fmt.Fprintf(&w, "divsubsidy=%d\n", p.DivSubsidy)
	fmt.Fprintf(&w, "subsidyreductioninterval=%d\n", p.SubsidyReductionInterval)
	fmt.Fprintf(&w, "workrewardproportion=%d\n", p.WorkRewardProportion)
	fmt.Fprintf(&w, "workrewardproportionv2=%d\n", p.WorkRewardProportionV2)
	fmt.Fprintf(&w, "stakerewardproportion=%d\n", p.StakeRewardProportion)
	fmt.Fprintf(&w, "stakerewardproportionv2=%d\n", p.StakeRewardProportionV2)
	fmt.Fprintf(&w, "blocktaxproportion=%d\n", p.BlockTaxProportion)
	fmt.Fprintf(&w, "assumevalid=%s\n", p.AssumeValid.String())
	if p.MinKnownChainWork != nil {
		fmt.Fprintf(&w, "minknownchainwork=%064x\n", p.MinKnownChainWork)
	} else {
		fmt.Fprintf(&w, "minknownchainwork=nil\n")
	}
	fmt.Fprintf(&w, "rulechangeactivationquorum=%d\n", p.RuleChangeActivationQuorum)
	fmt.Fprintf(&w, "rulechangeactivationmultiplier=%d\n", p.RuleChangeActivationMultiplier)
	fmt.Fprintf(&w, "rulechangeactivationdivisor=%d\n", p.RuleChangeActivationDivisor)
	fmt.Fprintf(&w, "rulechangeactivationinterval=%d\n", p.RuleChangeActivationInterval)
	versions := make([]uint32, 0, len(p.Deployments))
	for version := range p.Deployments {
		versions = append(versions, version)
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i] < versions[j] })
	for _, version := range versions {
		for _, dep := range p.Deployments[version] {
			fmt.Fprintf(&w,
				"deployment version=%d id=%s mask=0x%04x forced=%s start=%d expire=%d desc=%s\n",
				version, dep.Vote.Id, dep.Vote.Mask, dep.ForcedChoiceID,
				dep.StartTime, dep.ExpireTime, dep.Vote.Description)
			for _, c := range dep.Vote.Choices {
				fmt.Fprintf(&w, "choice id=%s bits=0x%04x abstain=%t no=%t desc=%s\n",
					c.Id, c.Bits, c.IsAbstain, c.IsNo, c.Description)
			}
		}
	}
	fmt.Fprintf(&w, "blockenforcenumrequired=%d\n", p.BlockEnforceNumRequired)
	fmt.Fprintf(&w, "blockrejectnumrequired=%d\n", p.BlockRejectNumRequired)
	fmt.Fprintf(&w, "blockupgradenumtocheck=%d\n", p.BlockUpgradeNumToCheck)
	fmt.Fprintf(&w, "acceptnonstdtxs=%t\n", p.AcceptNonStdTxs)
	fmt.Fprintf(&w, "networkaddressprefix=%s\n", p.NetworkAddressPrefix)
	fmt.Fprintf(&w, "pubkeyaddrid=%s\n", hex.EncodeToString(p.PubKeyAddrID[:]))
	fmt.Fprintf(&w, "pubkeyhashaddrid=%s\n", hex.EncodeToString(p.PubKeyHashAddrID[:]))
	fmt.Fprintf(&w, "pkhedwardsaddrid=%s\n", hex.EncodeToString(p.PKHEdwardsAddrID[:]))
	fmt.Fprintf(&w, "pkhschnorraddrid=%s\n", hex.EncodeToString(p.PKHSchnorrAddrID[:]))
	fmt.Fprintf(&w, "scripthashaddrid=%s\n", hex.EncodeToString(p.ScriptHashAddrID[:]))
	fmt.Fprintf(&w, "privatekeyid=%s\n", hex.EncodeToString(p.PrivateKeyID[:]))
	fmt.Fprintf(&w, "hdprivatekeyid=%s\n", hex.EncodeToString(p.HDPrivateKeyID[:]))
	fmt.Fprintf(&w, "hdpublickeyid=%s\n", hex.EncodeToString(p.HDPublicKeyID[:]))
	fmt.Fprintf(&w, "slip0044cointype=%d\n", p.SLIP0044CoinType)
	fmt.Fprintf(&w, "legacycointype=%d\n", p.LegacyCoinType)
	fmt.Fprintf(&w, "minimumstakediff=%d\n", p.MinimumStakeDiff)
	fmt.Fprintf(&w, "ticketpoolsize=%d\n", p.TicketPoolSize)
	fmt.Fprintf(&w, "ticketsperblock=%d\n", p.TicketsPerBlock)
	fmt.Fprintf(&w, "ticketmaturity=%d\n", p.TicketMaturity)
	fmt.Fprintf(&w, "ticketexpiry=%d\n", p.TicketExpiry)
	fmt.Fprintf(&w, "coinbasematurity=%d\n", p.CoinbaseMaturity)
	fmt.Fprintf(&w, "sstxchangematurity=%d\n", p.SStxChangeMaturity)
	fmt.Fprintf(&w, "ticketpoolsizeweight=%d\n", p.TicketPoolSizeWeight)
	fmt.Fprintf(&w, "stakediffalpha=%d\n", p.StakeDiffAlpha)
	fmt.Fprintf(&w, "stakediffwindowsize=%d\n", p.StakeDiffWindowSize)
	fmt.Fprintf(&w, "stakediffwindows=%d\n", p.StakeDiffWindows)
	fmt.Fprintf(&w, "stakeversioninterval=%d\n", p.StakeVersionInterval)
	fmt.Fprintf(&w, "maxfreshstakeperblock=%d\n", p.MaxFreshStakePerBlock)
	fmt.Fprintf(&w, "stakeenabledheight=%d\n", p.StakeEnabledHeight)
	fmt.Fprintf(&w, "stakevalidationheight=%d\n", p.StakeValidationHeight)
	fmt.Fprintf(&w, "stakebasesigscript=%s\n", hex.EncodeToString(p.StakeBaseSigScript))
	fmt.Fprintf(&w, "stakemajoritymultiplier=%d\n", p.StakeMajorityMultiplier)
	fmt.Fprintf(&w, "stakemajoritydivisor=%d\n", p.StakeMajorityDivisor)
	fmt.Fprintf(&w, "organizationpkscript=%s\n", hex.EncodeToString(p.OrganizationPkScript))
	fmt.Fprintf(&w, "organizationpkscriptversion=%d\n", p.OrganizationPkScriptVersion)
	var ledgerBuf bytes.Buffer
	for _, payout := range p.BlockOneLedger {
		var tmp [8]byte
		binary.LittleEndian.PutUint16(tmp[0:2], payout.ScriptVersion)
		ledgerBuf.Write(tmp[0:2])
		binary.LittleEndian.PutUint32(tmp[0:4], uint32(len(payout.Script)))
		ledgerBuf.Write(tmp[0:4])
		ledgerBuf.Write(payout.Script)
		binary.LittleEndian.PutUint64(tmp[0:8], uint64(payout.Amount))
		ledgerBuf.Write(tmp[0:8])
	}
	ledgerHash := blake256.Sum256(ledgerBuf.Bytes())
	fmt.Fprintf(&w, "blockoneledger count=%d hash=%s\n",
		len(p.BlockOneLedger), hex.EncodeToString(ledgerHash[:]))
	for _, key := range p.PiKeys {
		fmt.Fprintf(&w, "pikey=%s\n", hex.EncodeToString(key))
	}
	fmt.Fprintf(&w, "treasuryvoteinterval=%d\n", p.TreasuryVoteInterval)
	fmt.Fprintf(&w, "treasuryvoteintervalmultiplier=%d\n", p.TreasuryVoteIntervalMultiplier)
	fmt.Fprintf(&w, "treasuryvotequorummultiplier=%d\n", p.TreasuryVoteQuorumMultiplier)
	fmt.Fprintf(&w, "treasuryvotequorumdivisor=%d\n", p.TreasuryVoteQuorumDivisor)
	fmt.Fprintf(&w, "treasuryvoterequiredmultiplier=%d\n", p.TreasuryVoteRequiredMultiplier)
	fmt.Fprintf(&w, "treasuryvoterequireddivisor=%d\n", p.TreasuryVoteRequiredDivisor)
	fmt.Fprintf(&w, "treasuryexpenditurewindow=%d\n", p.TreasuryExpenditureWindow)
	fmt.Fprintf(&w, "treasuryexpenditurepolicy=%d\n", p.TreasuryExpenditurePolicy)
	fmt.Fprintf(&w, "treasuryexpenditurebootstrap=%d\n", p.TreasuryExpenditureBootstrap)
	return w.String(), nil
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	// Allow large inputs (full blocks later): 64 MiB line limit.
	in.Buffer(make([]byte, 0, 64*1024), 64*1024*1024)
	out := bufio.NewWriter(os.Stdout)
	enc := json.NewEncoder(out)

	for in.Scan() {
		line := in.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var req request
		var resp response
		if err := json.Unmarshal(line, &req); err != nil {
			resp = errResp("bad request: %v", err)
		} else {
			resp = handle(req)
		}
		if err := enc.Encode(&resp); err != nil {
			fmt.Fprintf(os.Stderr, "dcrd-oracle: write: %v\n", err)
			os.Exit(1)
		}
		if err := out.Flush(); err != nil {
			fmt.Fprintf(os.Stderr, "dcrd-oracle: flush: %v\n", err)
			os.Exit(1)
		}
	}
	if err := in.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "dcrd-oracle: read: %v\n", err)
		os.Exit(1)
	}
}
