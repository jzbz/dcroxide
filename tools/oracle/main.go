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
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/crypto/blake256"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
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

	default:
		return errResp("unknown cmd: %s", req.Cmd)
	}
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
