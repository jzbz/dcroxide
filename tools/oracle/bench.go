// Copyright (c) 2026 The dcroxide developers
// Use of this source code is governed by an ISC license that can be found in
// the LICENSE file.

// secp_bench: dcrd's side of dcroxide-bench's dcrec micro benchmark. Each
// request times one of dcrd's operations on secrets over every case it
// carries, once, in this process, and answers with the time and a digest of
// the outputs, so the client can set dcrd's time beside its own and check
// that both computed the same bytes.

package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/schnorr"
)

// benchCaseLen is the size of one case: a private key in [1, N-1], a
// 32-byte hash (also Ed25519's message), an HD tweak Il in [1, N-1], an HD
// parent key of any value, and an Ed25519 seed, 32 bytes each, in that
// order.
const benchCaseLen = 5 * 32

// benchCase is one case, as slices of the request's bytes.
type benchCase struct {
	key, hash, tweak, parent, seed []byte
}

// benchOp prepares its inputs from the cases untimed, times the operation
// over every case, and serializes the outputs untimed. It returns the
// elapsed time and the outputs, concatenated in case order.
type benchOp func(cases []benchCase) (time.Duration, []byte, error)

// benchOps are the operations secp_bench times, by the names
// dcroxide-bench sends. Each is the dcrd call a wallet or node makes, as
// tools/oracle's other commands make it.
var benchOps = map[string]benchOp{
	// k*G alone: ScalarBaseMultNonConst, which PubKey and both signers
	// call, into a Jacobian point that is not brought to affine
	// coordinates inside the timing.
	"generator": func(cases []benchCase) (time.Duration, []byte, error) {
		ks := make([]secp256k1.ModNScalar, len(cases))
		for i, c := range cases {
			ks[i].SetByteSlice(c.key)
		}
		points := make([]secp256k1.JacobianPoint, len(cases))
		start := time.Now()
		for i := range ks {
			secp256k1.ScalarBaseMultNonConst(&ks[i], &points[i])
		}
		elapsed := time.Since(start)
		out := make([]byte, 0, len(cases)*33)
		for i := range points {
			points[i].ToAffine()
			pub := secp256k1.NewPublicKey(&points[i].X, &points[i].Y)
			out = append(out, pub.SerializeCompressed()...)
		}
		return elapsed, out, nil
	},
	// PrivateKey.PubKey: k*G and its affine coordinates.
	"public_key": func(cases []benchCase) (time.Duration, []byte, error) {
		keys := make([]*secp256k1.PrivateKey, len(cases))
		for i, c := range cases {
			keys[i] = secp256k1.PrivKeyFromBytes(c.key)
		}
		pubs := make([]*secp256k1.PublicKey, len(cases))
		start := time.Now()
		for i, key := range keys {
			pubs[i] = key.PubKey()
		}
		elapsed := time.Since(start)
		out := make([]byte, 0, len(cases)*33)
		for _, pub := range pubs {
			out = append(out, pub.SerializeCompressed()...)
		}
		return elapsed, out, nil
	},
	// PrivKeyFromBytes on 32 bytes. dcrd reduces the bytes modulo N and
	// checks nothing; dcroxide's PrivateKey::from_bytes refuses zero and N
	// or more. Every case's key is in [1, N-1], where the two agree.
	"key_from_bytes": func(cases []benchCase) (time.Duration, []byte, error) {
		keys := make([]*secp256k1.PrivateKey, len(cases))
		start := time.Now()
		for i, c := range cases {
			keys[i] = secp256k1.PrivKeyFromBytes(c.key)
		}
		elapsed := time.Since(start)
		out := make([]byte, 0, len(cases)*32)
		for _, key := range keys {
			out = append(out, key.Serialize()...)
		}
		return elapsed, out, nil
	},
	// ecdsa.Sign: the RFC 6979 nonce, k*G, and the low-S signature.
	"ecdsa_sign": func(cases []benchCase) (time.Duration, []byte, error) {
		keys := make([]*secp256k1.PrivateKey, len(cases))
		for i, c := range cases {
			keys[i] = secp256k1.PrivKeyFromBytes(c.key)
		}
		sigs := make([]*ecdsa.Signature, len(cases))
		start := time.Now()
		for i, key := range keys {
			sigs[i] = ecdsa.Sign(key, cases[i].hash)
		}
		elapsed := time.Since(start)
		var out []byte
		for _, sig := range sigs {
			out = append(out, sig.Serialize()...)
		}
		return elapsed, out, nil
	},
	// schnorr.Sign: EC-Schnorr-DCRv0 with its RFC 6979 nonce.
	"schnorr_sign": func(cases []benchCase) (time.Duration, []byte, error) {
		keys := make([]*secp256k1.PrivateKey, len(cases))
		for i, c := range cases {
			keys[i] = secp256k1.PrivKeyFromBytes(c.key)
		}
		sigs := make([]*schnorr.Signature, len(cases))
		errs := make([]error, len(cases))
		start := time.Now()
		for i, key := range keys {
			sigs[i], errs[i] = schnorr.Sign(key, cases[i].hash)
		}
		elapsed := time.Since(start)
		out := make([]byte, 0, len(cases)*64)
		for i, sig := range sigs {
			if errs[i] != nil {
				return 0, nil, fmt.Errorf("case %d: %v", i, errs[i])
			}
			out = append(out, sig.Serialize()...)
		}
		return elapsed, out, nil
	},
	// NonceRFC6979 with no extra data or version, as ecdsa.Sign asks for
	// its first candidate.
	"rfc6979_nonce": func(cases []benchCase) (time.Duration, []byte, error) {
		nonces := make([]*secp256k1.ModNScalar, len(cases))
		start := time.Now()
		for i, c := range cases {
			nonces[i] = secp256k1.NonceRFC6979(c.key, c.hash, nil, nil, 0)
		}
		elapsed := time.Since(start)
		out := make([]byte, 0, len(cases)*32)
		for _, nonce := range nonces {
			b := nonce.Bytes()
			out = append(out, b[:]...)
		}
		return elapsed, out, nil
	},
	// hdkeychain's private child sum, composed of the calls it makes, as
	// privkey_tweak_add composes it: Il through SetByteSlice with its
	// overflow and zero checks, the parent through SetByteSlice, then
	// ModNScalar.Add.
	"hd_private_child": func(cases []benchCase) (time.Duration, []byte, error) {
		sums := make([]secp256k1.ModNScalar, len(cases))
		refused := -1
		start := time.Now()
		for i, c := range cases {
			var il, parent secp256k1.ModNScalar
			if overflow := il.SetByteSlice(c.tweak); overflow || il.IsZero() {
				refused = i
			}
			parent.SetByteSlice(c.parent)
			sums[i] = *il.Add(&parent)
		}
		elapsed := time.Since(start)
		if refused >= 0 {
			return 0, nil, fmt.Errorf("case %d: tweak is not in [1, N-1]", refused)
		}
		out := make([]byte, 0, len(cases)*32)
		for i := range sums {
			b := sums[i].Bytes()
			out = append(out, b[:]...)
		}
		return elapsed, out, nil
	},
	// edwards.PrivKeyFromSecret: SHA-512 of the seed, the clamped
	// scalar's multiple of the base point and its encoding.
	"ed25519_public_key": func(cases []benchCase) (time.Duration, []byte, error) {
		pubs := make([]*edwards.PublicKey, len(cases))
		start := time.Now()
		for i, c := range cases {
			_, pubs[i] = edwards.PrivKeyFromSecret(c.seed)
		}
		elapsed := time.Since(start)
		out := make([]byte, 0, len(cases)*32)
		for i, pub := range pubs {
			if pub == nil {
				return 0, nil, fmt.Errorf("case %d: bad secret", i)
			}
			out = append(out, pub.Serialize()...)
		}
		return elapsed, out, nil
	},
	// edwards.Sign over the case's hash as the message, with a key from
	// PrivKeyFromSecret, which carries the public key it computed.
	"ed25519_sign": func(cases []benchCase) (time.Duration, []byte, error) {
		keys := make([]*edwards.PrivateKey, len(cases))
		for i, c := range cases {
			keys[i], _ = edwards.PrivKeyFromSecret(c.seed)
			if keys[i] == nil {
				return 0, nil, fmt.Errorf("case %d: bad secret", i)
			}
		}
		sigs := make([]*edwards.Signature, len(cases))
		errs := make([]error, len(cases))
		start := time.Now()
		for i, key := range keys {
			r, s, err := edwards.Sign(key, cases[i].hash)
			sigs[i], errs[i] = edwards.NewSignature(r, s), err
		}
		elapsed := time.Since(start)
		out := make([]byte, 0, len(cases)*64)
		for i, sig := range sigs {
			if errs[i] != nil {
				return 0, nil, fmt.Errorf("case %d: %v", i, errs[i])
			}
			out = append(out, sig.Serialize()...)
		}
		return elapsed, out, nil
	},
}

// fnv1a64 is the 64-bit FNV-1a hash of b, the digest dcroxide-bench folds
// its own outputs into.
func fnv1a64(b []byte) uint64 {
	h := uint64(0xcbf29ce484222325)
	for _, c := range b {
		h ^= uint64(c)
		h *= 0x100000001b3
	}
	return h
}

// secpBench answers secp_bench: data is name_len(1) || op name || one or
// more 160-byte cases.
func secpBench(data []byte) response {
	if len(data) < 1 || len(data) < 1+int(data[0]) {
		return errResp("secp_bench: want name_len(1) || op name || cases, got %d bytes", len(data))
	}
	name := string(data[1 : 1+int(data[0])])
	raw := data[1+int(data[0]):]
	op, ok := benchOps[name]
	if !ok {
		return errResp("secp_bench: unknown op %q", name)
	}
	if len(raw) == 0 || len(raw)%benchCaseLen != 0 {
		return errResp("secp_bench: want a whole number of %d-byte cases, got %d bytes",
			benchCaseLen, len(raw))
	}
	cases := make([]benchCase, len(raw)/benchCaseLen)
	for i := range cases {
		c := raw[i*benchCaseLen : (i+1)*benchCaseLen]
		cases[i] = benchCase{key: c[0:32], hash: c[32:64], tweak: c[64:96],
			parent: c[96:128], seed: c[128:160]}
	}
	elapsed, out, err := op(cases)
	if err != nil {
		return errResp("secp_bench: %s: %v", name, err)
	}
	var digest [8]byte
	binary.BigEndian.PutUint64(digest[:], fnv1a64(out))
	detail, err := json.Marshal(struct {
		NS     int64  `json:"ns"`
		Digest string `json:"digest"`
	}{elapsed.Nanoseconds(), hex.EncodeToString(digest[:])})
	if err != nil {
		return errResp("secp_bench: %v", err)
	}
	return response{Detail: detail}
}
