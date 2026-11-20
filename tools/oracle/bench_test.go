// Copyright (c) 2026 The dcroxide developers
// Use of this source code is governed by an ISC license that can be found in
// the LICENSE file.

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"testing"
)

// benchDetail decodes a secp_bench answer's detail, failing the test on an
// error answer.
func benchDetail(t *testing.T, resp response) (int64, string) {
	t.Helper()
	if resp.Error != "" {
		t.Fatalf("secp_bench: %s", resp.Error)
	}
	var detail struct {
		NS     int64  `json:"ns"`
		Digest string `json:"digest"`
	}
	if err := json.Unmarshal(resp.Detail, &detail); err != nil {
		t.Fatalf("detail %s: %v", resp.Detail, err)
	}
	return detail.NS, detail.Digest
}

// benchRequest is a secp_bench request's data for op over the cases.
func benchRequest(op string, cases ...[]byte) []byte {
	return append(append([]byte{byte(len(op))}, op...), bytes.Join(cases, nil)...)
}

// oneCase is a case whose every field is the 32-byte big-endian value v.
func oneCase(v byte) []byte {
	field := make([]byte, 32)
	field[31] = v
	return bytes.Repeat(field, 5)
}

// TestSecpBenchDigests checks every op on fixed cases: the digest is the
// FNV-1a of the outputs dcrd's own calls give, through the oracle's other
// commands, and the same on a second run.
func TestSecpBenchDigests(t *testing.T) {
	cases := [][]byte{oneCase(1), oneCase(2), oneCase(0x7f)}
	// The outputs each op must give, from the commands that already answer
	// for those calls.
	want := map[string]func(c []byte) []byte{
		"generator":  func(c []byte) []byte { return hexToBytes(call("privkey_from_bytes", c[:32]).Compressed) },
		"public_key": func(c []byte) []byte { return hexToBytes(call("privkey_from_bytes", c[:32]).Compressed) },
		"key_from_bytes": func(c []byte) []byte {
			return hexToBytes(call("privkey_from_bytes", c[:32]).Result)
		},
		"ecdsa_sign":   func(c []byte) []byte { return hexToBytes(call("ecdsa_sign", c[:64]).Result) },
		"schnorr_sign": func(c []byte) []byte { return hexToBytes(call("schnorr_sign", c[:64]).Result) },
		"rfc6979_nonce": func(c []byte) []byte {
			// The nonce is the private key of the signature's R, which
			// nothing else answers for; it is checked against dcrd's own
			// vector below instead.
			return nil
		},
		"hd_private_child": func(c []byte) []byte {
			return hexToBytes(call("privkey_tweak_add", c[64:96], c[96:128]).Result)
		},
		"ed25519_public_key": func(c []byte) []byte {
			return hexToBytes(call("ed25519_sign", c[128:160], c[32:64]).Compressed)
		},
		"ed25519_sign": func(c []byte) []byte {
			return hexToBytes(call("ed25519_sign", c[128:160], c[32:64]).Result)
		},
	}
	ops := make([]string, 0, len(benchOps))
	for op := range benchOps {
		ops = append(ops, op)
	}
	sort.Strings(ops)
	for _, op := range ops {
		expect, ok := want[op]
		if !ok {
			t.Fatalf("op %s has no expected output in this test", op)
		}
		_, digest := benchDetail(t, call("secp_bench", benchRequest(op, cases...)))
		_, again := benchDetail(t, call("secp_bench", benchRequest(op, cases...)))
		if digest != again {
			t.Errorf("%s: digest %s, then %s", op, digest, again)
		}
		if op == "rfc6979_nonce" {
			continue
		}
		var out []byte
		for _, c := range cases {
			out = append(out, expect(c)...)
		}
		var sum [8]byte
		binary.BigEndian.PutUint64(sum[:], fnv1a64(out))
		if digest != hex.EncodeToString(sum[:]) {
			t.Errorf("%s: digest %s, want %x", op, digest, sum)
		}
	}
}

// TestSecpBenchNonce checks rfc6979_nonce against the first vector of
// dcrd's TestNonceRFC6979 (nonce_test.go): a 32-byte key and hash, no
// extra data, no version, the first candidate.
func TestSecpBenchNonce(t *testing.T) {
	c := oneCase(1)
	copy(c[:32], hexToBytes("0011111111111111111111111111111111111111111111111111111111111111"))
	nonce := hexToBytes("154e92760f77ad9af6b547edd6f14ad0fae023eb2221bc8be2911675d8a686a3")
	_, digest := benchDetail(t, call("secp_bench", benchRequest("rfc6979_nonce", c)))
	var sum [8]byte
	binary.BigEndian.PutUint64(sum[:], fnv1a64(nonce))
	if digest != hex.EncodeToString(sum[:]) {
		t.Errorf("digest %s, want %x", digest, sum)
	}
}

// TestSecpBenchFNV checks fnv1a64 against the published FNV-1a test values.
func TestSecpBenchFNV(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want uint64
	}{
		{"", 0xcbf29ce484222325},
		{"a", 0xaf63dc4c8601ec8c},
		{"foobar", 0x85944171f73967e8},
	} {
		if got := fnv1a64([]byte(tc.in)); got != tc.want {
			t.Errorf("fnv1a64(%q) = %#x, want %#x", tc.in, got, tc.want)
		}
	}
}

// TestSecpBenchRefuses checks the requests secp_bench refuses.
func TestSecpBenchRefuses(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
		want string
	}{
		{"empty", nil, "want name_len"},
		{"short name", []byte{9, 'a'}, "want name_len"},
		{"unknown op", benchRequest("nope", oneCase(1)), "unknown op"},
		{"no cases", benchRequest("public_key"), "whole number"},
		{"partial case", benchRequest("public_key", oneCase(1)[:159]), "whole number"},
		{"zero tweak", benchRequest("hd_private_child", bytes.Repeat([]byte{0}, 160)), "tweak"},
	} {
		resp := call("secp_bench", tc.data)
		if !strings.Contains(resp.Error, tc.want) {
			t.Errorf("%s: error %q, want it to contain %q", tc.name, resp.Error, tc.want)
		}
	}
}
