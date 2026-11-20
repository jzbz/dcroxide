// Copyright (c) 2026 The dcroxide developers
// Use of this source code is governed by an ISC license that can be found in
// the LICENSE file.

package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/decred/base58"
)

// base58Detail decodes a base58_bench answer's detail, failing the test on
// an error answer.
func base58Detail(t *testing.T, resp response) (int, string) {
	t.Helper()
	if resp.Error != "" {
		t.Fatalf("base58_bench: %s", resp.Error)
	}
	var detail struct {
		NS     int64  `json:"ns"`
		Cases  int    `json:"cases"`
		Digest string `json:"digest"`
	}
	if err := json.Unmarshal(resp.Detail, &detail); err != nil {
		t.Fatalf("detail %s: %v", resp.Detail, err)
	}
	return detail.Cases, detail.Digest
}

// base58Request is a base58_bench request's data for op over the strings.
func base58Request(op string, cases ...string) []byte {
	data := append([]byte{byte(len(op))}, op...)
	for _, c := range cases {
		data = appendLenPrefixed(data, []byte(c))
	}
	return data
}

// digestHex is the hex of the big-endian FNV-1a 64 of b.
func digestHex(b []byte) string {
	var sum [8]byte
	binary.BigEndian.PutUint64(sum[:], fnv1a64(b))
	return hex.EncodeToString(sum[:])
}

// TestBase58BenchDigests checks every op on fixed strings: the digest is the
// FNV-1a of the serialization of what the oracle's per-string base58
// commands answer, and the case count is the number of strings sent.
func TestBase58BenchDigests(t *testing.T) {
	valid := []string{
		base58.CheckEncode(make([]byte, 20), [2]byte{0x07, 0x3f}),
		base58.CheckEncode([]byte("test payload"), [2]byte{0x22, 0xde}),
		base58.CheckEncode(nil, [2]byte{0, 0}),
	}
	all := append(append([]string{}, valid...), "", "1", "111", "0OIl", "3mJr0",
		"3MNQE1X", valid[0][:len(valid[0])-1]+"2")
	want := map[string]func(s string) []byte{
		"decode": func(s string) []byte {
			return appendLenPrefixed(nil, hexToBytes(call("base58_decode", []byte(s)).Result))
		},
		"check_decode": func(s string) []byte {
			resp := call("base58_check_decode", []byte(s))
			switch resp.Kind {
			case "checksum":
				return []byte{1}
			case "invalid format":
				return []byte{2}
			}
			b := hexToBytes(resp.Result)
			return appendLenPrefixed(append([]byte{0}, b[:2]...), b[2:])
		},
		"encode": func(s string) []byte {
			decoded := hexToBytes(call("base58_decode", []byte(s)).Result)
			return appendLenPrefixed(nil, []byte(call("base58_encode", decoded).Result))
		},
		"check_encode": func(s string) []byte {
			b := hexToBytes(call("base58_check_decode", []byte(s)).Result)
			return appendLenPrefixed(nil, []byte(call("base58_check_encode", b).Result))
		},
	}
	ops := make([]string, 0, len(base58Ops))
	for op := range base58Ops {
		ops = append(ops, op)
	}
	sort.Strings(ops)
	for _, op := range ops {
		expect, ok := want[op]
		if !ok {
			t.Fatalf("op %s has no expected output in this test", op)
		}
		cases := all
		if op == "check_encode" {
			cases = valid
		}
		count, digest := base58Detail(t, call("base58_bench", base58Request(op, cases...)))
		if count != len(cases) {
			t.Errorf("%s: %d cases, want %d", op, count, len(cases))
		}
		var out []byte
		for _, c := range cases {
			out = append(out, expect(c)...)
		}
		if digest != digestHex(out) {
			t.Errorf("%s: digest %s, want %s", op, digest, digestHex(out))
		}
	}

	// No cases is a pass over nothing.
	count, digest := base58Detail(t, call("base58_bench", base58Request("decode")))
	if count != 0 || digest != digestHex(nil) {
		t.Errorf("no cases: %d cases, digest %s", count, digest)
	}
}

// TestBase58BenchRefuses checks the requests base58_bench refuses.
func TestBase58BenchRefuses(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
		want string
	}{
		{"empty", nil, "want name_len"},
		{"short name", []byte{9, 'a'}, "want name_len"},
		{"unknown op", base58Request("nope", "1"), "unknown op"},
		{"short length", append(base58Request("decode"), 0, 0, 1), "truncated length"},
		{"long case", append(base58Request("decode"), 0, 0, 0, 5, 'a'), "5 bytes, 1 left"},
		{"check_encode of a bad string", base58Request("check_encode", "0OIl"), "case 0"},
	} {
		resp := call("base58_bench", tc.data)
		if !strings.Contains(resp.Error, tc.want) {
			t.Errorf("%s: error %q, want it to contain %q", tc.name, resp.Error, tc.want)
		}
	}
}
