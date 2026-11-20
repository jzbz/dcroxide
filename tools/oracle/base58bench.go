// Copyright (c) 2026 The dcroxide developers
// Use of this source code is governed by an ISC license that can be found in
// the LICENSE file.

// base58_bench: dcrd's side of dcroxide-bench's base58 micro benchmark, and
// a batch differential for dcroxide-base58's tests. Each request times one
// of decred/base58's four functions over every string it carries, once, in
// this process, and answers with the time and a digest of the outputs, so
// the client can set Go's time beside its own and check that both computed
// the same bytes.

package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/decred/base58"
)

// base58Op prepares its inputs from the strings untimed, times the function
// over every case, and serializes the outputs untimed. It returns the
// elapsed time and the outputs, concatenated in case order.
type base58Op func(cases []string) (time.Duration, []byte, error)

// appendLenPrefixed appends len(b) as 4 big-endian bytes and then b.
func appendLenPrefixed(out, b []byte) []byte {
	out = binary.BigEndian.AppendUint32(out, uint32(len(b)))
	return append(out, b...)
}

// base58CheckKind is the byte a check_decode output starts with: 0 for a
// decoded string, 1 for ErrChecksum, 2 for ErrInvalidFormat.
func base58CheckKind(err error) byte {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, base58.ErrChecksum):
		return 1
	default:
		return 2
	}
}

// base58Ops are the functions base58_bench times, by the names
// dcroxide-bench sends. The serialization of each output is the one
// crates/dcroxide-bench/src/base58.rs and dcroxide-base58's batch
// differential write.
var base58Ops = map[string]base58Op{
	// Decode: length(4 BE) || bytes, empty for an invalid string.
	"decode": func(cases []string) (time.Duration, []byte, error) {
		outs := make([][]byte, len(cases))
		start := time.Now()
		for i, s := range cases {
			outs[i] = base58.Decode(s)
		}
		elapsed := time.Since(start)
		var out []byte
		for _, o := range outs {
			out = appendLenPrefixed(out, o)
		}
		return elapsed, out, nil
	},
	// CheckDecode: kind(1), then for a decoded string version(2) ||
	// length(4 BE) || payload.
	"check_decode": func(cases []string) (time.Duration, []byte, error) {
		payloads := make([][]byte, len(cases))
		versions := make([][2]byte, len(cases))
		errs := make([]error, len(cases))
		start := time.Now()
		for i, s := range cases {
			payloads[i], versions[i], errs[i] = base58.CheckDecode(s)
		}
		elapsed := time.Since(start)
		var out []byte
		for i := range cases {
			out = append(out, base58CheckKind(errs[i]))
			if errs[i] == nil {
				out = append(out, versions[i][:]...)
				out = appendLenPrefixed(out, payloads[i])
			}
		}
		return elapsed, out, nil
	},
	// Encode of each string's Decode: length(4 BE) || string.
	"encode": func(cases []string) (time.Duration, []byte, error) {
		inputs := make([][]byte, len(cases))
		for i, s := range cases {
			inputs[i] = base58.Decode(s)
		}
		outs := make([]string, len(cases))
		start := time.Now()
		for i, in := range inputs {
			outs[i] = base58.Encode(in)
		}
		elapsed := time.Since(start)
		var out []byte
		for _, o := range outs {
			out = appendLenPrefixed(out, []byte(o))
		}
		return elapsed, out, nil
	},
	// CheckEncode of each string's CheckDecode: length(4 BE) || string.
	// Every string must check-decode.
	"check_encode": func(cases []string) (time.Duration, []byte, error) {
		payloads := make([][]byte, len(cases))
		versions := make([][2]byte, len(cases))
		for i, s := range cases {
			var err error
			payloads[i], versions[i], err = base58.CheckDecode(s)
			if err != nil {
				return 0, nil, fmt.Errorf("case %d: %v", i, err)
			}
		}
		outs := make([]string, len(cases))
		start := time.Now()
		for i := range payloads {
			outs[i] = base58.CheckEncode(payloads[i], versions[i])
		}
		elapsed := time.Since(start)
		var out []byte
		for _, o := range outs {
			out = appendLenPrefixed(out, []byte(o))
		}
		return elapsed, out, nil
	},
}

// base58Bench answers base58_bench: data is name_len(1) || op name || zero
// or more cases, each length(4 BE) || string bytes.
func base58Bench(data []byte) response {
	if len(data) < 1 || len(data) < 1+int(data[0]) {
		return errResp("base58_bench: want name_len(1) || op name || cases, got %d bytes", len(data))
	}
	name := string(data[1 : 1+int(data[0])])
	raw := data[1+int(data[0]):]
	op, ok := base58Ops[name]
	if !ok {
		return errResp("base58_bench: unknown op %q", name)
	}
	var cases []string
	for len(raw) > 0 {
		if len(raw) < 4 {
			return errResp("base58_bench: truncated length after case %d", len(cases))
		}
		n := binary.BigEndian.Uint32(raw)
		if uint64(n) > uint64(len(raw)-4) {
			return errResp("base58_bench: case %d is %d bytes, %d left", len(cases), n, len(raw)-4)
		}
		cases = append(cases, string(raw[4:4+n]))
		raw = raw[4+n:]
	}
	elapsed, out, err := op(cases)
	if err != nil {
		return errResp("base58_bench: %s: %v", name, err)
	}
	var digest [8]byte
	binary.BigEndian.PutUint64(digest[:], fnv1a64(out))
	detail, err := json.Marshal(struct {
		NS     int64  `json:"ns"`
		Cases  int    `json:"cases"`
		Digest string `json:"digest"`
	}{elapsed.Nanoseconds(), len(cases), hex.EncodeToString(digest[:])})
	if err != nil {
		return errResp("base58_bench: %v", err)
	}
	return response{Detail: detail}
}
