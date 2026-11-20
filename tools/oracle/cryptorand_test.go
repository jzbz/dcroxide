// Copyright (c) 2026 The dcroxide developers
// Use of this source code is governed by an ISC license that can be found in
// the LICENSE file.

package main

import (
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20"
)

// randOps encodes rand_draws operations.
func randOps(seed []byte, ops ...[2]uint64) []byte {
	data := append([]byte(nil), seed...)
	for _, op := range ops {
		data = append(data, byte(op[0]))
		data = binary.BigEndian.AppendUint64(data, op[1])
	}
	return data
}

// TestRandDrawsStream checks that rand_draws runs dcrd's PRNG over the
// ChaCha20 stream of the seed under the all-zero nonce, as dcroxide's
// Prng::from_seed does: a Read of the first 24 bytes and the next draws are
// that keystream, read little-endian.
func TestRandDrawsStream(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	cipher, err := chacha20.NewUnauthenticatedCipher(seed, make([]byte, 12))
	if err != nil {
		t.Fatal(err)
	}
	stream := make([]byte, 36)
	cipher.XORKeyStream(stream, stream)

	resp := randDraws(randOps(seed, [2]uint64{randOpRead, 24},
		[2]uint64{randOpUint32, 0}, [2]uint64{randOpUint64, 0}))
	if resp.Error != "" {
		t.Fatal(resp.Error)
	}
	lines := strings.Split(resp.Result, "\n")
	want := []string{
		hex.EncodeToString(stream[:24]),
		strconv.FormatUint(uint64(binary.LittleEndian.Uint32(stream[24:28])), 10),
		strconv.FormatUint(binary.LittleEndian.Uint64(stream[28:36]), 10),
	}
	if len(lines) != 4 || !strings.HasPrefix(lines[3], "next=") {
		t.Fatalf("got %q", resp.Result)
	}
	for i, w := range want {
		if lines[i] != w {
			t.Errorf("line %d: got %s, want %s", i, lines[i], w)
		}
	}
}

// TestRandDrawsPanics checks that a panicking draw is answered in its line,
// draws nothing, and leaves the following operations their stream.
func TestRandDrawsPanics(t *testing.T) {
	seed := make([]byte, 32)
	a := randDraws(randOps(seed, [2]uint64{randOpInt32N, 0},
		[2]uint64{randOpUint64, 0}))
	b := randDraws(randOps(seed, [2]uint64{randOpUint64, 0}))
	if a.Error != "" || b.Error != "" {
		t.Fatal(a.Error, b.Error)
	}
	al := strings.Split(a.Result, "\n")
	bl := strings.Split(b.Result, "\n")
	if al[0] != "panic: rand: invalid argument to Int32N" {
		t.Errorf("got %q", al[0])
	}
	if al[1] != bl[0] || al[2] != bl[1] {
		t.Errorf("the panic moved the stream: %q, %q", a.Result, b.Result)
	}
}

// TestRandDrawsRefusals checks the request checks.
func TestRandDrawsRefusals(t *testing.T) {
	for name, data := range map[string][]byte{
		"short seed":     make([]byte, 31),
		"partial op":     make([]byte, 33),
		"oversized read": randOps(make([]byte, 32), [2]uint64{randOpRead, maxRandRead + 1}),
	} {
		resp := randDraws(data)
		if name == "oversized read" {
			if !strings.HasPrefix(resp.Result, "error: ") {
				t.Errorf("%s: got %+v", name, resp)
			}
			continue
		}
		if resp.Error == "" {
			t.Errorf("%s: got %+v, want an error", name, resp)
		}
	}
}

// TestRandDrawsRekey checks that a request is answered exactly while its
// draws, the next= draw included, fit in dcrd's 4 MiB byte budget, and is
// refused once they reach the rekey, which draws kernel entropy and would
// make the answer differ from call to call.  Each Read stays within
// maxRandRead, so the per-Read cap alone does not stop these requests.
func TestRandDrawsRekey(t *testing.T) {
	seed := make([]byte, 32)
	reads := func(last uint64, extra ...[2]uint64) []byte {
		ops := make([][2]uint64, 0, 64+len(extra))
		for range 63 {
			ops = append(ops, [2]uint64{randOpRead, maxRandRead})
		}
		ops = append(ops, [2]uint64{randOpRead, last})
		return randOps(seed, append(ops, extra...)...)
	}

	// 63 full Reads and one 8 short leave exactly the eight bytes next=
	// draws: read reaches randRekeyBytes without passing it, so no rekey.
	fit := reads(maxRandRead - 8)
	a, b := randDraws(fit), randDraws(fit)
	if a.Error != "" || b.Error != "" {
		t.Fatalf("a request that fits was refused: %q, %q", a.Error, b.Error)
	}
	if a.Result != b.Result {
		t.Fatal("a request that fits gave two answers")
	}

	for name, data := range map[string][]byte{
		"one byte over":       reads(maxRandRead - 7),
		"next= over":          reads(maxRandRead),
		"65 full reads":       reads(maxRandRead, [2]uint64{randOpRead, maxRandRead}),
		"a draw past":         reads(maxRandRead-8, [2]uint64{randOpUint32, 0}),
		"a bounded draw past": reads(maxRandRead-8, [2]uint64{randOpUint32N, 7}),
	} {
		resp := randDraws(data)
		if resp.Result != "" || !strings.Contains(resp.Error, "rekey") {
			t.Errorf("%s: got %+v, want the rekey refusal", name, resp)
		}
	}
}

// TestRecoverAsResponse checks that a panic becomes an error of kind panic.
func TestRecoverAsResponse(t *testing.T) {
	resp := recoverAsResponse(func() response {
		var s []int
		_ = s[0]
		return response{Result: "unreachable"}
	})
	if resp.Kind != "panic" ||
		!strings.Contains(resp.Error, "index out of range [0] with length 0") {
		t.Errorf("got %+v", resp)
	}
	if resp := recoverAsResponse(func() response {
		return response{Result: "ok"}
	}); resp.Result != "ok" || resp.Error != "" {
		t.Errorf("got %+v", resp)
	}
}
