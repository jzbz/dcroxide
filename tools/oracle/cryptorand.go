// Copyright (c) 2026 The dcroxide developers
// Use of this source code is governed by an ISC license that can be found in
// the LICENSE file.

package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
	"time"
	"unsafe"

	dcrdrand "github.com/decred/dcrd/crypto/rand"
	"golang.org/x/crypto/chacha20"
)

// The operations rand_draws runs, by their code byte.  Each takes the
// eight-byte argument that follows its code; the ones without a bound
// ignore it.
const (
	randOpUint32   = 1
	randOpUint64   = 2
	randOpUint32N  = 3
	randOpUint64N  = 4
	randOpInt32    = 5
	randOpInt32N   = 6
	randOpInt64    = 7
	randOpInt64N   = 8
	randOpInt      = 9
	randOpIntN     = 10
	randOpUintN    = 11
	randOpDuration = 12
	randOpRead     = 13
)

// maxRandRead caps one rand_draws Read, which bounds the memory one
// operation allocates and the size of its line.  It bounds each Read only,
// not the request: a request whose operations add up to dcrd's 4 MiB byte
// budget (maxCipherRead, prng.go:20) takes the generator through seed(),
// which mixes in kernel entropy, so randDraws detects that rekey after the
// fact and refuses the request rather than answer with a stream that
// differs from call to call.  Detecting rather than budgeting ahead is
// exact: a bounded draw rejection-samples, so the bytes it reads are not
// known before it runs.
const maxRandRead = 1 << 16

// randRekeyBytes is dcrd's maxCipherRead, the byte budget after which its
// PRNG rekeys, named here only for the refusal's text.
const randRekeyBytes = 4 << 20

// seededNonce is the nonce field seededPRNG leaves for the next cipher.
// Only dcrd's seed() advances it (prng.go:77), so a PRNG whose nonce no
// longer equals this has been rekeyed from the kernel.
var seededNonce = [chacha20.NonceSize]byte{1}

// seededPRNG returns dcrd's PRNG in the state dcroxide's Prng::from_seed
// constructs: a ChaCha20 cipher under seed with the all-zero nonce, the
// nonce for the next cipher advanced to one, and nothing read.  dcrd keys
// its PRNG only from the kernel and keeps every field unexported, so the
// fields are set through reflection; a change to their names or types
// fails here rather than seeding something else.  The reseed deadline is
// put out of reach, as dcroxide does not port the 20-second rekey and a
// request runs in far less time anyway.
func seededPRNG(seed []byte) (*dcrdrand.PRNG, error) {
	if len(seed) != chacha20.KeySize {
		return nil, fmt.Errorf("seed is %d bytes, want %d", len(seed),
			chacha20.KeySize)
	}
	cipher, err := chacha20.NewUnauthenticatedCipher(seed,
		make([]byte, chacha20.NonceSize))
	if err != nil {
		return nil, err
	}
	nonce := seededNonce
	p := new(dcrdrand.PRNG)
	v := reflect.ValueOf(p).Elem()
	set := func(name string, value any) error {
		f := v.FieldByName(name)
		if !f.IsValid() {
			return fmt.Errorf("dcrd's PRNG has no field %q", name)
		}
		val := reflect.ValueOf(value)
		if f.Kind() == reflect.Array && val.Kind() == reflect.Array &&
			f.Type().Elem() == val.Type().Elem() && f.Len() == val.Len() {
			val = val.Convert(f.Type())
		}
		if f.Type() != val.Type() {
			return fmt.Errorf("dcrd's PRNG field %q is %v, not %v", name,
				f.Type(), val.Type())
		}
		reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem().Set(val)
		return nil
	}
	for _, field := range []struct {
		name  string
		value any
	}{
		{"cipher", *cipher},
		{"nonce", nonce},
		{"read", 0},
		{"t", time.Now().AddDate(100, 0, 0)},
	} {
		if err := set(field.name, field.value); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// rekeyed reports whether p has left the cipher seededPRNG gave it, that
// is, whether dcrd's seed() has run and drawn from the kernel.  The nonce
// is read element by element, which reflection allows on an unexported
// field without the unsafe write path seededPRNG needs.
func rekeyed(p *dcrdrand.PRNG) (bool, error) {
	f := reflect.ValueOf(p).Elem().FieldByName("nonce")
	if !f.IsValid() || f.Kind() != reflect.Array ||
		f.Len() != len(seededNonce) || f.Type().Elem().Kind() != reflect.Uint8 {
		return false, fmt.Errorf("dcrd's PRNG has no 12-byte nonce field")
	}
	for i, b := range seededNonce {
		if f.Index(i).Uint() != uint64(b) {
			return true, nil
		}
	}
	return false, nil
}

// randDraw runs one rand_draws operation, rendering its result, or the
// panic it raised as "panic: " and the panic's value.
func randDraw(p *dcrdrand.PRNG, op byte, arg uint64) (out string) {
	defer func() {
		if r := recover(); r != nil {
			out = fmt.Sprintf("panic: %v", r)
		}
	}()
	switch op {
	case randOpUint32:
		return fmt.Sprint(p.Uint32())
	case randOpUint64:
		return fmt.Sprint(p.Uint64())
	case randOpUint32N:
		return fmt.Sprint(p.Uint32N(uint32(arg)))
	case randOpUint64N:
		return fmt.Sprint(p.Uint64N(arg))
	case randOpInt32:
		return fmt.Sprint(p.Int32())
	case randOpInt32N:
		return fmt.Sprint(p.Int32N(int32(arg)))
	case randOpInt64:
		return fmt.Sprint(p.Int64())
	case randOpInt64N:
		return fmt.Sprint(p.Int64N(int64(arg)))
	case randOpInt:
		return fmt.Sprint(p.Int())
	case randOpIntN:
		return fmt.Sprint(p.IntN(int(arg)))
	case randOpUintN:
		return fmt.Sprint(p.UintN(uint(arg)))
	case randOpDuration:
		return fmt.Sprint(int64(p.Duration(time.Duration(arg))))
	case randOpRead:
		if arg > maxRandRead {
			return fmt.Sprintf("error: read of %d bytes exceeds %d", arg,
				maxRandRead)
		}
		b := make([]byte, arg)
		p.Read(b)
		return hex.EncodeToString(b)
	}
	return fmt.Sprintf("error: unknown operation %d", op)
}

// randDraws answers rand_draws: data is seed(32) || operations, each
// code(1) || argument(8 BE).  The result is one line per operation, then
// "next=" and one more Uint64, which pins how far the operations moved the
// stream.  A request that reaches dcrd's 4 MiB rekey, the next= draw
// included, is refused: past that point the stream depends on the kernel.
func randDraws(data []byte) response {
	if len(data) < chacha20.KeySize || (len(data)-chacha20.KeySize)%9 != 0 {
		return errResp("rand_draws: want a 32-byte seed and 9-byte operations, "+
			"got %d bytes", len(data))
	}
	p, err := seededPRNG(data[:chacha20.KeySize])
	if err != nil {
		return errResp("rand_draws: %v", err)
	}
	var w strings.Builder
	for ops := data[chacha20.KeySize:]; len(ops) > 0; ops = ops[9:] {
		w.WriteString(randDraw(p, ops[0], binary.BigEndian.Uint64(ops[1:9])))
		w.WriteByte('\n')
	}
	fmt.Fprintf(&w, "next=%d", p.Uint64())
	switch again, err := rekeyed(p); {
	case err != nil:
		return errResp("rand_draws: %v", err)
	case again:
		return errResp("rand_draws: the operations reached the PRNG's "+
			"%d-byte rekey, which draws kernel entropy, so the result "+
			"would not be reproducible", randRekeyBytes)
	}
	return response{Result: w.String()}
}
