// Copyright (c) 2026 The dcroxide developers
// Use of this source code is governed by an ISC license that can be found in
// the LICENSE file.

package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/decred/dcrd/wire"
)

// TestMsgTxPkScriptLocs checks msgtx_pkscriptlocs on a transaction with one
// input and two outputs, laid out as dcrd's multiTx (msgtx_test.go), under
// each serialization type: the prefix serializations find the scripts at
// multiTxPkScriptLocs, and so does a witness-only type set after the
// decode, in a serialization that does not hold them.  A witness-only
// decode has no outputs and answers nil, as does an empty transaction.
func TestMsgTxPkScriptLocs(t *testing.T) {
	script := append(append([]byte{0x41}, bytes.Repeat([]byte{0x04}, 65)...), 0xac)
	tx := wire.NewMsgTx()
	tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Index: 0xffffffff}, 0, []byte{1, 2}))
	tx.AddTxOut(&wire.TxOut{Value: 1, Version: 0xabab, PkScript: script})
	tx.AddTxOut(&wire.TxOut{Value: 2, Version: 0xbcbc, PkScript: script})
	full, err := tx.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	witnessOnly := *tx
	witnessOnly.SerType = wire.TxSerializeOnlyWitness
	witnessBytes, err := witnessOnly.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	empty, err := wire.NewMsgTx().Bytes()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		txType  byte
		tx      []byte
		want    string
		located bool
	}{
		{"full, kept", keepTxType, full, "58,136", true},
		{"full", 0, full, "58,136", true},
		{"no witness", 1, full, "58,136", true},
		{"only witness, set after the decode", 2, full, "58,136", false},
		{"only witness, decoded", keepTxType, witnessBytes, "nil", true},
		{"no outputs", keepTxType, empty, "nil", true},
	}
	for _, test := range tests {
		resp := call("msgtx_pkscriptlocs", []byte{test.txType}, test.tx)
		if resp.Error != "" || resp.Result != test.want {
			t.Errorf("%s: got %+v, want result %s", test.name, resp, test.want)
			continue
		}
		var detail pkScriptLocsDetail
		if err := json.Unmarshal(resp.Detail, &detail); err != nil {
			t.Fatalf("%s: %v", test.name, err)
		}
		if detail.Located != test.located || len(detail.Blake256) != 64 {
			t.Errorf("%s: got detail %+v, want located %v", test.name,
				detail, test.located)
		}
	}

	for _, data := range [][]byte{nil, {3}, {0, 1}} {
		if resp := call("msgtx_pkscriptlocs", data); resp.Error == "" {
			t.Errorf("request %x: got %+v, want an error", data, resp)
		}
	}
	resp := call("msgtx_pkscriptlocs", []byte{3}, full)
	if resp.Error == "" {
		t.Errorf("serialization type 3: got %+v, want an error", resp)
	}
}
