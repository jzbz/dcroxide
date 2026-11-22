// Copyright (c) 2026 The dcroxide developers
// Use of this source code is governed by an ISC license that can be found in
// the LICENSE file.

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/decred/dcrd/crypto/blake256"
	"github.com/decred/dcrd/wire"
)

// keepTxType is the msgtx_pkscriptlocs type byte that leaves the
// decoded transaction's serialization type as its bytes gave it.
const keepTxType = 0xff

// pkScriptLocsDetail is msgtx_pkscriptlocs's account of the transaction's
// serialization under the type its locations were taken with: its length
// and BLAKE-256 digest, so a client can check it serializes the same
// transaction without the bytes coming back, and whether every output's
// script is found at its location in it.
type pkScriptLocsDetail struct {
	Len      int    `json:"len"`
	Blake256 string `json:"blake256"`
	Located  bool   `json:"located"`
}

// msgTxPkScriptLocs answers msgtx_pkscriptlocs.  data is type(1) ||
// serialized tx.  The transaction is decoded with FromBytes, whatever its
// serialization, and its serialization type is then set to type (0, 1 or 2)
// unless that is keepTxType.  Setting it after the decode is what reaches a
// witness-only transaction that holds outputs, which no decode produces but
// PkScriptLocs, which never reads the type, still answers for.
//
// The result is PkScriptLocs in decimal joined by ",", or "nil" for the nil
// slice it returns for a transaction without outputs.
func msgTxPkScriptLocs(data []byte) response {
	if len(data) < 1 {
		return errResp("msgtx_pkscriptlocs: truncated request")
	}
	txType := data[0]
	var tx wire.MsgTx
	if err := tx.FromBytes(data[1:]); err != nil {
		return errResp("%v", err)
	}
	switch txType {
	case keepTxType:
	case byte(wire.TxSerializeFull), byte(wire.TxSerializeNoWitness),
		byte(wire.TxSerializeOnlyWitness):
		tx.SerType = wire.TxSerializeType(txType)
	default:
		return errResp("msgtx_pkscriptlocs: unknown serialization type %d",
			txType)
	}

	locs := tx.PkScriptLocs()
	serialized, err := tx.Bytes()
	if err != nil {
		return errResp("msgtx_pkscriptlocs: serialize: %v", err)
	}

	result := "nil"
	if locs != nil {
		parts := make([]string, len(locs))
		for i, loc := range locs {
			parts[i] = strconv.Itoa(loc)
		}
		result = strings.Join(parts, ",")
	}
	located := len(locs) == len(tx.TxOut)
	for i, loc := range locs {
		if !located {
			break
		}
		script := tx.TxOut[i].PkScript
		located = loc >= 0 && loc <= len(serialized) &&
			len(script) <= len(serialized)-loc &&
			bytes.Equal(serialized[loc:loc+len(script)], script)
	}

	digest := blake256.Sum256(serialized)
	detail, err := json.Marshal(pkScriptLocsDetail{
		Len:      len(serialized),
		Blake256: hex.EncodeToString(digest[:]),
		Located:  located,
	})
	if err != nil {
		return errResp("msgtx_pkscriptlocs: %v", err)
	}
	return response{Result: result, Detail: detail}
}
