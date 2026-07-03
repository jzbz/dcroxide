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
// Protocol: one JSON object per line in, one per line out.
//
//	→ {"cmd":"blake256","data":"<hex>"}
//	← {"result":"<hex 32-byte digest>"}
//	← {"error":"<message>"}   on any failure
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/decred/dcrd/crypto/blake256"
)

type request struct {
	Cmd  string `json:"cmd"`
	Data string `json:"data,omitempty"`
}

type response struct {
	Result string `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
}

func handle(req request) response {
	switch req.Cmd {
	case "blake256":
		data, err := hex.DecodeString(req.Data)
		if err != nil {
			return response{Error: fmt.Sprintf("blake256: bad hex: %v", err)}
		}
		digest := blake256.Sum256(data)
		return response{Result: hex.EncodeToString(digest[:])}
	default:
		return response{Error: "unknown cmd: " + req.Cmd}
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
		if len(line) == 0 {
			continue
		}
		var req request
		var resp response
		if err := json.Unmarshal(line, &req); err != nil {
			resp = response{Error: fmt.Sprintf("bad request: %v", err)}
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
