// Copyright (c) 2026 The dcroxide developers
// Use of this source code is governed by an ISC license that can be found in
// the LICENSE file.

// The TLS commands under a Go older than 1.26, which tls.go needs: each
// answers that it needs a newer Go.

//go:build !go1.26

package main

import "runtime"

func tlsPKI([]byte) response          { return tlsNeedsGo126("tls_pki") }
func tlsDial([]byte) response         { return tlsNeedsGo126("tls_dial") }
func tlsListen([]byte) response       { return tlsNeedsGo126("tls_listen") }
func tlsListenResult([]byte) response { return tlsNeedsGo126("tls_listen_result") }

// tlsNeedsGo126 is the TLS commands' answer under this Go.
func tlsNeedsGo126(cmd string) response {
	return errResp("%s: needs Go 1.26 or later, and the oracle was built with %s", cmd, runtime.Version())
}
