// Copyright (c) 2026 The dcroxide developers
// Use of this source code is governed by an ISC license that can be found in
// the LICENSE file.

// ML-DSA under a Go older than 1.27, which mldsa.go needs: sig_sign and
// sig_verify answer for the ML-DSA names that they need a newer Go.

//go:build !go1.27

package main

import (
	"crypto"
	"fmt"
	"runtime"
)

// mldsaUnavailable is the answer for an ML-DSA scheme or x509 algorithm
// named under this Go, and nil for any other name.
func mldsaUnavailable(name string) error {
	switch name {
	case "MLDSA44", "MLDSA65", "MLDSA87", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87":
		return fmt.Errorf("%s needs Go 1.27 or later, and the oracle was built with %s", name, runtime.Version())
	}
	return nil
}

// mldsaSign is never reached: no algorithm of kind sigMLDSA is registered.
func mldsaSign(crypto.Signer, sigAlgorithm, []byte) ([]byte, error) {
	return nil, mldsaUnavailable("ML-DSA-44")
}

// mldsaVerifyHandshake is never reached either.
func mldsaVerifyHandshake(sigAlgorithm, crypto.PublicKey, []byte, []byte) error {
	return mldsaUnavailable("MLDSA44")
}
