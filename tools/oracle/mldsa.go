// Copyright (c) 2026 The dcroxide developers
// Use of this source code is governed by an ISC license that can be found in
// the LICENSE file.

// ML-DSA in sig_sign and sig_verify. crypto/mldsa, tls.MLDSA44 and
// x509.MLDSA44 are new in Go 1.27, and this module's go line is go1.24,
// so this file is built by Go 1.27 or later alone, and mldsa_old.go
// answers for the ML-DSA names under an older Go.

//go:build go1.27

package main

import (
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
)

// The three parameter sets' TLS schemes and x509 algorithms, taken by
// sig_sign and sig_verify beside the others.
func init() {
	for set, names := range map[int]struct {
		scheme tls.SignatureScheme
		x509   x509.SignatureAlgorithm
	}{
		44: {tls.MLDSA44, x509.MLDSA44},
		65: {tls.MLDSA65, x509.MLDSA65},
		87: {tls.MLDSA87, x509.MLDSA87},
	} {
		alg := sigAlgorithm{kind: sigMLDSA, mldsa: set}
		sigSchemes[names.scheme] = alg
		sigX509Algorithms[names.x509] = alg
	}
}

// mldsaUnavailable is nil: this Go has ML-DSA.
func mldsaUnavailable(string) error { return nil }

// mldsaParameters is the parameter set alg names.
func mldsaParameters(alg sigAlgorithm) (mldsa.Parameters, error) {
	switch alg.mldsa {
	case 44:
		return mldsa.MLDSA44(), nil
	case 65:
		return mldsa.MLDSA65(), nil
	case 87:
		return mldsa.MLDSA87(), nil
	}
	return mldsa.Parameters{}, fmt.Errorf("no ML-DSA parameter set %d", alg.mldsa)
}

// mldsaSign signs message with an ML-DSA key of alg's parameter set, pure
// and with no context, as crypto/tls signs a TLS 1.3 handshake
// (crypto/tls/auth.go:145-162 gives the zero hash, which
// crypto/tls/handshake_server_tls13.go:869-873 and
// handshake_client_tls13.go:795-799 sign with) and crypto/x509 a
// certificate: the key's Sign with a zero hash, which hedges with fresh
// randomness.
func mldsaSign(key crypto.Signer, alg sigAlgorithm, message []byte) ([]byte, error) {
	params, err := mldsaParameters(alg)
	if err != nil {
		return nil, err
	}
	k, ok := key.(*mldsa.PrivateKey)
	if !ok || k.PublicKey().Parameters() != params {
		return nil, fmt.Errorf("a key of type %T for this algorithm", key)
	}
	return k.Sign(rand.Reader, message, crypto.Hash(0))
}

// mldsaVerifyHandshake is crypto/tls's verification of an ML-DSA
// handshake signature (crypto/tls/auth.go:49-56), after the check a TLS
// 1.3 server makes on a client's CertificateVerify that the scheme is one
// of the key's own (crypto/tls/handshake_server_tls13.go:1088-1092,
// auth.go:242-252), so that a signature under another set's scheme is
// refused as Go refuses it in a handshake.
func mldsaVerifyHandshake(alg sigAlgorithm, pub crypto.PublicKey, signed, sig []byte) error {
	params, err := mldsaParameters(alg)
	if err != nil {
		return err
	}
	key, ok := pub.(*mldsa.PublicKey)
	if !ok {
		return fmt.Errorf("expected an ML-DSA public key, got %T", pub)
	}
	if key.Parameters() != params {
		return errors.New("tls: client certificate used with invalid signature algorithm")
	}
	if err := mldsa.Verify(key, signed, sig, nil); err != nil {
		return fmt.Errorf("ML-DSA verification failure: %w", err)
	}
	return nil
}
