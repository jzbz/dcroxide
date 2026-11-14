// Copyright (c) 2026 The dcroxide developers
// Use of this source code is governed by an ISC license that can be found in
// the LICENSE file.

// ML-DSA's tests in sig_sign, sig_verify, tls_pki, x509_key_pair and the
// TLS commands, built with mldsa.go, by Go 1.27 or later.

//go:build go1.27

package main

import (
	"crypto/mldsa"
	"crypto/x509"
	"encoding/hex"
	"runtime"
	"strings"
	"testing"
)

// TestTLSPKIAndKeyPairMLDSA checks tls_pki with a key of each ML-DSA
// parameter set, a CA signing a leaf of each, its key in PKCS#8 seed form
// and the certificate signed with the issuer's own set; x509_key_pair
// naming each set for the pair; and Go's server serving each in TLS 1.3
// to Go's client and refusing a client held to TLS 1.2 with internal_error
// and crypto/tls's text (crypto/tls/handshake_server.go:310-314).
func TestTLSPKIAndKeyPairMLDSA(t *testing.T) {
	t.Setenv("GODEBUG", tlsGODEBUG)
	for _, tc := range []struct {
		name   string
		sigAlg x509.SignatureAlgorithm
	}{
		{"ML-DSA-44", x509.MLDSA44},
		{"ML-DSA-65", x509.MLDSA65},
		{"ML-DSA-87", x509.MLDSA87},
	} {
		pki := tlsPKIOf(t,
			map[string]any{"name": "ca", "key": tc.name, "ca": true},
			map[string]any{
				"name": "server", "key": tc.name, "issuer": "ca", "eku": []string{"server_auth"},
				"dns": []string{"localhost"},
			},
		)
		ca, _ := parsed(t, "ca", pki["ca"])
		cert, key := parsed(t, "server", pki["server"])
		if _, ok := key.(*mldsa.PrivateKey); !ok {
			t.Fatalf("%s: a key of type %T", tc.name, key)
		}
		if cert.SignatureAlgorithm != tc.sigAlg || ca.SignatureAlgorithm != tc.sigAlg {
			t.Errorf("%s: signed with %v and %v", tc.name, cert.SignatureAlgorithm, ca.SignatureAlgorithm)
		}
		if err := cert.CheckSignatureFrom(ca); err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
		// The seed form: the 32-byte seed under [0], 34 bytes at the end.
		if der := hexToBytes(pki["server"].KeyPKCS8); len(der) < 34 || der[len(der)-34] != 0x80 || der[len(der)-33] != 0x20 {
			t.Errorf("%s: key_pkcs8 %x is not the seed form", tc.name, der)
		}
		resp := call("x509_key_pair", jsonRequest(t, map[string]any{
			"cert_pem": pki["server"].CertPEM, "key_pem": pki["server"].KeyPEM,
		}))
		if resp.Error != "" || resp.Result != "ok "+tc.name {
			t.Errorf("%s: x509_key_pair %+v", tc.name, resp)
		}

		identity := map[string]any{"chain": []string{pki["server"].Cert}, "key_pkcs8": pki["server"].KeyPKCS8}
		dial := func(addr string, fields map[string]any) tlsDialDetail {
			t.Helper()
			fields["addr"], fields["server_name"], fields["roots"] = addr, "localhost", []string{pki["ca"].Cert}
			fields["request"] = map[string]any{"method": "POST", "path": "/", "body": "{}"}
			return tlsDialOf(t, fields)
		}
		listen := func() (string, uint64) {
			t.Helper()
			fields := map[string]any{"response_body": `{"result":0}`}
			for k, v := range identity {
				fields[k] = v
			}
			return tlsListenOf(t, fields)
		}
		addr, id := listen()
		got := dial(addr, map[string]any{})
		served := tlsListenResultOf(t, id)
		if !got.OK || got.Version != "TLS 1.3" || !served.OK {
			t.Errorf("%s: TLS 1.3: dial %+v, listen %+v", tc.name, got, served)
		}
		addr, id = listen()
		got = dial(addr, map[string]any{"max_version": "TLS 1.2"})
		served = tlsListenResultOf(t, id)
		if got.OK || got.Error != "remote error: tls: internal error" {
			t.Errorf("%s: TLS 1.2: dial %+v", tc.name, got)
		}
		if want := "tls: ML-DSA certificates require TLS 1.3, but client negotiated TLS 1.2"; served.OK || served.Error != want {
			t.Errorf("%s: TLS 1.2: listen %+v, want the error %q", tc.name, served, want)
		}
	}
}

// TestSigMLDSA checks sig_sign and sig_verify on each ML-DSA parameter
// set, a key in PKCS#8 seed form signing through an x509 algorithm and a
// TLS scheme alike: its signature verifies under both, and is refused when
// a byte of it or of the message changes, under another set's name, with
// Go's x509 text for the set mismatch and crypto/tls's for the scheme,
// and with a key one byte short, which x509.ParsePKIXPublicKey refuses.
func TestSigMLDSA(t *testing.T) {
	message := []byte("a TLS 1.3 CertificateVerify's content")
	for _, tc := range []struct {
		params                  mldsa.Parameters
		x509Alg, scheme         string
		otherX509, otherScheme  string
		keyLen, signatureLength int
	}{
		{mldsa.MLDSA44(), "ML-DSA-44", "MLDSA44", "ML-DSA-65", "MLDSA65", 1312, 2420},
		{mldsa.MLDSA65(), "ML-DSA-65", "MLDSA65", "ML-DSA-87", "MLDSA87", 1952, 3309},
		{mldsa.MLDSA87(), "ML-DSA-87", "MLDSA87", "ML-DSA-44", "MLDSA44", 2592, 4627},
	} {
		key, err := mldsa.GenerateKey(tc.params)
		if err != nil {
			t.Fatal(err)
		}
		pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		spki, err := x509.MarshalPKIXPublicKey(key.PublicKey())
		if err != nil {
			t.Fatal(err)
		}
		if got := len(key.PublicKey().Bytes()); got != tc.keyLen {
			t.Fatalf("%s: a key of %d bytes", tc.x509Alg, got)
		}
		for _, name := range []map[string]any{{"x509_alg": tc.x509Alg}, {"scheme": tc.scheme}} {
			fields := map[string]any{"key_pkcs8": hex.EncodeToString(pkcs8),
				"message": hex.EncodeToString(message)}
			for k, v := range name {
				fields[k] = v
			}
			resp := call("sig_sign", jsonRequest(t, fields))
			if resp.Error != "" || resp.GoVersion != runtime.Version() {
				t.Fatalf("%v: got %+v", name, resp)
			}
			sig, err := hex.DecodeString(resp.Result)
			if err != nil || len(sig) != tc.signatureLength {
				t.Fatalf("%v: a signature of %d bytes, %v", name, len(sig), err)
			}
			flipped := append([]byte{}, sig...)
			flipped[len(flipped)/2] ^= 0x10
			verify := func(path, alg string, spki, message, sig []byte) string {
				t.Helper()
				resp := call("sig_verify", jsonRequest(t, map[string]any{"spki": hex.EncodeToString(spki),
					path: alg, "message": hex.EncodeToString(message), "signature": hex.EncodeToString(sig)}))
				if resp.Error != "" || resp.GoVersion != runtime.Version() {
					t.Fatalf("%s %s: got %+v", path, alg, resp)
				}
				return resp.Result
			}
			for _, path := range []struct{ field, alg, other, mismatch string }{
				{"x509_alg", tc.x509Alg, tc.otherX509, "refused: x509: signature algorithm specifies an ML-DSA public key with " + tc.otherX509 + " parameters"},
				{"tls_scheme", tc.scheme, tc.otherScheme, "refused: tls: client certificate used with invalid signature algorithm"},
			} {
				if got := verify(path.field, path.alg, spki, message, sig); got != "ok" {
					t.Errorf("%s, %s: got %q", tc.x509Alg, path.field, got)
				}
				for what, got := range map[string]string{
					"a byte of the signature": verify(path.field, path.alg, spki, message, flipped),
					"another message":         verify(path.field, path.alg, spki, []byte("another"), sig),
				} {
					if !strings.HasPrefix(got, "refused: ") || !strings.Contains(got, "ML-DSA verification failure: mldsa: invalid signature") {
						t.Errorf("%s, %s, %s: got %q", tc.x509Alg, path.field, what, got)
					}
				}
				if got := verify(path.field, path.other, spki, message, sig); !strings.HasPrefix(got, path.mismatch) {
					t.Errorf("%s under %s: got %q", tc.x509Alg, path.other, got)
				}
			}
		}
		// The key one byte short: the SPKI's SEQUENCE length (bytes 2 and
		// 3) and the BIT STRING's (bytes 19 and 20, after the 13 of the
		// AlgorithmIdentifier) both drop by one.
		short := append([]byte{}, spki[:len(spki)-1]...)
		if short[3] == 0 || short[20] == 0 {
			t.Fatalf("%s: an SPKI whose lengths end in zero bytes", tc.x509Alg)
		}
		short[3]--
		short[20]--
		resp := call("sig_verify", jsonRequest(t, map[string]any{"spki": hex.EncodeToString(short),
			"x509_alg": tc.x509Alg, "message": "", "signature": "00"}))
		if resp.Result != "refused: mldsa: invalid public key length" {
			t.Errorf("%s, a key a byte short: got %+v", tc.x509Alg, resp)
		}
	}
	// An ML-DSA key under an algorithm of another kind, and another kind
	// of key under an ML-DSA name.
	key, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Ed25519", "ML-DSA-65"} {
		resp := call("sig_sign", jsonRequest(t, map[string]any{"key_pkcs8": hex.EncodeToString(pkcs8),
			"x509_alg": name, "message": ""}))
		if resp.Error == "" {
			t.Errorf("an ML-DSA-44 key for %s: got %+v, want an error", name, resp)
		}
	}
}
