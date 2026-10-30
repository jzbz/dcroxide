// Copyright (c) 2026 The dcroxide developers
// Use of this source code is governed by an ISC license that can be found in
// the LICENSE file.

// The TLS commands' tests, built with tls.go, by Go 1.26 or later.

//go:build go1.26

package main

import (
	"crypto"
	stdecdsa "crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// tlsGODEBUG is dcrd's GODEBUG at the parity pin for the four crypto,
// crypto/tls and crypto/x509 settings among the eight where its
// default=go1.26 differs from this module's go1.24 line, which dcroxide's
// TLS interop tests start the oracle with (dcroxide-testutil's
// DCRD_TLS_GODEBUG, which a test there holds to this).
const tlsGODEBUG = "tlssecpmlkem=1,tlssha1=0,x509sha256skid=1,cryptocustomrand=0"

// tlsCall answers a TLS command through handle, failing the test on an
// error response or one without the running Go.
func tlsCall(t *testing.T, cmd string, fields map[string]any) response {
	t.Helper()
	resp := call(cmd, jsonRequest(t, fields))
	if resp.Error != "" || resp.GoVersion != runtime.Version() {
		t.Fatalf("%s: got %+v, want an answer from %s", cmd, resp, runtime.Version())
	}
	return resp
}

// tlsPKIOf answers tls_pki for certs, decoded.
func tlsPKIOf(t *testing.T, certs ...map[string]any) map[string]tlsPKIEntry {
	t.Helper()
	resp := tlsCall(t, "tls_pki", map[string]any{"certs": certs})
	var pki map[string]tlsPKIEntry
	if err := json.Unmarshal(resp.Detail, &pki); err != nil {
		t.Fatal(err)
	}
	if len(pki) != len(certs) {
		t.Fatalf("tls_pki: %d certificates for %d asked", len(pki), len(certs))
	}
	return pki
}

// parsed is the certificate and the key of a tls_pki entry, each checked
// against its PEM form, and the key against the certificate.
func parsed(t *testing.T, name string, e tlsPKIEntry) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	der, keyDER := hexToBytes(e.Cert), hexToBytes(e.KeyPKCS8)
	certBlock, rest := pem.Decode([]byte(e.CertPEM))
	if certBlock == nil || certBlock.Type != "CERTIFICATE" || !slices.Equal(certBlock.Bytes, der) || len(rest) != 0 {
		t.Fatalf("%s: cert_pem is not cert", name)
	}
	keyBlock, rest := pem.Decode([]byte(e.KeyPEM))
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" || !slices.Equal(keyBlock.Bytes, keyDER) || len(rest) != 0 {
		t.Fatalf("%s: key_pem is not key_pkcs8", name)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	key, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	signer := key.(crypto.Signer)
	if pub, ok := signer.Public().(interface{ Equal(crypto.PublicKey) bool }); !ok || !pub.Equal(cert.PublicKey) {
		t.Fatalf("%s: the key is not the certificate's", name)
	}
	if cert.Subject.CommonName != name {
		t.Errorf("%s: common name %q", name, cert.Subject.CommonName)
	}
	return cert, signer
}

// TestTLSPKI checks tls_pki: a chain of a P-256 root, an RSA intermediate
// with the caller's key and an Ed25519 leaf, and P-384 and P-521
// self-signed certificates, each with the key, issuer, signature
// algorithm, basic constraints, key usage, extended key usage, names,
// addresses and validity asked for or the defaults, its key the one
// key_pkcs8 holds, and the chain verifying as Go verifies a server's; and
// that requests it cannot meet are errors.
func TestTLSPKI(t *testing.T) {
	rsaKey, _ := testRSAKey(t, 2048, 65537)
	notBefore, notAfter := time.Unix(1767225600, 0), time.Unix(4102444800, 0)
	pki := tlsPKIOf(t,
		map[string]any{"name": "root", "key": "P-256", "ca": true},
		map[string]any{"name": "inter", "rsa": rsaKey, "issuer": "root", "sig_alg": "ECDSA-SHA384", "ca": true},
		map[string]any{
			"name": "leaf", "key": "Ed25519", "issuer": "inter", "sig_alg": "SHA256-RSAPSS",
			"eku": []string{"server_auth", "client_auth"}, "dns": []string{"localhost"},
			"ip": []string{"127.0.0.1", "::1"}, "not_before": notBefore.Unix(), "not_after": notAfter.Unix(),
		},
		map[string]any{"name": "p384", "key": "P-384", "eku": []string{"any"}},
		map[string]any{"name": "p521", "key": "P-521", "sig_alg": "ECDSA-SHA512", "ca": true},
	)
	now := time.Now()
	type want struct {
		key    string
		sigAlg x509.SignatureAlgorithm
		ca     bool
		eku    []x509.ExtKeyUsage
	}
	certs := map[string]*x509.Certificate{}
	for name, w := range map[string]want{
		"root":  {"ECDSA P-256", x509.ECDSAWithSHA256, true, nil},
		"inter": {"RSA 2048", x509.ECDSAWithSHA384, true, nil},
		"leaf":  {"Ed25519", x509.SHA256WithRSAPSS, false, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}},
		"p384":  {"ECDSA P-384", x509.ECDSAWithSHA384, false, []x509.ExtKeyUsage{x509.ExtKeyUsageAny}},
		"p521":  {"ECDSA P-521", x509.ECDSAWithSHA512, true, nil},
	} {
		cert, key := parsed(t, name, pki[name])
		certs[name] = cert
		var kind string
		switch k := key.(type) {
		case *stdecdsa.PrivateKey:
			kind = "ECDSA " + k.Curve.Params().Name
		case ed25519.PrivateKey:
			kind = "Ed25519"
		case *rsa.PrivateKey:
			kind = fmt.Sprintf("RSA %d", k.N.BitLen())
			if k.N.Text(16) != rsaKey.N {
				t.Errorf("%s: not the caller's RSA key", name)
			}
		}
		wantUsage := x509.KeyUsageDigitalSignature
		if w.ca {
			wantUsage |= x509.KeyUsageCertSign
		}
		switch {
		case kind != w.key:
			t.Errorf("%s: a key of %s, want %s", name, kind, w.key)
		case cert.SignatureAlgorithm != w.sigAlg:
			t.Errorf("%s: signed %v, want %v", name, cert.SignatureAlgorithm, w.sigAlg)
		case !cert.BasicConstraintsValid || cert.IsCA != w.ca:
			t.Errorf("%s: CA %v, want %v", name, cert.IsCA, w.ca)
		case cert.KeyUsage != wantUsage:
			t.Errorf("%s: key usage %v, want %v", name, cert.KeyUsage, wantUsage)
		case !slices.Equal(cert.ExtKeyUsage, w.eku):
			t.Errorf("%s: extended key usage %v, want %v", name, cert.ExtKeyUsage, w.eku)
		}
		if name != "leaf" && (cert.NotBefore.After(now.Add(-time.Hour)) ||
			cert.NotBefore.Before(now.Add(-time.Hour-time.Minute)) ||
			!cert.NotAfter.Equal(cert.NotBefore.Add(25*time.Hour))) {
			t.Errorf("%s: valid from %v to %v, want an hour ago to a day ahead", name, cert.NotBefore, cert.NotAfter)
		}
	}
	leaf := certs["leaf"]
	if !leaf.NotBefore.Equal(notBefore) || !leaf.NotAfter.Equal(notAfter) {
		t.Errorf("leaf: valid from %v to %v", leaf.NotBefore, leaf.NotAfter)
	}
	if !slices.Equal(leaf.DNSNames, []string{"localhost"}) || len(leaf.IPAddresses) != 2 ||
		!leaf.IPAddresses[0].Equal(net.IPv4(127, 0, 0, 1)) || !leaf.IPAddresses[1].Equal(net.IPv6loopback) {
		t.Errorf("leaf: names %v, addresses %v", leaf.DNSNames, leaf.IPAddresses)
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(certs["root"])
	intermediates.AddCert(certs["inter"])
	chains, err := leaf.Verify(x509.VerifyOptions{
		DNSName: "localhost", Roots: roots, Intermediates: intermediates, CurrentTime: now,
	})
	if err != nil || len(chains) != 1 || len(chains[0]) != 3 {
		t.Errorf("leaf: chains %v, %v", chains, err)
	}
	if certs["root"].SerialNumber.Cmp(certs["p384"].SerialNumber) == 0 {
		t.Errorf("two certificates with one serial")
	}

	big31, _ := testRSAKey(t, 1024, 1<<31+1)
	for name, certs := range map[string][]map[string]any{
		"no name":               {{"key": "P-256"}},
		"a name twice":          {{"name": "a", "key": "P-256"}, {"name": "a", "key": "P-256"}},
		"an unknown key":        {{"name": "a", "key": "P-224"}},
		"no key":                {{"name": "a"}},
		"key and rsa":           {{"name": "a", "key": "P-256", "rsa": rsaKey}},
		"an RSA key Go refuses": {{"name": "a", "rsa": big31}},
		"a later issuer":        {{"name": "a", "key": "P-256", "issuer": "b"}, {"name": "b", "key": "P-256", "ca": true}},
		"an unknown sig_alg":    {{"name": "a", "key": "P-256", "sig_alg": "SHA1-RSA"}},
		"another key's sig_alg": {{"name": "a", "key": "Ed25519", "sig_alg": "ECDSA-SHA256"}},
		"an unknown eku":        {{"name": "a", "key": "P-256", "eku": []string{"code_signing"}}},
		"an ip that is not one": {{"name": "a", "key": "P-256", "ip": []string{"localhost"}}},
		"a misspelled field":    {{"name": "a", "key": "P-256", "dns_names": []string{"localhost"}}},
	} {
		resp := call("tls_pki", jsonRequest(t, map[string]any{"certs": certs}))
		if resp.Error == "" || len(resp.Detail) != 0 {
			t.Errorf("%s: got %+v, want an error", name, resp)
		}
	}
	for what, data := range map[string]string{"not JSON": "not JSON", "two values": `{"certs": []} {}`} {
		if resp := call("tls_pki", []byte(data)); resp.Error == "" {
			t.Errorf("%s: got %+v, want an error", what, resp)
		}
	}
}

// tlsListenOf answers tls_listen for fields, with the server's address and
// id.
func tlsListenOf(t *testing.T, fields map[string]any) (string, uint64) {
	t.Helper()
	resp := tlsCall(t, "tls_listen", fields)
	var detail struct {
		ID *uint64 `json:"id"`
	}
	if err := json.Unmarshal(resp.Detail, &detail); err != nil || detail.ID == nil {
		t.Fatalf("tls_listen: detail %s, %v", resp.Detail, err)
	}
	if host, _, err := net.SplitHostPort(resp.Result); err != nil || host != "127.0.0.1" {
		t.Fatalf("tls_listen: address %q, %v", resp.Result, err)
	}
	return resp.Result, *detail.ID
}

// tlsDialOf answers tls_dial for fields, decoded.
func tlsDialOf(t *testing.T, fields map[string]any) tlsDialDetail {
	t.Helper()
	var detail tlsDialDetail
	if err := json.Unmarshal(tlsCall(t, "tls_dial", fields).Detail, &detail); err != nil {
		t.Fatal(err)
	}
	return detail
}

// tlsListenResultOf answers tls_listen_result for id, decoded.
func tlsListenResultOf(t *testing.T, id uint64) tlsListenDetail {
	t.Helper()
	var detail tlsListenDetail
	resp := tlsCall(t, "tls_listen_result", map[string]any{"id": id})
	if err := json.Unmarshal(resp.Detail, &detail); err != nil {
		t.Fatal(err)
	}
	return detail
}

// TestTLSListenAndDial serves tls_listen's servers to tls_dial's clients
// under dcrd's GODEBUG and checks every field of both answers: in TLS 1.2
// with a suite and a group chosen; in TLS 1.3 with a HelloRetryRequest and
// a client certificate verified to its root; with both sides on Go's
// defaults, which settle on X25519MLKEM768; a server certificate the
// client does not trust and a client certificate the server does not, the
// second refused after a TLS 1.3 client's handshake; a server nobody
// dials, which gives up at its deadline, and a dial to its closed port; a
// client that sends no request; and requests the commands cannot meet,
// each refused before anything is dialed. Every server's result is taken,
// which waits for its goroutine to close its listener, and none is left.
func TestTLSListenAndDial(t *testing.T) {
	t.Setenv("GODEBUG", tlsGODEBUG)
	pki := tlsPKIOf(t,
		map[string]any{"name": "ca", "key": "P-256", "ca": true},
		map[string]any{
			"name": "server", "key": "P-256", "issuer": "ca", "eku": []string{"server_auth"},
			"dns": []string{"localhost"}, "ip": []string{"127.0.0.1"},
		},
		map[string]any{"name": "client", "key": "Ed25519", "issuer": "ca", "eku": []string{"client_auth"}},
		map[string]any{
			"name": "expired", "key": "P-384", "issuer": "ca", "eku": []string{"client_auth"},
			"not_before": time.Now().Add(-48 * time.Hour).Unix(), "not_after": time.Now().Add(-24 * time.Hour).Unix(),
		},
		map[string]any{"name": "stranger", "key": "P-256", "ca": true},
	)
	identity := func(name string, chain ...string) map[string]any {
		certs := []string{pki[name].Cert}
		for _, c := range chain {
			certs = append(certs, pki[c].Cert)
		}
		return map[string]any{"chain": certs, "key_pkcs8": pki[name].KeyPKCS8}
	}
	server := identity("server", "ca")
	listen := func(fields map[string]any) (string, uint64) {
		t.Helper()
		fields["chain"], fields["key_pkcs8"] = server["chain"], server["key_pkcs8"]
		fields["response_body"] = `{"result":0}`
		return tlsListenOf(t, fields)
	}
	request := map[string]any{
		"method": "POST", "path": "/", "body": `{"method":"getblockcount"}`,
		"headers": map[string]string{"Content-Type": "application/json"},
	}
	dial := func(addr string, fields map[string]any) tlsDialDetail {
		t.Helper()
		fields["addr"], fields["server_name"], fields["request"] = addr, "localhost", request
		if _, ok := fields["roots"]; !ok {
			fields["roots"] = []string{pki["ca"].Cert}
		}
		return tlsDialOf(t, fields)
	}
	// Go 1.26.2's signature schemes, without SHA-1 (tlssha1=0), and in TLS
	// 1.3 without PKCS#1 v1.5 either (crypto/tls/common.go:1752-1794).
	tls12Schemes := []string{
		"PSSWithSHA256", "ECDSAWithP256AndSHA256", "Ed25519", "PSSWithSHA384", "PSSWithSHA512",
		"PKCS1WithSHA256", "PKCS1WithSHA384", "PKCS1WithSHA512", "ECDSAWithP384AndSHA384",
		"ECDSAWithP521AndSHA512",
	}
	tls13Schemes := []string{
		"PSSWithSHA256", "ECDSAWithP256AndSHA256", "Ed25519", "PSSWithSHA384", "PSSWithSHA512",
		"ECDSAWithP384AndSHA384", "ECDSAWithP521AndSHA512",
	}
	tls13Suites := []string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"}
	allCurves := []string{
		"X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024",
		"X25519", "CurveP256", "CurveP384", "CurveP521",
	}

	// TLS 1.2, with the suite and the group the client offers alone.
	addr, id := listen(map[string]any{"max_version": "TLS 1.2"})
	got := dial(addr, map[string]any{
		"max_version":       "TLS 1.2",
		"cipher_suites":     []string{"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"},
		"curve_preferences": []string{"CurveP384"},
	})
	state := tlsState{"TLS 1.2", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "CurveP384", false}
	wantDial := tlsDialDetail{OK: true, tlsState: state, HTTPStatus: 200, HTTPBody: `{"result":0}`}
	if !reflect.DeepEqual(got, wantDial) {
		t.Errorf("TLS 1.2: dial %+v, want %+v", got, wantDial)
	}
	served := tlsListenResultOf(t, id)
	hello := served.ClientHello
	if hello == nil {
		t.Fatal("TLS 1.2: no ClientHello")
	}
	served.ClientHello = nil
	wantListen := tlsListenDetail{
		OK: true, tlsState: state, PeerCertificates: []string{}, VerifiedChains: [][]string{},
	}
	if !reflect.DeepEqual(served, wantListen) {
		t.Errorf("TLS 1.2: listen %+v, want %+v", served, wantListen)
	}
	wantHello := &tlsClientHello{
		CipherSuites:      []string{"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"},
		SupportedCurves:   []string{"CurveP384"},
		SignatureSchemes:  tls12Schemes,
		SupportedVersions: []string{"TLS 1.2"},
		Extensions:        hello.Extensions,
	}
	if !reflect.DeepEqual(hello, wantHello) {
		t.Errorf("TLS 1.2: ClientHello %+v, want %+v", hello, wantHello)
	}
	// server_name, supported_groups, ec_point_formats, signature_algorithms,
	// supported_versions, listing TLS 1.2 alone, and renegotiation_info,
	// among Go's extensions, and no key_share.
	for _, ext := range []uint16{0, 10, 11, 13, 43, 0xff01} {
		if !slices.Contains(hello.Extensions, ext) {
			t.Errorf("TLS 1.2: extensions %v, without %d", hello.Extensions, ext)
		}
	}
	if slices.Contains(hello.Extensions, 51) {
		t.Errorf("TLS 1.2: extensions %v", hello.Extensions)
	}

	// TLS 1.3, the server asking for a P-256 share and verifying a client
	// certificate.
	addr, id = listen(map[string]any{
		"curve_preferences": []string{"CurveP256"},
		"client_auth":       "RequireAndVerifyClientCert",
		"client_cas":        []string{pki["ca"].Cert},
	})
	got = dial(addr, map[string]any{
		"min_version":       "TLS 1.3",
		"curve_preferences": []string{"CurveP256", "X25519"},
		"client_cert":       identity("client"),
	})
	served = tlsListenResultOf(t, id)
	hello = served.ClientHello
	if hello == nil {
		t.Fatal("TLS 1.3: no ClientHello")
	}
	// The client lists the three suites in its own order, AES-GCM first
	// with AES hardware, and a Go server on the same machine takes its
	// first.
	if len(hello.CipherSuites) != 3 || !slices.Equal(slices.Sorted(slices.Values(hello.CipherSuites)), tls13Suites) {
		t.Errorf("TLS 1.3: suites %v", hello.CipherSuites)
	}
	state = tlsState{"TLS 1.3", hello.CipherSuites[0], "CurveP256", true}
	wantDial = tlsDialDetail{OK: true, tlsState: state, HTTPStatus: 200, HTTPBody: `{"result":0}`}
	if !reflect.DeepEqual(got, wantDial) {
		t.Errorf("TLS 1.3: dial %+v, want %+v", got, wantDial)
	}
	served.ClientHello = nil
	wantListen = tlsListenDetail{
		OK: true, tlsState: state,
		PeerCertificates: []string{pki["client"].Cert},
		VerifiedChains:   [][]string{{pki["client"].Cert, pki["ca"].Cert}},
	}
	if !reflect.DeepEqual(served, wantListen) {
		t.Errorf("TLS 1.3: listen %+v, want %+v", served, wantListen)
	}
	wantHello = &tlsClientHello{
		CipherSuites:      hello.CipherSuites,
		SupportedCurves:   []string{"X25519", "CurveP256"},
		SignatureSchemes:  tls13Schemes,
		SupportedVersions: []string{"TLS 1.3"},
		Extensions:        hello.Extensions,
	}
	if !reflect.DeepEqual(hello, wantHello) {
		t.Errorf("TLS 1.3: ClientHello %+v, want %+v", hello, wantHello)
	}
	// supported_groups, signature_algorithms, supported_versions and
	// key_share.
	for _, ext := range []uint16{10, 13, 43, 51} {
		if !slices.Contains(hello.Extensions, ext) {
			t.Errorf("TLS 1.3: extensions %v, without %d", hello.Extensions, ext)
		}
	}

	// Go's defaults on both sides, under dcrd's GODEBUG: all seven groups
	// offered, and X25519MLKEM768 taken.
	addr, id = listen(map[string]any{})
	got = dial(addr, map[string]any{})
	served = tlsListenResultOf(t, id)
	if served.ClientHello == nil || !slices.Equal(served.ClientHello.SupportedCurves, allCurves) {
		t.Errorf("defaults: ClientHello %+v", served.ClientHello)
	}
	if !got.OK || got.Version != "TLS 1.3" || got.CurveID != "X25519MLKEM768" || got.HelloRetryRequest ||
		got.tlsState != served.tlsState || !served.OK {
		t.Errorf("defaults: dial %+v, listen %+v", got, served)
	}

	// A server certificate the client does not trust.
	addr, id = listen(map[string]any{})
	got = dial(addr, map[string]any{"roots": []string{pki["stranger"].Cert}})
	served = tlsListenResultOf(t, id)
	wantDial = tlsDialDetail{
		Error: "tls: failed to verify certificate: x509: certificate signed by unknown authority",
	}
	if !reflect.DeepEqual(got, wantDial) {
		t.Errorf("untrusted server: dial %+v, want %+v", got, wantDial)
	}
	if served.OK || served.Error != "remote error: tls: bad certificate" ||
		served.tlsState != (tlsState{}) || served.ClientHello == nil {
		t.Errorf("untrusted server: listen %+v", served)
	}

	// A client certificate the server refuses, one that has expired: a TLS
	// 1.3 client's handshake is done before the server reads it.
	addr, id = listen(map[string]any{
		"client_auth": "RequireAndVerifyClientCert",
		"client_cas":  []string{pki["ca"].Cert},
	})
	got = dial(addr, map[string]any{"client_cert": identity("expired")})
	served = tlsListenResultOf(t, id)
	if got.OK || got.Error != "remote error: tls: expired certificate" || got.Version != "TLS 1.3" ||
		got.HTTPStatus != 0 || got.HTTPBody != "" {
		t.Errorf("expired client: dial %+v", got)
	}
	if served.OK ||
		!strings.HasPrefix(served.Error, "tls: failed to verify certificate: x509: certificate has expired") ||
		served.tlsState != (tlsState{}) || len(served.VerifiedChains) != 0 {
		t.Errorf("expired client: listen %+v", served)
	}

	// A client that sends no request: its handshake is the whole of
	// tls_dial's connection, and the server finds no request on it.
	addr, id = listen(map[string]any{})
	got = tlsDialOf(t, map[string]any{"addr": addr, "server_name": "localhost", "roots": []string{pki["ca"].Cert}})
	served = tlsListenResultOf(t, id)
	if !got.OK || got.Error != "" || got.Version != "TLS 1.3" || got.HTTPStatus != 0 || got.HTTPBody != "" {
		t.Errorf("no request: dial %+v", got)
	}
	if served.OK || served.Error != "EOF" || served.tlsState != got.tlsState {
		t.Errorf("no request: listen %+v", served)
	}

	// A server nobody dials gives up at its deadline, closing its
	// listener.
	addr, id = listen(map[string]any{"timeout_ms": 200})
	started := time.Now()
	served = tlsListenResultOf(t, id)
	wantListen = tlsListenDetail{PeerCertificates: []string{}, VerifiedChains: [][]string{}}
	if !strings.HasSuffix(served.Error, "i/o timeout") || time.Since(started) > 5*time.Second {
		t.Errorf("nobody dials: listen %+v after %v", served, time.Since(started))
	}
	served.Error = ""
	if !reflect.DeepEqual(served, wantListen) {
		t.Errorf("nobody dials: listen %+v, want %+v", served, wantListen)
	}
	got = dial(addr, map[string]any{})
	if got.OK || !strings.HasSuffix(got.Error, "connect: connection refused") || got.tlsState != (tlsState{}) {
		t.Errorf("a closed port: dial %+v", got)
	}

	// The unspecified address, which the loopback check refuses before
	// anything is dialed; without the check it would reach this machine,
	// which routes the unspecified address to itself.
	unspecified := net.JoinHostPort(net.IPv4zero.String(), "1")
	listening := func(fields map[string]any) map[string]any {
		fields["chain"], fields["key_pkcs8"] = server["chain"], server["key_pkcs8"]
		return fields
	}
	for name, tc := range map[string]struct {
		cmd    string
		fields map[string]any
	}{
		"dial: a host name":                {"tls_dial", map[string]any{"addr": "localhost:1"}},
		"dial: no port":                    {"tls_dial", map[string]any{"addr": "127.0.0.1"}},
		"dial: an address not on loopback": {"tls_dial", map[string]any{"addr": unspecified}},
		"dial: an unknown max_version":     {"tls_dial", map[string]any{"addr": addr, "max_version": "TLS 1.4"}},
		"dial: an unknown min_version":     {"tls_dial", map[string]any{"addr": addr, "min_version": "TLS 1.4"}},
		"dial: an unknown suite":           {"tls_dial", map[string]any{"addr": addr, "cipher_suites": []string{"TLS_RSA_WITH_RC4"}}},
		"dial: a TLS 1.3 suite":            {"tls_dial", map[string]any{"addr": addr, "cipher_suites": []string{"TLS_CHACHA20_POLY1305_SHA256"}}},
		"dial: an unknown curve":           {"tls_dial", map[string]any{"addr": addr, "curve_preferences": []string{"X448"}}},
		"dial: a negative timeout":         {"tls_dial", map[string]any{"addr": addr, "timeout_ms": -1}},
		"dial: too long a timeout":         {"tls_dial", map[string]any{"addr": addr, "timeout_ms": 120001}},
		"dial: a root that is not one":     {"tls_dial", map[string]any{"addr": addr, "roots": []string{"3000"}}},
		"dial: another certificate's key": {"tls_dial", map[string]any{"addr": addr, "request": request, "client_cert": map[string]any{
			"chain": []string{pki["client"].Cert}, "key_pkcs8": pki["server"].KeyPKCS8}}},
		// Each field that is not hex holds a valid value before its bad
		// digit, which hex.DecodeString still returns
		// (encoding/hex/hex.go:132-142), so that only the hex check
		// refuses it.
		"dial: a root that is not hex": {"tls_dial", map[string]any{"addr": addr, "roots": []string{pki["ca"].Cert + "z"}}},
		"dial: a client chain that is not hex": {"tls_dial", map[string]any{"addr": addr, "request": request, "client_cert": map[string]any{
			"chain": []string{pki["client"].Cert + "z"}, "key_pkcs8": pki["client"].KeyPKCS8}}},
		"dial: a client key that is not hex": {"tls_dial", map[string]any{"addr": addr, "request": request, "client_cert": map[string]any{
			"chain": []string{pki["client"].Cert}, "key_pkcs8": pki["client"].KeyPKCS8 + "zz"}}},
		"dial: a client certificate without a request": {"tls_dial", map[string]any{"addr": addr, "client_cert": identity("client")}},
		"dial: a bad request":                          {"tls_dial", map[string]any{"addr": addr, "request": map[string]any{"method": "GET\n", "path": "/"}}},
		"dial: a misspelled field":                     {"tls_dial", map[string]any{"addr": addr, "curves": []string{"CurveP384"}}},
		"listen: no certificate":                       {"tls_listen", map[string]any{}},
		"listen: an unknown min_version":               {"tls_listen", listening(map[string]any{"min_version": "SSLv3"})},
		"listen: an unknown max_version":               {"tls_listen", listening(map[string]any{"max_version": "TLS 1.4"})},
		"listen: an unknown suite":                     {"tls_listen", listening(map[string]any{"cipher_suites": []string{"TLS_RSA_WITH_RC4"}})},
		"listen: a TLS 1.3 suite":                      {"tls_listen", listening(map[string]any{"cipher_suites": []string{"TLS_AES_256_GCM_SHA384"}})},
		"listen: an unknown curve":                     {"tls_listen", listening(map[string]any{"curve_preferences": []string{"X448"}})},
		"listen: too long a timeout":                   {"tls_listen", listening(map[string]any{"timeout_ms": 120001})},
		"listen: a CA that is not one":                 {"tls_listen", listening(map[string]any{"client_cas": []string{"zz"}})},
		"listen: an unknown client_auth":               {"tls_listen", listening(map[string]any{"client_auth": "RequireClientCert"})},
		"listen: a misspelled field":                   {"tls_listen", listening(map[string]any{"client_ca": []string{pki["ca"].Cert}})},
		"result: no id":                                {"tls_listen_result", map[string]any{}},
		"result: an unknown id":                        {"tls_listen_result", map[string]any{"id": id + 1000}},
		"result: one taken":                            {"tls_listen_result", map[string]any{"id": id}},
	} {
		resp := call(tc.cmd, jsonRequest(t, tc.fields))
		if resp.Error == "" || len(resp.Detail) != 0 {
			t.Errorf("%s: got %+v, want an error", name, resp)
		}
	}
	for _, cmd := range []string{"tls_dial", "tls_listen", "tls_listen_result"} {
		if resp := call(cmd, []byte("not JSON")); resp.Error == "" {
			t.Errorf("%s, not JSON: got %+v, want an error", cmd, resp)
		}
	}
	// A result asked for with a field beside the id is refused, and the
	// server's result is still there to take.
	_, id = listen(map[string]any{"timeout_ms": 200})
	if resp := call("tls_listen_result", jsonRequest(t, map[string]any{"id": id, "idx": id})); resp.Error == "" {
		t.Errorf("result: a misspelled field: got %+v, want an error", resp)
	}
	if served = tlsListenResultOf(t, id); !strings.HasSuffix(served.Error, "i/o timeout") {
		t.Errorf("result: after a misspelled field: listen %+v", served)
	}

	tlsListenersMu.Lock()
	left := len(tlsListeners)
	tlsListenersMu.Unlock()
	if left != 0 {
		t.Errorf("%d servers left", left)
	}
}
