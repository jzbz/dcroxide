// Copyright (c) 2026 The dcroxide developers
// Use of this source code is governed by an ISC license that can be found in
// the LICENSE file.

// The TLS commands read a connection's key exchange and HelloRetryRequest
// from crypto/tls's ConnectionState, fields Go 1.25 and Go 1.26 added, and
// this module's go line is go1.24, whose GODEBUG defaults the other
// commands keep. So this file is built by Go 1.26 or later alone, which
// also makes it go1.26 code, and tls_old.go answers the four commands
// with an error under an older Go.

//go:build go1.26

package main

import (
	"bufio"
	"bytes"
	"crypto"
	stdecdsa "crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"
)

// The TLS commands run crypto/tls against a TLS implementation under test,
// on loopback alone: tls_dial dials only a loopback address, and
// tls_listen listens only on 127.0.0.1, on a port the system picks. Every
// accept, handshake, read and write of a connection runs under one
// deadline, the request's timeout_ms from its start, or tlsTimeoutDefault
// when it names none, so no connection outlives its command by more than
// that, and none waits on a peer that never comes.
const (
	tlsTimeoutDefault = 10 * time.Second
	tlsTimeoutMax     = 2 * time.Minute
	// tlsBodyMax caps the HTTP body tls_dial reads.
	tlsBodyMax = 1 << 20
)

// tlsTimeout is a request's timeout_ms as a duration.
func tlsTimeout(ms int64) (time.Duration, error) {
	if ms == 0 {
		return tlsTimeoutDefault, nil
	}
	if ms < 0 || ms > tlsTimeoutMax.Milliseconds() {
		return 0, fmt.Errorf("timeout_ms: %d, not from 1 to %d", ms, tlsTimeoutMax.Milliseconds())
	}
	return time.Duration(ms) * time.Millisecond, nil
}

// tlsVersion is the protocol version tls.VersionName gives name, or 0,
// crypto/tls's default, for "".
func tlsVersion(name string) (uint16, error) {
	if name == "" {
		return 0, nil
	}
	for _, v := range []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13} {
		if tls.VersionName(v) == name {
			return v, nil
		}
	}
	return 0, fmt.Errorf("unknown version %q", name)
}

// tlsDecode reads a TLS command's JSON data into v, refusing a field v does
// not have and anything after the one value. Nearly every field is
// optional, and one left out means crypto/tls's default, the baseline the
// interop tests compare with, so a misspelled field would otherwise run a
// cell on Go's defaults and let it pass for the wrong reason.
func tlsDecode(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("data after the JSON value")
	}
	return nil
}

// tlsCipherSuites are the suites tls.CipherSuiteName gives names, insecure
// ones included, or none, crypto/tls's default, for an empty list. A TLS
// 1.3 suite is refused: crypto/tls offers and takes its own TLS 1.3 suites
// whatever Config.CipherSuites lists (crypto/tls/common.go:730-731), so
// naming one would configure nothing while the answer said it had.
func tlsCipherSuites(names []string) ([]uint16, error) {
	if len(names) == 0 {
		return nil, nil
	}
	known := append(tls.CipherSuites(), tls.InsecureCipherSuites()...)
	ids := make([]uint16, 0, len(names))
	for _, name := range names {
		i := slices.IndexFunc(known, func(s *tls.CipherSuite) bool { return s.Name == name })
		if i < 0 {
			return nil, fmt.Errorf("unknown cipher suite %q", name)
		}
		if slices.Equal(known[i].SupportedVersions, []uint16{tls.VersionTLS13}) {
			return nil, fmt.Errorf("cipher suite %q: crypto/tls does not configure TLS 1.3 suites", name)
		}
		ids = append(ids, known[i].ID)
	}
	return ids, nil
}

// tlsCurves are the key exchanges the TLS commands name by CurveID's
// String: Go's default list from Go 1.26 on (tlssecpmlkem=1), in its order
// (crypto/tls/defaults.go:23-43).
var tlsCurves = []tls.CurveID{
	tls.X25519MLKEM768, tls.SecP256r1MLKEM768, tls.SecP384r1MLKEM1024,
	tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521,
}

// tlsCurvePreferences are the key exchanges names name, or none,
// crypto/tls's default list, for an empty list. crypto/tls keeps each
// configured key exchange it implements, whether or not its default list
// has it, and offers them in its own fixed order
// (crypto/tls/common.go:1281-1308): GODEBUG=tlssecpmlkem=0, which this
// module's go 1.24 line sets, drops the hybrids SecP256r1MLKEM768 and
// SecP384r1MLKEM1024 from the default list only (defaults.go:23-34).
func tlsCurvePreferences(names []string) ([]tls.CurveID, error) {
	if len(names) == 0 {
		return nil, nil
	}
	curves := make([]tls.CurveID, 0, len(names))
	for _, name := range names {
		i := slices.IndexFunc(tlsCurves, func(c tls.CurveID) bool { return c.String() == name })
		if i < 0 {
			return nil, fmt.Errorf("unknown curve %q", name)
		}
		curves = append(curves, tlsCurves[i])
	}
	return curves, nil
}

// tlsClientAuth is the policy tls.ClientAuthType's String gives name, or
// NoClientCert for "".
func tlsClientAuth(name string) (tls.ClientAuthType, error) {
	if name == "" {
		return tls.NoClientCert, nil
	}
	for auth := tls.NoClientCert; auth <= tls.RequireAndVerifyClientCert; auth++ {
		if auth.String() == name {
			return auth, nil
		}
	}
	return 0, fmt.Errorf("unknown client_auth %q", name)
}

// tlsCertPool is a pool of the certificates, each in hex DER, each of
// which x509.ParseCertificate must take. It is never nil, so that no
// command trusts the system's roots: an empty list trusts nothing.
func tlsCertPool(certs []string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	for i, h := range certs {
		der, err := hex.DecodeString(h)
		if err != nil {
			return nil, fmt.Errorf("certificate %d: %v", i, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("certificate %d: %v", i, err)
		}
		pool.AddCert(cert)
	}
	return pool, nil
}

// tlsIdentity is a certificate chain and its key as the TLS commands take
// them: the chain in hex DER, leaf first, and the leaf's key in hex
// PKCS#8.
type tlsIdentity struct {
	Chain    []string `json:"chain"`
	KeyPKCS8 string   `json:"key_pkcs8"`
}

// certificate is the identity as crypto/tls takes it, loaded by
// tls.X509KeyPair, as dcrd loads rpc.cert and rpc.key, so that a key that
// is not the leaf's is refused here and not in a handshake.
func (id *tlsIdentity) certificate() (tls.Certificate, error) {
	var chain []byte
	for i, h := range id.Chain {
		der, err := hex.DecodeString(h)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("chain %d: %v", i, err)
		}
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	key, err := hex.DecodeString(id.KeyPKCS8)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("key_pkcs8: %v", err)
	}
	return tls.X509KeyPair(chain, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
}

// tlsState is what the TLS commands report of a connection: its version,
// cipher suite and key exchange by Go's names, and whether the server
// asked for a key share with a HelloRetryRequest. All four are empty until
// the handshake completes.
type tlsState struct {
	Version           string `json:"version"`
	CipherSuite       string `json:"cipher_suite"`
	CurveID           string `json:"curve_id"`
	HelloRetryRequest bool   `json:"hello_retry_request"`
}

// tlsStateOf is a connection's tlsState.
func tlsStateOf(state tls.ConnectionState) tlsState {
	if !state.HandshakeComplete {
		return tlsState{}
	}
	return tlsState{
		Version:           tls.VersionName(state.Version),
		CipherSuite:       tls.CipherSuiteName(state.CipherSuite),
		CurveID:           state.CurveID.String(),
		HelloRetryRequest: state.HelloRetryRequest,
	}
}

// tlsPKICert is one certificate of a tls_pki request.
type tlsPKICert struct {
	Name      string         `json:"name"`
	Key       string         `json:"key"`
	RSA       *rsaComponents `json:"rsa"`
	Issuer    string         `json:"issuer"`
	SigAlg    string         `json:"sig_alg"`
	CA        bool           `json:"ca"`
	EKU       []string       `json:"eku"`
	DNS       []string       `json:"dns"`
	IP        []string       `json:"ip"`
	NotBefore int64          `json:"not_before"`
	NotAfter  int64          `json:"not_after"`
	Dcrwallet string         `json:"dcrwallet"`
}

// tlsPKIEntry is a certificate tls_pki made, with its key.
type tlsPKIEntry struct {
	Cert     string `json:"cert"`
	CertPEM  string `json:"cert_pem"`
	KeyPKCS8 string `json:"key_pkcs8"`
	KeyPEM   string `json:"key_pem"`
}

// tlsPKIUsages are the extended key usages tls_pki names.
var tlsPKIUsages = map[string]x509.ExtKeyUsage{
	"server_auth": x509.ExtKeyUsageServerAuth,
	"client_auth": x509.ExtKeyUsageClientAuth,
	"any":         x509.ExtKeyUsageAny,
}

// tlsPKIKey is the key a tls_pki certificate is for: one generated here on
// the named curve or of the named ML-DSA parameter set, which is cheap, or
// the caller's RSA key, since one generated here would be slow and, from
// Go 1.26, never the same twice.
func tlsPKIKey(c tlsPKICert) (crypto.Signer, error) {
	if c.RSA != nil {
		if c.Key != "" {
			return nil, errors.New("one of key and rsa")
		}
		return c.RSA.privateKey()
	}
	switch c.Key {
	case "P-256":
		return stdecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P-384":
		return stdecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "P-521":
		return stdecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case "Ed25519":
		_, key, err := ed25519.GenerateKey(rand.Reader)
		return key, err
	}
	if key, ok, err := mldsaGenerateKey(c.Key); ok {
		return key, err
	}
	return nil, fmt.Errorf("unknown key %q", c.Key)
}

// tlsPKITemplate is the template of a tls_pki certificate: the name as its
// common name, a random serial, the validity asked for or from an hour ago
// to a day ahead, explicit basic constraints, digital signature as its key
// usage and certificate signing too for a CA, and the extended key usages,
// DNS names and IP addresses asked for.
func tlsPKITemplate(c tlsPKICert, now time.Time) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial.Add(serial, big.NewInt(1)),
		Subject:               pkix.Name{CommonName: c.Name},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  c.CA,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		DNSNames:              c.DNS,
	}
	if c.NotBefore != 0 {
		template.NotBefore = time.Unix(c.NotBefore, 0)
	}
	if c.NotAfter != 0 {
		template.NotAfter = time.Unix(c.NotAfter, 0)
	}
	if c.CA {
		template.KeyUsage |= x509.KeyUsageCertSign
	}
	for _, name := range c.EKU {
		usage, ok := tlsPKIUsages[name]
		if !ok {
			return nil, fmt.Errorf("unknown eku %q", name)
		}
		template.ExtKeyUsage = append(template.ExtKeyUsage, usage)
	}
	for _, s := range c.IP {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("ip %q: not an address", s)
		}
		template.IPAddresses = append(template.IPAddresses, ip)
	}
	if c.SigAlg != "" {
		alg, err := lookupSigAlgorithm("", c.SigAlg)
		if err != nil {
			return nil, err
		}
		template.SignatureAlgorithm = alg.x509
	}
	return template, nil
}

// tlsPKIDcrwalletEndOfTime is dcrwallet's endOfTime, the latest NotAfter
// its authority takes (rpcserver.go:124-125 at the wallet's pin,
// decred.org/dcrwallet/v5 v5.0.1-0.20261105142009-54b85b336077).
var tlsPKIDcrwalletEndOfTime = time.Date(2049, 12, 31, 23, 59, 59, 0, time.UTC)

// tlsPKIDcrwalletTemplate is the template dcrwallet's --issueclientcert
// makes a certificate from, at the wallet's pin: for "ca" the authority's
// of generateAuthority (rpcserver.go:133-160), self-signed, valid from a
// day ago for ten years capped at endOfTime, with certificate signing as
// its only key usage, explicit basic constraints and no extended key
// usage; for "client" the client certificate's of createSignedClientCert
// (:193-203), valid from a day ago until its authority's NotAfter, with no
// key usage, no extended key usage, no basic constraints and no names. The
// serial is randomX509SerialNumber's, below 2^128 (:118-122), and the
// signature algorithm x509.CreateCertificate's default for the issuer's
// key, as dcrwallet leaves it. Every other field of the request must be
// empty, since dcrwallet sets none of them, but "key", the --tlscurve
// both keys are generated on, and "issuer", which a client must name and
// which must be a "ca" of this request.
func tlsPKIDcrwalletTemplate(c tlsPKICert, issuer *x509.Certificate, now time.Time) (*x509.Certificate, error) {
	if c.RSA != nil || c.SigAlg != "" || c.CA || len(c.EKU) != 0 || len(c.DNS) != 0 || len(c.IP) != 0 ||
		c.NotBefore != 0 || c.NotAfter != 0 {
		return nil, errors.New("dcrwallet: a field dcrwallet's template sets")
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	switch c.Dcrwallet {
	case "ca":
		if c.Issuer != "" {
			return nil, errors.New("dcrwallet: an authority is self-signed")
		}
		validUntil := now.Add(time.Hour * 24 * 365 * 10)
		if validUntil.After(tlsPKIDcrwalletEndOfTime) {
			validUntil = tlsPKIDcrwalletEndOfTime
		}
		return &x509.Certificate{
			SerialNumber: serial,
			Subject: pkix.Name{
				CommonName:         "dcrwallet",
				Organization:       []string{"dcrwallet"},
				OrganizationalUnit: []string{"dcrwallet certificate authority"},
			},
			NotBefore:             now.Add(-time.Hour * 24),
			NotAfter:              validUntil,
			KeyUsage:              x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}, nil
	case "client":
		if issuer == nil {
			return nil, errors.New("dcrwallet: a client certificate's issuer is a dcrwallet authority of this request")
		}
		return &x509.Certificate{
			SerialNumber: serial,
			NotBefore:    now.Add(-time.Hour * 24),
			NotAfter:     issuer.NotAfter,
			Subject: pkix.Name{
				CommonName:         "dcrwallet",
				Organization:       []string{"dcrwallet"},
				OrganizationalUnit: []string{"dcrwallet client certificate"},
			},
		}, nil
	}
	return nil, fmt.Errorf("dcrwallet: unknown template %q", c.Dcrwallet)
}

// tlsPKI answers tls_pki: the certificates in the order given, each signed
// by its issuer, an earlier certificate of the request, or by its own key
// when it names none, with the issuer's signature algorithm sig_alg or
// x509.CreateCertificate's default for the key. Each certificate and key
// comes back in hex DER and in PEM. A certificate naming a dcrwallet
// template is made from it instead (tlsPKIDcrwalletTemplate).
func tlsPKI(data []byte) response {
	var in struct {
		Certs []tlsPKICert `json:"certs"`
	}
	if err := tlsDecode(data, &in); err != nil {
		return errResp("tls_pki: %v", err)
	}
	type made struct {
		cert      *x509.Certificate
		key       crypto.Signer
		dcrwallet string
	}
	byName := make(map[string]made, len(in.Certs))
	out := make(map[string]tlsPKIEntry, len(in.Certs))
	now := time.Now()
	for _, c := range in.Certs {
		if c.Name == "" {
			return errResp("tls_pki: a certificate without a name")
		}
		if _, ok := byName[c.Name]; ok {
			return errResp("tls_pki: %s: named twice", c.Name)
		}
		key, err := tlsPKIKey(c)
		if err != nil {
			return errResp("tls_pki: %s: %v", c.Name, err)
		}
		var template *x509.Certificate
		if c.Dcrwallet != "" {
			var walletCA *x509.Certificate
			if issuer, ok := byName[c.Issuer]; ok && issuer.dcrwallet == "ca" {
				walletCA = issuer.cert
			}
			template, err = tlsPKIDcrwalletTemplate(c, walletCA, now)
		} else {
			template, err = tlsPKITemplate(c, now)
		}
		if err != nil {
			return errResp("tls_pki: %s: %v", c.Name, err)
		}
		parent, parentKey := template, key
		if c.Issuer != "" {
			issuer, ok := byName[c.Issuer]
			if !ok {
				return errResp("tls_pki: %s: issuer %q is not an earlier certificate", c.Name, c.Issuer)
			}
			parent, parentKey = issuer.cert, issuer.key
		}
		der, err := x509.CreateCertificate(rand.Reader, template, parent, key.Public(), parentKey)
		if err != nil {
			return errResp("tls_pki: %s: %v", c.Name, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return errResp("tls_pki: %s: %v", c.Name, err)
		}
		pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return errResp("tls_pki: %s: %v", c.Name, err)
		}
		byName[c.Name] = made{cert, key, c.Dcrwallet}
		out[c.Name] = tlsPKIEntry{
			Cert:     hex.EncodeToString(der),
			CertPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
			KeyPKCS8: hex.EncodeToString(pkcs8),
			KeyPEM:   string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})),
		}
	}
	detail, err := json.Marshal(out)
	if err != nil {
		return errResp("tls_pki: %v", err)
	}
	return response{Detail: detail, GoVersion: runtime.Version()}
}

// tlsRequest is the HTTP request tls_dial sends.
type tlsRequest struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

// tlsDialDetail is tls_dial's answer: whether the handshake and the
// request, when there is one, both succeeded, the first error otherwise,
// the connection's state, the application protocol it negotiated once its
// handshake completed, left out when none was, the signature schemes of
// the server's CertificateRequest by Go's names, as Go's client reads them in
// CertificateRequestInfo.SignatureSchemes, or null when it sent none, and
// the response. In TLS 1.3 that is the list as sent; in TLS 1.2 Go keeps,
// in their order, only the schemes it knows that fit the request's
// certificate types, so an ML-DSA scheme there would not show
// (crypto/tls/handshake_client.go:1251-1271).
type tlsDialDetail struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
	tlsState
	NegotiatedProtocol string   `json:"negotiated_protocol,omitempty"`
	DidResume          bool     `json:"did_resume"`
	CertificateRequest []string `json:"certificate_request"`
	HTTPStatus         int      `json:"http_status"`
	HTTPBody           string   `json:"http_body"`
}

// tlsDial answers tls_dial: one connection to a loopback address by
// crypto/tls's client, configured as the request says and verifying the
// server against the roots given and server_name, then, when the request
// has one, an HTTP/1.1 request over it, closing the connection, and the
// response read. A CertificateRequest's signature schemes are read in
// GetClientCertificate, which then chooses the certificate as crypto/tls
// chooses one without it (crypto/tls/handshake_client.go:1274-1288): the
// client_cert if the request admits it, and none otherwise. A server's
// refusal of a TLS 1.3 client's certificate arrives after the client's
// handshake is done, so it shows as the request's error, and a
// client_cert without a request is refused: its ok would cover the
// client's handshake alone and read a refusal as an acceptance.
func tlsDial(data []byte) response {
	var in struct {
		Addr             string       `json:"addr"`
		ServerName       string       `json:"server_name"`
		Roots            []string     `json:"roots"`
		MinVersion       string       `json:"min_version"`
		MaxVersion       string       `json:"max_version"`
		CipherSuites     []string     `json:"cipher_suites"`
		CurvePreferences []string     `json:"curve_preferences"`
		NextProtos       []string     `json:"next_protos"`
		ClientCert       *tlsIdentity `json:"client_cert"`
		Request          *tlsRequest  `json:"request"`
		TimeoutMS        int64        `json:"timeout_ms"`
	}
	if err := tlsDecode(data, &in); err != nil {
		return errResp("tls_dial: %v", err)
	}
	host, _, err := net.SplitHostPort(in.Addr)
	if err != nil {
		return errResp("tls_dial: addr: %v", err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return errResp("tls_dial: addr %q: not a loopback address", in.Addr)
	}
	timeout, err := tlsTimeout(in.TimeoutMS)
	if err != nil {
		return errResp("tls_dial: %v", err)
	}
	config := &tls.Config{ServerName: in.ServerName, NextProtos: in.NextProtos}
	if config.RootCAs, err = tlsCertPool(in.Roots); err != nil {
		return errResp("tls_dial: roots: %v", err)
	}
	if config.MinVersion, err = tlsVersion(in.MinVersion); err != nil {
		return errResp("tls_dial: min_version: %v", err)
	}
	if config.MaxVersion, err = tlsVersion(in.MaxVersion); err != nil {
		return errResp("tls_dial: max_version: %v", err)
	}
	if config.CipherSuites, err = tlsCipherSuites(in.CipherSuites); err != nil {
		return errResp("tls_dial: cipher_suites: %v", err)
	}
	if config.CurvePreferences, err = tlsCurvePreferences(in.CurvePreferences); err != nil {
		return errResp("tls_dial: curve_preferences: %v", err)
	}
	if in.ClientCert != nil {
		cert, err := in.ClientCert.certificate()
		if err != nil {
			return errResp("tls_dial: client_cert: %v", err)
		}
		config.Certificates = []tls.Certificate{cert}
		if in.Request == nil {
			return errResp("tls_dial: client_cert without a request, which alone shows a TLS 1.3 server's refusal of it")
		}
	}
	var detail tlsDialDetail
	config.GetClientCertificate = func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		detail.CertificateRequest = []string{}
		for _, scheme := range cri.SignatureSchemes {
			detail.CertificateRequest = append(detail.CertificateRequest, scheme.String())
		}
		for i := range config.Certificates {
			if cri.SupportsCertificate(&config.Certificates[i]) == nil {
				return &config.Certificates[i], nil
			}
		}
		return new(tls.Certificate), nil
	}
	var req *http.Request
	if in.Request != nil {
		req, err = http.NewRequest(in.Request.Method, "https://"+in.Addr+in.Request.Path,
			strings.NewReader(in.Request.Body))
		if err != nil {
			return errResp("tls_dial: request: %v", err)
		}
		for name, value := range in.Request.Headers {
			req.Header.Set(name, value)
		}
		req.Close = true
	}

	deadline := time.Now().Add(timeout)
	if err := tlsDialOnce(in.Addr, config, req, deadline, &detail); err != nil {
		detail.Error = err.Error()
	} else {
		detail.OK = true
	}
	out, err := json.Marshal(detail)
	if err != nil {
		return errResp("tls_dial: %v", err)
	}
	return response{Detail: out, GoVersion: runtime.Version()}
}

// tlsDialOnce makes tls_dial's connection, filling detail in as it goes,
// and returns the first error.
func tlsDialOnce(addr string, config *tls.Config, req *http.Request, deadline time.Time, detail *tlsDialDetail) error {
	dialer := net.Dialer{Deadline: deadline}
	raw, err := dialer.Dial("tcp", addr)
	if err != nil {
		return err
	}
	if err := raw.SetDeadline(deadline); err != nil {
		raw.Close()
		return err
	}
	conn := tls.Client(raw, config)
	defer conn.Close()
	err = conn.Handshake()
	state := conn.ConnectionState()
	detail.tlsState = tlsStateOf(state)
	if state.HandshakeComplete {
		detail.NegotiatedProtocol = state.NegotiatedProtocol
	}
	detail.DidResume = state.DidResume
	if err != nil || req == nil {
		return err
	}
	if err := req.Write(conn); err != nil {
		return err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	detail.HTTPStatus = resp.StatusCode
	body, err := io.ReadAll(io.LimitReader(resp.Body, tlsBodyMax))
	detail.HTTPBody = string(body)
	return err
}

// tlsClientHello is a ClientHello as a crypto/tls server's
// ClientHelloInfo shows it (crypto/tls/common.go:444-508): the cipher
// suites, groups, signature schemes and versions by Go's names, in the
// client's order, and the extensions' code points in wire order. A client
// that sends no supported_versions extension gets the versions Go infers
// from its legacy version.
type tlsClientHello struct {
	CipherSuites      []string `json:"cipher_suites"`
	SupportedCurves   []string `json:"supported_curves"`
	SignatureSchemes  []string `json:"signature_schemes"`
	SupportedVersions []string `json:"supported_versions"`
	Extensions        []uint16 `json:"extensions"`
}

// tlsClientHelloOf is chi's tlsClientHello.
func tlsClientHelloOf(chi *tls.ClientHelloInfo) *tlsClientHello {
	hello := &tlsClientHello{
		CipherSuites:      []string{},
		SupportedCurves:   []string{},
		SignatureSchemes:  []string{},
		SupportedVersions: []string{},
		Extensions:        slices.Clone(chi.Extensions),
	}
	for _, id := range chi.CipherSuites {
		hello.CipherSuites = append(hello.CipherSuites, tls.CipherSuiteName(id))
	}
	for _, curve := range chi.SupportedCurves {
		hello.SupportedCurves = append(hello.SupportedCurves, curve.String())
	}
	for _, scheme := range chi.SignatureSchemes {
		hello.SignatureSchemes = append(hello.SignatureSchemes, scheme.String())
	}
	for _, v := range chi.SupportedVersions {
		hello.SupportedVersions = append(hello.SupportedVersions, tls.VersionName(v))
	}
	if hello.Extensions == nil {
		hello.Extensions = []uint16{}
	}
	return hello
}

// tlsListenDetail is tls_listen_result's answer: whether the connection
// was accepted, its handshake completed and its one HTTP request answered,
// the first error otherwise, the connection's state, the application
// protocol it negotiated once its handshake completed, left out when none
// was, the client's certificates and the chains Go verified them to, in
// hex DER, and the client's first ClientHello.
type tlsListenDetail struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
	tlsState
	NegotiatedProtocol string          `json:"negotiated_protocol,omitempty"`
	PeerCertificates   []string        `json:"peer_certificates"`
	VerifiedChains     [][]string      `json:"verified_chains"`
	ClientHello        *tlsClientHello `json:"client_hello"`
}

// tlsListener is a tls_listen server: its detail is written by its
// goroutine alone, and read once done is closed. grpc says whether it
// makes grpc-go's ALPN check after the handshake (tlsGRPCServerHandshake).
type tlsListener struct {
	done   chan struct{}
	detail tlsListenDetail
	grpc   bool
}

// tlsGRPCForbiddenSuites are the suites grpc-go removes from
// tls.CipherSuites() when a configuration names none, those RFC 7540
// Appendix A forbids for HTTP/2 (tls12ForbiddenCipherSuites,
// google.golang.org/grpc v1.83.2 credentials/tls.go:207-217, the version
// dcrwallet's go.mod requires at its pin).
var tlsGRPCForbiddenSuites = []uint16{
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
}

// tlsGRPCDefaults applies to config what grpc-go v1.83.2's
// credentials.NewTLS does to the tls.Config dcrwallet's gRPC listener
// passes it (applyDefaults, credentials/tls.go:236-256): "h2" appended to
// NextProtos unless it is there (internal/credentials/util.go:28-37);
// MinVersion TLS 1.2 when neither bound is set below it; and, when no
// suites are named, tls.CipherSuites() less tlsGRPCForbiddenSuites, which
// leaves the six ECDHE suites with AES-GCM or ChaCha20-Poly1305 for TLS
// 1.2 and drops Go's default ECDHE CBC suites. crypto/tls still orders
// the suites by its own preference (Config.cipherSuites,
// crypto/tls/common.go). NewTLS works on a shallow copy, which changes
// nothing here, where the configuration is the server's alone.
func tlsGRPCDefaults(config *tls.Config) {
	if !slices.Contains(config.NextProtos, "h2") {
		config.NextProtos = append(slices.Clip(config.NextProtos), "h2")
	}
	if config.MinVersion == 0 && (config.MaxVersion == 0 || config.MaxVersion >= tls.VersionTLS12) {
		config.MinVersion = tls.VersionTLS12
	}
	if config.CipherSuites == nil {
		for _, cs := range tls.CipherSuites() {
			if !slices.Contains(tlsGRPCForbiddenSuites, cs.ID) {
				config.CipherSuites = append(config.CipherSuites, cs.ID)
			}
		}
	}
}

// tlsGRPCMissingALPN is the error grpc-go v1.83.2's ServerHandshake
// returns, after closing the connection, for a handshake that negotiated
// no application protocol, with GRPC_ENFORCE_ALPN_ENABLED at its default
// of true (credentials/tls.go:35, :168-185;
// internal/envconfig/envconfig.go:53).
const tlsGRPCMissingALPN = "credentials: cannot check peer: missing selected ALPN property. " +
	"If you upgraded from a grpc-go version earlier than 1.67, your TLS connections may have " +
	"stopped working due to ALPN enforcement. For more details, see: " +
	"https://github.com/grpc/grpc-go/issues/434"

// The servers tls_listen started whose results tls_listen_result has not
// taken, by id.
var (
	tlsListenersMu  sync.Mutex
	tlsListeners    = map[uint64]*tlsListener{}
	tlsListenerNext uint64
)

// tlsListen answers tls_listen: a crypto/tls server configured as the
// request says, listening on 127.0.0.1, which a goroutine serves: one
// connection accepted, its handshake, one HTTP request read and answered
// 200 with response_body, and the connection closed, all within the
// timeout, after which the listener is closed whether or not a client
// came. The server's ClientHelloInfo is taken in GetConfigForClient, which
// crypto/tls calls for the first ClientHello alone
// (crypto/tls/handshake_server.go:166-176), and changes nothing. With grpc
// the configuration is first passed through what grpc-go's
// credentials.NewTLS does to it (tlsGRPCDefaults), and a completed
// handshake that negotiated no protocol is closed as grpc-go's
// ServerHandshake closes it.
func tlsListen(data []byte) response {
	var in struct {
		tlsIdentity
		MinVersion       string   `json:"min_version"`
		MaxVersion       string   `json:"max_version"`
		CipherSuites     []string `json:"cipher_suites"`
		CurvePreferences []string `json:"curve_preferences"`
		NextProtos       []string `json:"next_protos"`
		ClientAuth       string   `json:"client_auth"`
		ClientCAs        []string `json:"client_cas"`
		GRPC             bool     `json:"grpc"`
		ResponseBody     string   `json:"response_body"`
		TimeoutMS        int64    `json:"timeout_ms"`
	}
	if err := tlsDecode(data, &in); err != nil {
		return errResp("tls_listen: %v", err)
	}
	timeout, err := tlsTimeout(in.TimeoutMS)
	if err != nil {
		return errResp("tls_listen: %v", err)
	}
	cert, err := in.tlsIdentity.certificate()
	if err != nil {
		return errResp("tls_listen: %v", err)
	}
	config := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: in.NextProtos}
	if config.MinVersion, err = tlsVersion(in.MinVersion); err != nil {
		return errResp("tls_listen: min_version: %v", err)
	}
	if config.MaxVersion, err = tlsVersion(in.MaxVersion); err != nil {
		return errResp("tls_listen: max_version: %v", err)
	}
	if config.CipherSuites, err = tlsCipherSuites(in.CipherSuites); err != nil {
		return errResp("tls_listen: cipher_suites: %v", err)
	}
	if config.CurvePreferences, err = tlsCurvePreferences(in.CurvePreferences); err != nil {
		return errResp("tls_listen: curve_preferences: %v", err)
	}
	if config.ClientAuth, err = tlsClientAuth(in.ClientAuth); err != nil {
		return errResp("tls_listen: %v", err)
	}
	if config.ClientCAs, err = tlsCertPool(in.ClientCAs); err != nil {
		return errResp("tls_listen: client_cas: %v", err)
	}
	if in.GRPC {
		tlsGRPCDefaults(config)
	}
	l := &tlsListener{
		done:   make(chan struct{}),
		detail: tlsListenDetail{PeerCertificates: []string{}, VerifiedChains: [][]string{}},
		grpc:   in.GRPC,
	}
	config.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		l.detail.ClientHello = tlsClientHelloOf(chi)
		return nil, nil
	}
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return errResp("tls_listen: %v", err)
	}
	tlsListenersMu.Lock()
	id := tlsListenerNext
	tlsListenerNext++
	tlsListeners[id] = l
	tlsListenersMu.Unlock()
	go l.serve(ln, config, in.ResponseBody, time.Now().Add(timeout))
	detail, err := json.Marshal(struct {
		ID uint64 `json:"id"`
	}{id})
	if err != nil {
		return errResp("tls_listen: %v", err)
	}
	return response{Result: ln.Addr().String(), Detail: detail, GoVersion: runtime.Version()}
}

// serve is a tls_listen server's goroutine. Whatever ends it, the
// connection and then the listener are closed before done is.
func (l *tlsListener) serve(ln *net.TCPListener, config *tls.Config, body string, deadline time.Time) {
	defer close(l.done)
	defer ln.Close()
	if err := l.serveOne(ln, config, body, deadline); err != nil {
		l.detail.Error = err.Error()
		return
	}
	l.detail.OK = true
}

// serveOne serves the one connection, filling the detail in as it goes,
// and returns the first error.
func (l *tlsListener) serveOne(ln *net.TCPListener, config *tls.Config, body string, deadline time.Time) error {
	if err := ln.SetDeadline(deadline); err != nil {
		return err
	}
	raw, err := ln.Accept()
	if err != nil {
		return err
	}
	if err := raw.SetDeadline(deadline); err != nil {
		raw.Close()
		return err
	}
	conn := tls.Server(raw, config)
	defer conn.Close()
	err = conn.Handshake()
	state := conn.ConnectionState()
	l.detail.tlsState = tlsStateOf(state)
	if state.HandshakeComplete {
		l.detail.NegotiatedProtocol = state.NegotiatedProtocol
	}
	for _, cert := range state.PeerCertificates {
		l.detail.PeerCertificates = append(l.detail.PeerCertificates, hex.EncodeToString(cert.Raw))
	}
	for _, chain := range state.VerifiedChains {
		var certs []string
		for _, cert := range chain {
			certs = append(certs, hex.EncodeToString(cert.Raw))
		}
		l.detail.VerifiedChains = append(l.detail.VerifiedChains, certs)
	}
	if err != nil {
		return err
	}
	// grpc-go's ServerHandshake: a handshake that negotiated no protocol
	// is closed, which the deferred Close does, with close_notify. grpc-go
	// then reads HTTP/2 over a connection it keeps; this server reads the
	// HTTP/1.1 request tls_dial sends whatever was negotiated, so only the
	// TLS ends are grpc-go's.
	if l.grpc && state.NegotiatedProtocol == "" {
		return errors.New(tlsGRPCMissingALPN)
	}
	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		return err
	}
	if _, err := io.Copy(io.Discard, req.Body); err != nil {
		return err
	}
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": {"application/json"}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Close:         true,
		Request:       req,
	}
	return resp.Write(conn)
}

// tlsListenResult answers tls_listen_result: the detail of the server the
// id names, once its goroutine is done, which its deadline bounds. Each
// result is given once.
func tlsListenResult(data []byte) response {
	var in struct {
		ID *uint64 `json:"id"`
	}
	if err := tlsDecode(data, &in); err != nil {
		return errResp("tls_listen_result: %v", err)
	}
	if in.ID == nil {
		return errResp("tls_listen_result: no id")
	}
	tlsListenersMu.Lock()
	l, ok := tlsListeners[*in.ID]
	delete(tlsListeners, *in.ID)
	tlsListenersMu.Unlock()
	if !ok {
		return errResp("tls_listen_result: no server %d", *in.ID)
	}
	<-l.done
	detail, err := json.Marshal(l.detail)
	if err != nil {
		return errResp("tls_listen_result: %v", err)
	}
	return response{Detail: detail, GoVersion: runtime.Version()}
}
