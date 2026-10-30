// Copyright (c) 2026 The dcroxide developers
// Use of this source code is governed by an ISC license that can be found in
// the LICENSE file.

// Command dcrd-oracle exposes dcrd's reference implementations over a
// line-delimited JSON protocol on stdin/stdout, for dcroxide's vector
// generation and differential tests.
//
// Every dcrd module dependency in go.mod is pinned to the project's parity
// pin, dcrd master 3360ae4d, so the oracle links the code the dcrd binary
// at that commit links: each module sits either at the pin's pseudo-version
// or at a published tag whose source is byte-identical to the pin's. The
// pseudo-versions are not what dcrd's own go.mod requires: it requires
// published releases and builds most of them from the in-tree source through
// replace directives. The tag pins, by contrast, are the very releases it
// requires at 3360ae4d, all but one: blockchain/stake is pinned at v5.0.3, the
// tag its in-tree source matches, where dcrd's go.mod still requires v5.0.2
// and builds the in-tree source in its place. go.mod's header records the rule
// and how each module was placed; dcroxide-testutil's
// the_dcrd_pin_matches_ci_and_the_oracle checks the pseudo-versions against
// the harness pin. Do not bump them independently of a parity-pin move.
//
// Protocol: one JSON object per line in, one per line out, in order. Every
// command takes a single "data" argument holding hex-encoded bytes. A request
// may also carry an "id", an unsigned 64-bit integer that its response echoes,
// so a client keeping several requests in flight can check that each answer
// is the one it expects; a request without an id gets a response without one.
// A line that does not decode as a request, or is longer than 64 MiB, is
// answered in its place with an error carrying no id, and the line after it
// is served as usual. Responses are written out whenever the input holds no
// further complete request, so a client that sends one request and waits has
// its answer at once, and one that sends many gets theirs in few writes. A
// request that panics ends the process, as it always has, once the answers
// ahead of it are written out. Responses carry {"error": "..."} on failure or
// command-specific fields on success:
//
//	blake256           → {"result": "<hex 32-byte digest>"}
//	newhashfromstr     → data is the hex of the string bytes;
//	                     {"result": "<hex 32-byte hash, natural order>"}
//	hash_string        → data is 32 hash bytes; {"result": "<display string>"}
//	msgtx_decode       → {"txid": ..., "witness_hash": ..., "full_hash": ...,
//	                      "reencoded": "<hex>"}
//	blockheader_decode → {"block_hash": ..., "reencoded": "<hex>"}
//	ecdsa_parse_der    → {"result": "<hex 64-byte R||S>"} or
//	                     {"error": ..., "kind": "ErrSig..."}
//	ecdsa_sign         → data is 32-byte privkey, nonzero mod N ||
//	                     32-byte hash; {"result": "<hex DER signature>"}
//	ecdsa_verify       → data is 33-byte compressed pubkey || 32-byte hash ||
//	                     DER signature; {"result": "true"|"false"}
//	ecdsa_verify_raw   → data is key_len(1) || key || 32-byte hash ||
//	                     32-byte r || 32-byte s, the key in any format
//	                     ParsePubKey takes; {"result": "true"|"false"} or
//	                     {"error": ..., "kind": "ErrPubKey..."|
//	                      "ErrSigRTooBig"|"ErrSigSTooBig"}
//	ecdsa_sign_compact → data is compressed(1: 0 or 1) || 32-byte privkey,
//	                     nonzero mod N || 32-byte hash; {"result": "<hex
//	                     65-byte compact signature>"}
//	ecdsa_recover_compact → data is 32-byte hash || compact signature;
//	                     {"result": "<hex pubkey, compressed if the
//	                      signature says so>",
//	                      "was_compressed": "true"|"false"} or
//	                     {"error": ..., "kind": "ErrSig..."|
//	                      "ErrPointNotOnCurve"}
//	pubkey_parse       → {"result": "<hex uncompressed>",
//	                      "compressed": "<hex compressed>"} or
//	                     {"error": ..., "kind": "ErrPubKey..."}
//	schnorr_parse      → {"result": "<hex 64-byte r||s>"} or
//	                     {"error": ..., "kind": "ErrSig..."}
//	schnorr_sign       → data is 32-byte privkey || 32-byte hash;
//	                     {"result": "<hex 64-byte signature>"}
//	schnorr_verify     → data is 33-byte compressed pubkey || 32-byte hash ||
//	                     64-byte signature; {"result": "true"|"false"}
//	schnorr_pubkey_parse → {"result": "<hex compressed>"} or {"error": ...}
//	ed25519_pubkey_parse → {"result": "<hex canonical 32 bytes>"} or
//	                       {"error": ...}
//	ed25519_parse      → {"result": "<hex 64-byte R||S>"} or {"error": ...}
//	ed25519_sign       → data is 32-byte seed || message;
//	                     {"result": "<hex 64-byte sig>",
//	                      "compressed": "<hex pubkey>"}
//	ed25519_verify     → data is 32-byte pubkey || 64-byte raw sig || message;
//	                     R/S are taken raw (no ParseSignature) to expose the
//	                     verify-layer semantics; {"result": "true"|"false"}
//	uint256_op         → data is op(1) || a(32 BE) || b(32 BE) || aux(8 BE);
//	                     {"result": "<hex 32-byte BE>"} for value ops or the
//	                     plain string for bitlen/cmp/text ops (see handler)
//	wire_msg           → data is pver(4 BE) || magic(4 BE) || framed message;
//	                     {"result": "<hex re-encoded frame>",
//	                      "compressed": "<command>"} or
//	                     {"error": ..., "kind": "Err..." when a wire
//	                      MessageError}
//	script_exec        → data is flags(4 BE) || script_version(2 BE) ||
//	                     tx_idx(4 BE) || pkscript_len(4 BE) || pkscript ||
//	                     serialized tx; {"result": "ok"} or
//	                     {"error": ..., "kind": "Err..." when a txscript
//	                      ErrorKind}
//	calc_sighash       → data is hash_type(1) || idx(4 BE) ||
//	                     script_len(4 BE) || script || serialized tx;
//	                     {"result": "<hex 32-byte sighash>"} or
//	                     {"error": ..., "kind": ...}
//	base58_encode      → {"result": "<encoded string>"} (omitted if empty)
//	base58_decode      → data is the string bytes; {"result": "<hex>"}
//	                     (omitted if empty; invalid input decodes empty)
//	base58_check_encode → data is version(2) || payload; {"result": "<str>"}
//	base58_check_decode → data is the string bytes;
//	                     {"result": "<hex version||payload>"} or
//	                     {"error": ..., "kind": "checksum"|"invalid format"}
//	stdaddr_decode     → data is net_len(1) || net name || amount(8 BE) ||
//	                     votefee(8 BE) || revokefee(8 BE) || address bytes;
//	                     {"result": "<hex of canonical address dump>"} or
//	                     {"error": ..., "kind": "Err..."}
//	stdscript_analyze  → data is net_len(1) || net name || version(2 BE) ||
//	                     script; {"result": "<hex of canonical analysis>"}
//	raw_txin_sig       → raw input signature across the three suites;
//	                     see the handler for the field layout
//	sign_tx_output     → full SignTxOutput with explicit key/script DBs;
//	                     see the handler for the field layout
//	tspend_sig         → data is key(32) || serialized tx;
//	                     {"result": "<hex signature script>"}
//	stake_analyze      → data is a serialized tx; {"result": "<hex of the
//	                     canonical stake-analysis dump>"} covering
//	                     DetermineTxType, the six Check* verdicts (error
//	                     kind names), SStx commitment extraction, and
//	                     SSGen vote extraction
//	stake_lottery      → data is n_rand(2 BE) || pool_size(4 BE) ||
//	                     winners(2 BE) || seed; {"result": "<hex dump>"} of
//	                     the PRNG IV, draws, state hashes, and winner
//	                     selection
//	stake_calc_rewards → data is mode(1) || purchase(8 BE) || subsidy(8 BE)
//	                     || n(1) || n*amount(8 BE) || prev header;
//	                     {"result": "<hex of the amounts, one per line>"}
//	stake_create_revocation → CreateRevocationFromTicket; see the handler
//	                     for the field layout; {"result": "<hex tx>"} or
//	                     {"error": ..., "kind": "Err..."}
//	gcs_filter         → build a v1/v2 GCS filter from entries and check
//	                     match verdicts; see the handler for the layout;
//	                     {"result": "<hex dump>"} or {"error", "kind"}
//	gcs_blockcf2       → build the DCP0005 v2 block filter for a block
//	                     given its previous scripts; see the handler for
//	                     the layout; {"result": "<hex dump>"}
//	standalone_merkle  → data is leaf_index(4 BE) || n(4 BE) || n*32-byte
//	                     leaves; {"result": "<hex dump>"} of the merkle
//	                     root, inclusion proof, and verification result
//	standalone_tx_merkle → data is n_regular(2 BE) || length-prefixed
//	                     serialized txs; {"result": "<hex dump>"} of the
//	                     regular, stake, and DCP0005 combined roots
//	standalone_pow     → data is bits(4 BE) || pow_limit(32 BE) ||
//	                     pow hash(32); {"result": "<hex dump>"} of the
//	                     compact conversions, work, and check verdicts
//	standalone_asert   → data is start_bits(4 BE) || pow_limit(32 BE) ||
//	                     target_secs(8) || time_delta(8) ||
//	                     height_delta(8) || half_life(8), all BE;
//	                     {"result": "<8-hex-digit diff bits>"}
//	standalone_subsidy → data is net_len(1) || net || height(8 BE) ||
//	                     voters(2 BE) || variant(1);
//	                     {"result": "<hex dump>"} of every subsidy calc
//	standalone_treasury → data is height(8 BE) || expiry(4 BE) ||
//	                     tvi(8 BE) || mul(8 BE); {"result": "<hex dump>"}
//	                     of the TVI/expiry/window/inside calculations
//	standalone_tx      → data is max_tx_size(8 BE) || serialized tx;
//	                     {"result": "<hex dump>"} of coinbase/treasury
//	                     base identification and the sanity verdict
//	blockheader_powhash → data is a serialized block header;
//	                     {"result": "<hex dump>"} of the v1 (BLAKE-256)
//	                     and v2 (BLAKE3, DCP0011) proof of work hashes
//	chaincfg_dump      → data is the network name bytes ("mainnet",
//	                     "testnet3", "simnet", or "regnet");
//	                     {"result": "<hex of the canonical params dump>"}
//	                     (line format defined by dumpParams below, mirrored
//	                     byte-for-byte by dcroxide's Params::dump)
//	x509_verify_client → data is JSON {"roots": [hex DER], "leaf": hex DER,
//	                     "intermediates": [hex DER], "time": unix seconds};
//	                     the leaf verified as crypto/tls verifies a client
//	                     certificate under RequireAndVerifyClientCert;
//	                     {"result": "ok"} or {"result": "refused: <error>"},
//	                     each with "go_version": runtime.Version()
//	ecdh               → data is JSON {"curve": "X25519"|"P-256"|"P-384"|
//	                     "P-521", "private": hex, "public": hex}; the key
//	                     agreement crypto/tls makes with a peer's key share:
//	                     the private key through crypto/ecdh's
//	                     NewPrivateKey, the share through NewPublicKey, then
//	                     ECDH; {"result": "<hex shared secret>"} or
//	                     {"result": "refused: <error>"}, each with
//	                     "go_version": runtime.Version()
//	x509_key_pair      → data is JSON {"cert_pem": string, "key_pem":
//	                     string}; the pair loaded as crypto/tls's
//	                     X509KeyPair loads a certificate and its key;
//	                     {"result": "ok <key type>"}, the type "ECDSA
//	                     <curve name>", "Ed25519" or "RSA <modulus bits>",
//	                     or {"result": "refused: <error>"}, each with
//	                     "go_version": runtime.Version()
//	sig_sign           → data is JSON {"key_pkcs8": hex | "rsa": {"n",
//	                     "e", "d", "p", "q": hex}, "scheme": name |
//	                     "x509_alg": name, "message": hex, "raw": bool,
//	                     "encoding": "" | "no_null" | "short_padding",
//	                     "salt_len": number}; the signature crypto/tls or
//	                     crypto/x509 makes with the key for the TLS
//	                     signature scheme or x509 signature algorithm of
//	                     that name (tls.SignatureScheme's or
//	                     x509.SignatureAlgorithm's String): ed25519.Sign,
//	                     ecdsa.SignASN1, rsa.SignPKCS1v15 or rsa.SignPSS
//	                     with a salt the hash's length; with "raw", for an
//	                     RSA key, the encoding built by hand and raised to
//	                     d with math/big, "encoding" and "salt_len" making
//	                     it deliberately wrong; {"result": "<hex
//	                     signature>"} with "go_version": runtime.Version()
//	sig_verify         → data is JSON {"spki": hex, "x509_alg": name |
//	                     "tls_scheme": name, "message": hex, "signature":
//	                     hex}; the key through x509.ParsePKIXPublicKey,
//	                     then Certificate.CheckSignature for an x509
//	                     algorithm or crypto/tls's handshake verification
//	                     for a scheme; {"result": "ok"} or {"result":
//	                     "refused: <error>"}, each with "go_version":
//	                     runtime.Version()
//	rsa_keygen         → data is JSON {"bits": number, "e": number}; a
//	                     test-only RSA key of exactly that many bits and
//	                     that public exponent; {"detail": {"n", "e", "d",
//	                     "p", "q": hex}} with "go_version":
//	                     runtime.Version()
//	tls_pki            → data is JSON {"certs": [{"name", "key": "P-256" |
//	                     "P-384" | "P-521" | "Ed25519" | "rsa": {"n",
//	                     "e", "d", "p", "q": hex}, "issuer": name,
//	                     "sig_alg": x509 name, "ca": bool, "eku":
//	                     ["server_auth" | "client_auth" | "any"], "dns":
//	                     [name], "ip": [address], "not_before",
//	                     "not_after": unix seconds}]}; each certificate
//	                     made by x509.CreateCertificate, in order, over
//	                     a key generated here or, for RSA, the caller's;
//	                     {"detail": {name: {"cert", "key_pkcs8": hex,
//	                     "cert_pem", "key_pem": PEM}}} with "go_version":
//	                     runtime.Version()
//	tls_dial           → data is JSON {"addr": loopback host:port,
//	                     "server_name", "roots": [hex DER], "min_version",
//	                     "max_version": tls.VersionName, "cipher_suites":
//	                     [tls.CipherSuiteName of TLS 1.2 or earlier],
//	                     "curve_preferences": [CurveID name],
//	                     "client_cert": {"chain": [hex DER], "key_pkcs8":
//	                     hex}, only with "request": {"method", "path",
//	                     "headers": {name: value}, "body"}, "timeout_ms"};
//	                     one connection by crypto/tls's client, and one
//	                     HTTP request over it, "ok" true only if both
//	                     succeed; {"detail": {"ok", "error", "version",
//	                     "cipher_suite", "curve_id", "hello_retry_request",
//	                     "did_resume", "http_status", "http_body"}} with
//	                     "go_version": runtime.Version()
//	tls_listen         → data is JSON {"chain": [hex DER], "key_pkcs8":
//	                     hex, "min_version", "max_version",
//	                     "cipher_suites", "curve_preferences" as tls_dial
//	                     takes them, "client_auth": tls.ClientAuthType
//	                     name, "client_cas": [hex DER], "response_body",
//	                     "timeout_ms"}; a crypto/tls server on loopback
//	                     that serves one connection in the background;
//	                     {"result": "<host:port>", "detail": {"id"}} with
//	                     "go_version": runtime.Version()
//	tls_listen_result  → data is JSON {"id"}; once that server is done,
//	                     {"detail": {"ok", "error", "version",
//	                     "cipher_suite", "curve_id", "hello_retry_request",
//	                     "peer_certificates", "verified_chains",
//	                     "client_hello": {"cipher_suites",
//	                     "supported_curves", "signature_schemes",
//	                     "supported_versions", "extensions"}}} with
//	                     "go_version": runtime.Version(); each of the four
//	                     TLS commands refuses a field it does not name
//	build_info         → takes no data; {"go_version": runtime.Version(),
//	                      "modules": {"<module path>": "<version>"}} for the
//	                     secp256k1/v4 and edwards/v2 modules linked in
package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdh"
	stdecdsa "crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"math/big"

	"github.com/decred/base58"
	stake "github.com/decred/dcrd/blockchain/stake/v5"
	standalone "github.com/decred/dcrd/blockchain/standalone/v2"
	"github.com/decred/dcrd/chaincfg/chainhash"
	chaincfg "github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/crypto/blake256"
	"github.com/decred/dcrd/dcrec"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/schnorr"
	"github.com/decred/dcrd/dcrutil/v4"
	"github.com/decred/dcrd/gcs/v4"
	"github.com/decred/dcrd/gcs/v4/blockcf2"
	"github.com/decred/dcrd/math/uint256"
	"github.com/decred/dcrd/txscript/v4"
	"github.com/decred/dcrd/txscript/v4/sign"
	"github.com/decred/dcrd/txscript/v4/stdaddr"
	"github.com/decred/dcrd/txscript/v4/stdscript"
	"github.com/decred/dcrd/wire"
)

type request struct {
	ID   *uint64 `json:"id,omitempty"`
	Cmd  string  `json:"cmd"`
	Data string  `json:"data,omitempty"`
}

type response struct {
	ID            *uint64           `json:"id,omitempty"`
	Result        string            `json:"result,omitempty"`
	Error         string            `json:"error,omitempty"`
	Kind          string            `json:"kind,omitempty"`
	Compressed    string            `json:"compressed,omitempty"`
	WasCompressed string            `json:"was_compressed,omitempty"`
	TxID          string            `json:"txid,omitempty"`
	WitnessHash   string            `json:"witness_hash,omitempty"`
	FullHash      string            `json:"full_hash,omitempty"`
	BlockHash     string            `json:"block_hash,omitempty"`
	Reencoded     string            `json:"reencoded,omitempty"`
	GoVersion     string            `json:"go_version,omitempty"`
	Modules       map[string]string `json:"modules,omitempty"`
	Detail        json.RawMessage   `json:"detail,omitempty"`
}

// buildInfoModules are the modules build_info reports: the signature code
// the differential tests compare against.
var buildInfoModules = []string{
	"github.com/decred/dcrd/dcrec/secp256k1/v4",
	"github.com/decred/dcrd/dcrec/edwards/v2",
}

// maxLineBytes caps one request line, newline excluded. A full block travels
// hex-encoded in well under it.
const maxLineBytes = 64 << 20

var errLineTooLong = fmt.Errorf("line exceeds %d bytes", maxLineBytes)

func errResp(format string, args ...any) response {
	return response{Error: fmt.Sprintf(format, args...)}
}

// littleEndianToBigInt interprets 32 little-endian bytes as a big integer,
// like the edwards package's unexported encodedBytesToBigInt.
func littleEndianToBigInt(le []byte) *big.Int {
	be := make([]byte, len(le))
	for i, b := range le {
		be[len(le)-1-i] = b
	}
	return new(big.Int).SetBytes(be)
}

// errKindResp builds an error response carrying the dcrd error kind name
// (e.g. "ErrSigTooShort") when the error wraps a known kind type.
func errKindResp(err error) response {
	resp := response{Error: err.Error()}
	var sigErr ecdsa.Error
	if errors.As(err, &sigErr) {
		resp.Kind = sigErr.Err.Error()
		return resp
	}
	var keyErr secp256k1.Error
	if errors.As(err, &keyErr) {
		resp.Kind = keyErr.Err.Error()
		return resp
	}
	var schnorrErr schnorr.Error
	if errors.As(err, &schnorrErr) {
		resp.Kind = schnorrErr.Err.Error()
		return resp
	}
	var wireErr *wire.MessageError
	if errors.As(err, &wireErr) {
		resp.Kind = wireErr.ErrorCode.String()
		return resp
	}
	var scriptErrKind txscript.ErrorKind
	if errors.As(err, &scriptErrKind) {
		resp.Kind = scriptErrKind.Error()
	}
	return resp
}

func handle(req request) response {
	data, err := hex.DecodeString(req.Data)
	if err != nil {
		return errResp("%s: bad hex argument: %v", req.Cmd, err)
	}

	switch req.Cmd {
	case "blake256":
		digest := blake256.Sum256(data)
		return response{Result: hex.EncodeToString(digest[:])}

	case "newhashfromstr":
		hash, err := chainhash.NewHashFromStr(string(data))
		if err != nil {
			return errResp("%v", err)
		}
		return response{Result: hex.EncodeToString(hash[:])}

	case "hash_string":
		var hash chainhash.Hash
		if err := hash.SetBytes(data); err != nil {
			return errResp("%v", err)
		}
		return response{Result: hash.String()}

	case "msgtx_decode":
		var tx wire.MsgTx
		if err := tx.FromBytes(data); err != nil {
			return errResp("%v", err)
		}
		reencoded, err := tx.Bytes()
		if err != nil {
			return errResp("re-encode: %v", err)
		}
		txid := tx.TxHash()
		witnessHash := tx.TxHashWitness()
		fullHash := tx.TxHashFull()
		return response{
			TxID:        txid.String(),
			WitnessHash: witnessHash.String(),
			FullHash:    fullHash.String(),
			Reencoded:   hex.EncodeToString(reencoded),
		}

	case "blockheader_decode":
		var h wire.BlockHeader
		if err := h.FromBytes(data); err != nil {
			return errResp("%v", err)
		}
		reencoded, err := h.Bytes()
		if err != nil {
			return errResp("re-encode: %v", err)
		}
		blockHash := h.BlockHash()
		return response{
			BlockHash: blockHash.String(),
			Reencoded: hex.EncodeToString(reencoded),
		}

	case "ecdsa_parse_der":
		sig, err := ecdsa.ParseDERSignature(data)
		if err != nil {
			return errKindResp(err)
		}
		r, s := sig.R(), sig.S()
		var buf [64]byte
		r.PutBytesUnchecked(buf[:32])
		s.PutBytesUnchecked(buf[32:])
		return response{Result: hex.EncodeToString(buf[:])}

	case "ecdsa_sign":
		if len(data) != 64 {
			return errResp("ecdsa_sign: want 64 bytes (privkey || hash), got %d",
				len(data))
		}
		// A key that reduces to zero mod N is refused: signRFC6979 never
		// returns for it when the hash reduces to zero as well, since every
		// nonce then gives s = 0, and over any other hash it signs for a
		// public key at the point at infinity.
		privKey := secp256k1.PrivKeyFromBytes(data[:32])
		if privKey.Key.IsZero() {
			return errResp("ecdsa_sign: private key is zero mod N")
		}
		sig := ecdsa.Sign(privKey, data[32:])
		return response{Result: hex.EncodeToString(sig.Serialize())}

	case "ecdsa_verify":
		if len(data) < 33+32 {
			return errResp("ecdsa_verify: want >= 65 bytes, got %d", len(data))
		}
		pubKey, err := secp256k1.ParsePubKey(data[:33])
		if err != nil {
			return errKindResp(err)
		}
		hash := data[33 : 33+32]
		sig, err := ecdsa.ParseDERSignature(data[33+32:])
		if err != nil {
			return errKindResp(err)
		}
		if sig.Verify(hash, pubKey) {
			return response{Result: "true"}
		}
		return response{Result: "false"}

	case "ecdsa_verify_raw":
		// data: key_len(1) || key || hash(32) || r(32) || s(32).  The key
		// takes any format ParsePubKey does, so uncompressed and hybrid
		// keys reach Verify too.  r and s reach it as NewSignature takes
		// them, zero included, so Verify's own range check is what
		// rejects a zero.  dcrd has no verify taking r and s as bytes, so
		// a value at or above N is reported under the kinds
		// ParseDERSignature and RecoverCompact give it, r checked first,
		// rather than reduced or folded into false.
		if len(data) < 1 || len(data) != 1+int(data[0])+32+64 {
			return errResp("ecdsa_verify_raw: want key_len(1) || key || "+
				"96 bytes, got %d bytes", len(data))
		}
		keyLen := int(data[0])
		pubKey, err := secp256k1.ParsePubKey(data[1 : 1+keyLen])
		if err != nil {
			return errKindResp(err)
		}
		rest := data[1+keyLen:]
		var r, s secp256k1.ModNScalar
		if overflow := r.SetByteSlice(rest[32:64]); overflow {
			return errKindResp(ecdsa.Error{Err: ecdsa.ErrSigRTooBig,
				Description: "invalid signature: R >= group order"})
		}
		if overflow := s.SetByteSlice(rest[64:96]); overflow {
			return errKindResp(ecdsa.Error{Err: ecdsa.ErrSigSTooBig,
				Description: "invalid signature: S >= group order"})
		}
		if ecdsa.NewSignature(&r, &s).Verify(rest[:32], pubKey) {
			return response{Result: "true"}
		}
		return response{Result: "false"}

	case "ecdsa_sign_compact":
		// data: compressed(1) || privkey(32) || hash(32).  PrivKeyFromBytes
		// reduces the key mod N, as for ecdsa_sign, where the port rejects
		// a key outside [1, N-1], so callers keep keys in that range.  A
		// key that reduces to zero is refused for ecdsa_sign's reason.
		if len(data) != 1+32+32 {
			return errResp("ecdsa_sign_compact: want 65 bytes "+
				"(compressed || privkey || hash), got %d", len(data))
		}
		if data[0] > 1 {
			return errResp("ecdsa_sign_compact: compressed flag %d is not "+
				"0 or 1", data[0])
		}
		privKey := secp256k1.PrivKeyFromBytes(data[1:33])
		if privKey.Key.IsZero() {
			return errResp("ecdsa_sign_compact: private key is zero mod N")
		}
		sig := ecdsa.SignCompact(privKey, data[33:], data[0] == 1)
		return response{Result: hex.EncodeToString(sig)}

	case "ecdsa_recover_compact":
		// data: hash(32) || compact signature of any length, so a wrong
		// length reaches RecoverCompact's own check.  The key is
		// serialized as dcrd's verifymessage serializes it before
		// hashing it into an address.
		if len(data) < 32 {
			return errResp("ecdsa_recover_compact: want >= 32 bytes "+
				"(hash || sig), got %d", len(data))
		}
		pubKey, wasCompressed, err := ecdsa.RecoverCompact(data[32:], data[:32])
		if err != nil {
			return errKindResp(err)
		}
		serialized := pubKey.SerializeUncompressed()
		if wasCompressed {
			serialized = pubKey.SerializeCompressed()
		}
		return response{
			Result:        hex.EncodeToString(serialized),
			WasCompressed: strconv.FormatBool(wasCompressed),
		}

	case "pubkey_parse":
		pubKey, err := secp256k1.ParsePubKey(data)
		if err != nil {
			return errKindResp(err)
		}
		return response{
			Result:     hex.EncodeToString(pubKey.SerializeUncompressed()),
			Compressed: hex.EncodeToString(pubKey.SerializeCompressed()),
		}

	case "schnorr_parse":
		sig, err := schnorr.ParseSignature(data)
		if err != nil {
			return errKindResp(err)
		}
		return response{Result: hex.EncodeToString(sig.Serialize())}

	case "schnorr_sign":
		if len(data) != 64 {
			return errResp("schnorr_sign: want 64 bytes (privkey || hash), got %d",
				len(data))
		}
		privKey := secp256k1.PrivKeyFromBytes(data[:32])
		sig, err := schnorr.Sign(privKey, data[32:])
		if err != nil {
			return errKindResp(err)
		}
		return response{Result: hex.EncodeToString(sig.Serialize())}

	case "schnorr_verify":
		if len(data) != 33+32+64 {
			return errResp("schnorr_verify: want 129 bytes, got %d", len(data))
		}
		pubKey, err := secp256k1.ParsePubKey(data[:33])
		if err != nil {
			return errKindResp(err)
		}
		sig, err := schnorr.ParseSignature(data[33+32:])
		if err != nil {
			return errKindResp(err)
		}
		if sig.Verify(data[33:33+32], pubKey) {
			return response{Result: "true"}
		}
		return response{Result: "false"}

	case "schnorr_pubkey_parse":
		pubKey, err := schnorr.ParsePubKey(data)
		if err != nil {
			return errKindResp(err)
		}
		return response{Result: hex.EncodeToString(pubKey.SerializeCompressed())}

	case "ed25519_pubkey_parse":
		pubKey, err := edwards.ParsePubKey(data)
		if err != nil {
			return errResp("%v", err)
		}
		return response{Result: hex.EncodeToString(pubKey.Serialize())}

	case "ed25519_parse":
		sig, err := edwards.ParseSignature(data)
		if err != nil {
			return errResp("%v", err)
		}
		return response{Result: hex.EncodeToString(sig.Serialize())}

	case "ed25519_sign":
		if len(data) < 32 {
			return errResp("ed25519_sign: want >= 32 bytes (seed || msg), got %d",
				len(data))
		}
		privKey, pubKey := edwards.PrivKeyFromSecret(data[:32])
		if privKey == nil {
			return errResp("ed25519_sign: bad secret")
		}
		r, s, err := edwards.Sign(privKey, data[32:])
		if err != nil {
			return errResp("%v", err)
		}
		sig := edwards.NewSignature(r, s)
		return response{
			Result:     hex.EncodeToString(sig.Serialize()),
			Compressed: hex.EncodeToString(pubKey.Serialize()),
		}

	case "ed25519_verify":
		if len(data) < 32+64 {
			return errResp("ed25519_verify: want >= 96 bytes, got %d", len(data))
		}
		pubKey, err := edwards.ParsePubKey(data[:32])
		if err != nil {
			return errResp("%v", err)
		}
		// R and S are taken from the raw bytes without ParseSignature,
		// exposing the verify-layer (agl) semantics for differential
		// testing; consensus always parses first.
		r := littleEndianToBigInt(data[32 : 32+32])
		s := littleEndianToBigInt(data[64 : 64+32])
		if edwards.Verify(pubKey, data[96:], r, s) {
			return response{Result: "true"}
		}
		return response{Result: "false"}

	case "uint256_op":
		if len(data) != 1+32+32+8 {
			return errResp("uint256_op: want 73 bytes, got %d", len(data))
		}
		op := data[0]
		var aBytes, bBytes [32]byte
		copy(aBytes[:], data[1:33])
		copy(bBytes[:], data[33:65])
		a := new(uint256.Uint256).SetBytes(&aBytes)
		b := new(uint256.Uint256).SetBytes(&bBytes)
		var aux uint64
		for _, by := range data[65:73] {
			aux = aux<<8 | uint64(by)
		}

		hexResult := func(n *uint256.Uint256) response {
			nb := n.Bytes()
			return response{Result: hex.EncodeToString(nb[:])}
		}
		switch op {
		case 0:
			return hexResult(a.Add(b))
		case 1:
			return hexResult(a.Sub(b))
		case 2:
			return hexResult(a.Mul(b))
		case 3:
			if b.IsZero() {
				return errResp("uint256_op: division by zero")
			}
			return hexResult(a.Div(b))
		case 4:
			return hexResult(a.Square())
		case 5:
			return hexResult(a.Negate())
		case 6:
			return hexResult(a.Not())
		case 7:
			return hexResult(a.And(b))
		case 8:
			return hexResult(a.Or(b))
		case 9:
			return hexResult(a.Xor(b))
		case 10:
			return hexResult(a.Lsh(uint32(aux)))
		case 11:
			return hexResult(a.Rsh(uint32(aux)))
		case 12:
			return response{Result: fmt.Sprintf("%d", a.BitLen())}
		case 13:
			return response{Result: fmt.Sprintf("%d", a.Cmp(b))}
		case 14:
			return response{Result: a.Text(uint256.OutputBaseBinary)}
		case 15:
			return response{Result: a.Text(uint256.OutputBaseOctal)}
		case 16:
			return response{Result: a.Text(uint256.OutputBaseDecimal)}
		case 17:
			return response{Result: a.Text(uint256.OutputBaseHex)}
		case 18:
			return hexResult(a.AddUint64(aux))
		case 19:
			return hexResult(a.SubUint64(aux))
		case 20:
			return hexResult(a.MulUint64(aux))
		case 21:
			if aux == 0 {
				return errResp("uint256_op: division by zero")
			}
			return hexResult(a.DivUint64(aux))
		default:
			return errResp("uint256_op: unknown op %d", op)
		}

	case "wire_msg":
		if len(data) < 8 {
			return errResp("wire_msg: want >= 8 bytes, got %d", len(data))
		}
		pver := binary.BigEndian.Uint32(data[0:4])
		net := wire.CurrencyNet(binary.BigEndian.Uint32(data[4:8]))
		msg, _, err := wire.ReadMessage(bytes.NewReader(data[8:]), pver, net)
		if err != nil {
			return errKindResp(err)
		}
		var buf bytes.Buffer
		if err := wire.WriteMessage(&buf, msg, pver, net); err != nil {
			return errKindResp(err)
		}
		return response{
			Result:     hex.EncodeToString(buf.Bytes()),
			Compressed: msg.Command(),
		}

	case "script_exec":
		// data: flags(4 BE) || script_version(2 BE) || tx_idx(4 BE) ||
		//       pkscript_len(4 BE) || pkscript || serialized tx
		if len(data) < 14 {
			return errResp("script_exec: want >= 14 bytes, got %d", len(data))
		}
		flags := txscript.ScriptFlags(binary.BigEndian.Uint32(data[0:4]))
		scriptVersion := binary.BigEndian.Uint16(data[4:6])
		txIdx := int(binary.BigEndian.Uint32(data[6:10]))
		pkLen := int(binary.BigEndian.Uint32(data[10:14]))
		if len(data) < 14+pkLen {
			return errResp("script_exec: truncated pkscript")
		}
		pkScript := data[14 : 14+pkLen]
		var tx wire.MsgTx
		if err := tx.Deserialize(bytes.NewReader(data[14+pkLen:])); err != nil {
			return errResp("script_exec: bad tx: %v", err)
		}
		vm, err := txscript.NewEngine(pkScript, &tx, txIdx, flags,
			scriptVersion, nil)
		if err == nil {
			err = vm.Execute()
		}
		if err != nil {
			return errKindResp(err)
		}
		return response{Result: "ok"}

	case "calc_sighash":
		// data: hash_type(1) || idx(4 BE) || script_len(4 BE) || script ||
		//       serialized tx
		if len(data) < 9 {
			return errResp("calc_sighash: want >= 9 bytes, got %d", len(data))
		}
		hashType := txscript.SigHashType(data[0])
		idx := int(binary.BigEndian.Uint32(data[1:5]))
		scriptLen := int(binary.BigEndian.Uint32(data[5:9]))
		if len(data) < 9+scriptLen {
			return errResp("calc_sighash: truncated script")
		}
		script := data[9 : 9+scriptLen]
		var tx wire.MsgTx
		if err := tx.Deserialize(bytes.NewReader(data[9+scriptLen:])); err != nil {
			return errResp("calc_sighash: bad tx: %v", err)
		}
		hash, err := txscript.CalcSignatureHash(script, hashType, &tx, idx, nil)
		if err != nil {
			return errKindResp(err)
		}
		return response{Result: hex.EncodeToString(hash)}

	case "base58_encode":
		return response{Result: base58.Encode(data)}

	case "base58_decode":
		return response{Result: hex.EncodeToString(base58.Decode(string(data)))}

	case "base58_check_encode":
		if len(data) < 2 {
			return errResp("base58_check_encode: want >= 2 bytes")
		}
		var version [2]byte
		copy(version[:], data[0:2])
		return response{Result: base58.CheckEncode(data[2:], version)}

	case "base58_check_decode":
		payload, version, err := base58.CheckDecode(string(data))
		if err != nil {
			resp := response{Error: err.Error()}
			if errors.Is(err, base58.ErrChecksum) {
				resp.Kind = "checksum"
			} else {
				resp.Kind = "invalid format"
			}
			return resp
		}
		return response{Result: hex.EncodeToString(append(version[:], payload...))}

	case "stdaddr_decode":
		// data: net_len(1) || net name || amount(8 BE) || votefee(8 BE) ||
		//       revokefee(8 BE) || address string bytes
		if len(data) < 1 {
			return errResp("stdaddr_decode: empty request")
		}
		netLen := int(data[0])
		if len(data) < 1+netLen+24 {
			return errResp("stdaddr_decode: truncated request")
		}
		params, err := netParams(string(data[1 : 1+netLen]))
		if err != nil {
			return errResp("stdaddr_decode: %v", err)
		}
		rest := data[1+netLen:]
		amount := int64(binary.BigEndian.Uint64(rest[0:8]))   // nolint:gosec
		voteFee := int64(binary.BigEndian.Uint64(rest[8:16])) // nolint:gosec
		revokeFee := int64(binary.BigEndian.Uint64(rest[16:24]))
		addrStr := string(rest[24:])
		addr, err := stdaddr.DecodeAddress(addrStr, params)
		if err != nil {
			var kindErr stdaddr.ErrorKind
			resp := response{Error: err.Error()}
			if errors.As(err, &kindErr) {
				resp.Kind = kindErr.Error()
			}
			return resp
		}
		return response{Result: hex.EncodeToString([]byte(dumpStdAddr(addr,
			amount, voteFee, revokeFee)))}

	case "stdscript_analyze":
		// data: net_len(1) || net name || version(2 BE) || script
		if len(data) < 1 {
			return errResp("stdscript_analyze: empty request")
		}
		netLen := int(data[0])
		if len(data) < 1+netLen+2 {
			return errResp("stdscript_analyze: truncated request")
		}
		params, err := netParams(string(data[1 : 1+netLen]))
		if err != nil {
			return errResp("stdscript_analyze: %v", err)
		}
		version := binary.BigEndian.Uint16(data[1+netLen : 3+netLen])
		script := data[3+netLen:]
		var w strings.Builder
		scriptType, addrs := stdscript.ExtractAddrs(version, script, params)
		fmt.Fprintf(&w, "type=%s\n", scriptType)
		fmt.Fprintf(&w, "determined=%s\n", stdscript.DetermineScriptType(version, script))
		fmt.Fprintf(&w, "reqsigs=%d\n", stdscript.DetermineRequiredSigs(version, script))
		for _, addr := range addrs {
			fmt.Fprintf(&w, "addr=%T %s\n", addr, addr.String())
		}
		if pushes := stdscript.ExtractAtomicSwapDataPushesV0(script); version == 0 && pushes != nil {
			fmt.Fprintf(&w, "atomicswap=%x %x %x %d %d\n", pushes.RecipientHash160,
				pushes.RefundHash160, pushes.SecretHash, pushes.SecretSize,
				pushes.LockTime)
		}
		return response{Result: hex.EncodeToString([]byte(w.String()))}

	case "raw_txin_sig":
		// data: sig_type(1) || hash_type(1) || idx(4 BE) || key_len(1) ||
		//       key || sub_len(4 BE) || subscript || serialized tx
		if len(data) < 7 {
			return errResp("raw_txin_sig: truncated request")
		}
		sigType := dcrec.SignatureType(data[0])
		hashType := txscript.SigHashType(data[1])
		idx := int(binary.BigEndian.Uint32(data[2:6]))
		keyLen := int(data[6])
		if len(data) < 7+keyLen+4 {
			return errResp("raw_txin_sig: truncated key")
		}
		key := data[7 : 7+keyLen]
		rest := data[7+keyLen:]
		subLen := int(binary.BigEndian.Uint32(rest[0:4]))
		if len(rest) < 4+subLen {
			return errResp("raw_txin_sig: truncated subscript")
		}
		subScript := rest[4 : 4+subLen]
		var tx wire.MsgTx
		if err := tx.Deserialize(bytes.NewReader(rest[4+subLen:])); err != nil {
			return errResp("raw_txin_sig: bad tx: %v", err)
		}
		sig, err := sign.RawTxInSignature(&tx, idx, subScript, hashType, key,
			sigType)
		if err != nil {
			return response{Error: err.Error()}
		}
		return response{Result: hex.EncodeToString(sig)}

	case "sign_tx_output":
		// data: net_len(1) || net || hash_type(1) || treasury(1) ||
		//       idx(4 BE) || pk_len(4 BE) || pkscript || prev_len(4 BE) ||
		//       prevscript || nkeys(1) || per key: addr_len(1) || addr ||
		//       sigtype(1) || compressed(1) || key_len(1) || key ||
		//       nscripts(1) || per script: addr_len(1) || addr ||
		//       slen(2 BE) || script || serialized tx
		//       (key_len lets Ed25519 keys travel in their 64-byte
		//       seed || pubkey form)
		if len(data) < 1 {
			return errResp("sign_tx_output: empty request")
		}
		netLen := int(data[0])
		if len(data) < 1+netLen+10 {
			return errResp("sign_tx_output: truncated request")
		}
		params, err := netParams(string(data[1 : 1+netLen]))
		if err != nil {
			return errResp("sign_tx_output: %v", err)
		}
		rest := data[1+netLen:]
		hashType := txscript.SigHashType(rest[0])
		isTreasuryEnabled := rest[1] != 0
		idx := int(binary.BigEndian.Uint32(rest[2:6]))
		pkLen := int(binary.BigEndian.Uint32(rest[6:10]))
		rest = rest[10:]
		if len(rest) < pkLen+4 {
			return errResp("sign_tx_output: truncated pkscript")
		}
		pkScript := rest[:pkLen]
		prevLen := int(binary.BigEndian.Uint32(rest[pkLen : pkLen+4]))
		rest = rest[pkLen+4:]
		if len(rest) < prevLen+1 {
			return errResp("sign_tx_output: truncated prevscript")
		}
		prevScript := rest[:prevLen]
		rest = rest[prevLen:]

		type keyEntry struct {
			key        []byte
			sigType    dcrec.SignatureType
			compressed bool
		}
		keys := make(map[string]keyEntry)
		nKeys := int(rest[0])
		rest = rest[1:]
		for i := 0; i < nKeys; i++ {
			if len(rest) < 1 {
				return errResp("sign_tx_output: truncated key entry")
			}
			addrLen := int(rest[0])
			if len(rest) < 1+addrLen+3 {
				return errResp("sign_tx_output: truncated key entry")
			}
			addr := string(rest[1 : 1+addrLen])
			sigType := dcrec.SignatureType(rest[1+addrLen])
			compressed := rest[2+addrLen] != 0
			keyLen := int(rest[3+addrLen])
			if len(rest) < 4+addrLen+keyLen {
				return errResp("sign_tx_output: truncated key")
			}
			key := rest[4+addrLen : 4+addrLen+keyLen]
			keys[addr] = keyEntry{key: key, sigType: sigType, compressed: compressed}
			rest = rest[4+addrLen+keyLen:]
		}

		scripts := make(map[string][]byte)
		if len(rest) < 1 {
			return errResp("sign_tx_output: truncated script db")
		}
		nScripts := int(rest[0])
		rest = rest[1:]
		for i := 0; i < nScripts; i++ {
			if len(rest) < 1 {
				return errResp("sign_tx_output: truncated script entry")
			}
			addrLen := int(rest[0])
			if len(rest) < 1+addrLen+2 {
				return errResp("sign_tx_output: truncated script entry")
			}
			addr := string(rest[1 : 1+addrLen])
			sLen := int(binary.BigEndian.Uint16(rest[1+addrLen : 3+addrLen]))
			if len(rest) < 3+addrLen+sLen {
				return errResp("sign_tx_output: truncated script entry")
			}
			scripts[addr] = rest[3+addrLen : 3+addrLen+sLen]
			rest = rest[3+addrLen+sLen:]
		}

		var tx wire.MsgTx
		if err := tx.Deserialize(bytes.NewReader(rest)); err != nil {
			return errResp("sign_tx_output: bad tx: %v", err)
		}

		kdb := sign.KeyClosure(func(addr stdaddr.Address) ([]byte,
			dcrec.SignatureType, bool, error) {
			entry, ok := keys[addr.String()]
			if !ok {
				return nil, 0, false, fmt.Errorf("no key for %s", addr)
			}
			return entry.key, entry.sigType, entry.compressed, nil
		})
		sdb := sign.ScriptClosure(func(addr stdaddr.Address) ([]byte, error) {
			script, ok := scripts[addr.String()]
			if !ok {
				return nil, fmt.Errorf("no script for %s", addr)
			}
			return script, nil
		})

		sigScript, err := sign.SignTxOutput(params, &tx, idx, pkScript,
			hashType, kdb, sdb, prevScript, isTreasuryEnabled)
		if err != nil {
			return response{Error: err.Error()}
		}
		return response{Result: hex.EncodeToString(sigScript)}

	case "tspend_sig":
		// data: key(32) || serialized tx
		if len(data) < 32 {
			return errResp("tspend_sig: truncated request")
		}
		var tx wire.MsgTx
		if err := tx.Deserialize(bytes.NewReader(data[32:])); err != nil {
			return errResp("tspend_sig: bad tx: %v", err)
		}
		script, err := sign.TSpendSignatureScript(&tx, data[0:32])
		if err != nil {
			return response{Error: err.Error()}
		}
		return response{Result: hex.EncodeToString(script)}

	case "stake_analyze":
		// data: treasury-agenda flag ignored (checks are format-only in
		// the stake package) — serialized tx.
		var tx wire.MsgTx
		if err := tx.Deserialize(bytes.NewReader(data)); err != nil {
			return errResp("stake_analyze: bad tx: %v", err)
		}
		var w strings.Builder
		fmt.Fprintf(&w, "type=%v\n", int(stake.DetermineTxType(&tx)))
		fmt.Fprintf(&w, "checksstx=%s\n", stakeErrKind(stake.CheckSStx(&tx)))
		votes, ssgenErr := stake.CheckSSGenVotes(&tx)
		fmt.Fprintf(&w, "checkssgen=%s\n", stakeErrKind(ssgenErr))
		fmt.Fprintf(&w, "checkssrtx=%s\n", stakeErrKind(stake.CheckSSRtx(&tx)))
		fmt.Fprintf(&w, "checktadd=%s\n", stakeErrKind(stake.CheckTAdd(&tx)))
		_, _, tspendErr := stake.CheckTSpend(&tx)
		fmt.Fprintf(&w, "checktspend=%s\n", stakeErrKind(tspendErr))
		fmt.Fprintf(&w, "checktreasurybase=%s\n",
			stakeErrKind(stake.CheckTreasuryBase(&tx)))
		if stake.IsSStx(&tx) {
			isP2SH, addrs, amts, changes, rules, limits :=
				stake.TxSStxStakeOutputInfo(&tx)
			for i := range isP2SH {
				fmt.Fprintf(&w, "commit=%t %x %d %d %t %t %d %d\n",
					isP2SH[i], addrs[i], amts[i], changes[i],
					rules[i][0], rules[i][1], limits[i][0], limits[i][1])
			}
		}
		if stake.IsSSGen(&tx) {
			blockHash, height := stake.SSGenBlockVotedOn(&tx)
			fmt.Fprintf(&w, "votedon=%s %d\n", blockHash, height)
			fmt.Fprintf(&w, "votebits=%d\n", stake.SSGenVoteBits(&tx))
			fmt.Fprintf(&w, "voteversion=%d\n", stake.SSGenVersion(&tx))
			for _, v := range votes {
				fmt.Fprintf(&w, "tv=%s %d\n", v.Hash, v.Vote)
			}
		}
		return response{Result: hex.EncodeToString([]byte(w.String()))}

	case "stake_lottery":
		// data: n_rand(2 BE) || pool_size(4 BE) || winners(2 BE) || seed
		if len(data) < 8 {
			return errResp("stake_lottery: truncated request")
		}
		nRand := int(binary.BigEndian.Uint16(data[0:2]))
		poolSize := binary.BigEndian.Uint32(data[2:6])
		winners := binary.BigEndian.Uint16(data[6:8])
		seed := data[8:]
		var w strings.Builder
		fmt.Fprintf(&w, "iv=%s\n", stake.CalcHash256PRNGIV(seed))
		prng := stake.NewHash256PRNG(seed)
		for i := 0; i < nRand; i++ {
			fmt.Fprintf(&w, "rand=%d\n", prng.Hash256Rand())
		}
		fmt.Fprintf(&w, "state=%s\n", prng.StateHash())
		// Winner selection with a fresh PRNG using the same algorithm as
		// dcrd's private findTicketIdxs, expressed via the public
		// UniformRandom (the loop below matches it line for line).
		prng2 := stake.NewHash256PRNG(seed)
		if uint32(winners) <= poolSize {
			picked := make([]int, 0, winners)
			for len(picked) < int(winners) {
				r := int(prng2.UniformRandom(poolSize))
				dup := false
				for _, e := range picked {
					if e == r {
						dup = true
						break
					}
				}
				if !dup {
					picked = append(picked, r)
				}
			}
			for _, idx := range picked {
				fmt.Fprintf(&w, "winner=%d\n", idx)
			}
			fmt.Fprintf(&w, "winstate=%s\n", prng2.StateHash())
		}
		return response{Result: hex.EncodeToString([]byte(w.String()))}

	case "stake_calc_rewards":
		// data: mode(1: 0=vote,1=revocation no-auto,2=revocation auto) ||
		//       purchase(8 BE) || subsidy(8 BE) || n(1) || n*amount(8 BE) ||
		//       prev header bytes
		if len(data) < 18 {
			return errResp("stake_calc_rewards: truncated request")
		}
		mode := data[0]
		purchase := int64(binary.BigEndian.Uint64(data[1:9])) // nolint:gosec
		subsidy := int64(binary.BigEndian.Uint64(data[9:17])) // nolint:gosec
		n := int(data[17])
		if len(data) < 18+n*8 {
			return errResp("stake_calc_rewards: truncated amounts")
		}
		contribs := make([]int64, n)
		for i := 0; i < n; i++ {
			contribs[i] = int64(binary.BigEndian.Uint64(data[18+i*8 : 26+i*8])) // nolint:gosec
		}
		prevHeader := data[18+n*8:]
		var amounts []int64
		switch mode {
		case 0:
			amounts = stake.CalculateRewards(contribs, purchase, subsidy)
		case 1:
			amounts = stake.CalculateRevocationRewards(contribs, purchase,
				prevHeader, false)
		default:
			amounts = stake.CalculateRevocationRewards(contribs, purchase,
				prevHeader, true)
		}
		var w strings.Builder
		for _, amt := range amounts {
			fmt.Fprintf(&w, "%d\n", amt)
		}
		return response{Result: hex.EncodeToString([]byte(w.String()))}

	case "stake_create_revocation":
		// data: net_len(1) || net || fee(8 BE) || version(2 BE) ||
		//       auto(1) || ticket hash(32) || header_len(2 BE) || header ||
		//       serialized ticket tx (for its outputs)
		if len(data) < 1 {
			return errResp("stake_create_revocation: empty request")
		}
		netLen := int(data[0])
		if len(data) < 1+netLen+45 {
			return errResp("stake_create_revocation: truncated request")
		}
		params, err := netParams(string(data[1 : 1+netLen]))
		if err != nil {
			return errResp("stake_create_revocation: %v", err)
		}
		rest := data[1+netLen:]
		fee := int64(binary.BigEndian.Uint64(rest[0:8])) // nolint:gosec
		version := binary.BigEndian.Uint16(rest[8:10])
		auto := rest[10] != 0
		var ticketHash chainhash.Hash
		copy(ticketHash[:], rest[11:43])
		headerLen := int(binary.BigEndian.Uint16(rest[43:45]))
		if len(rest) < 45+headerLen {
			return errResp("stake_create_revocation: truncated header")
		}
		prevHeader := rest[45 : 45+headerLen]
		var ticketTx wire.MsgTx
		if err := ticketTx.Deserialize(bytes.NewReader(rest[45+headerLen:])); err != nil {
			return errResp("stake_create_revocation: bad ticket tx: %v", err)
		}
		minOuts := stake.ConvertToMinimalOutputs(&ticketTx)
		revocation, err := stake.CreateRevocationFromTicket(&ticketHash,
			minOuts, dcrutil.Amount(fee), version, params, prevHeader, auto)
		if err != nil {
			resp := response{Error: err.Error()}
			var kindErr stake.ErrorKind
			if errors.As(err, &kindErr) {
				resp.Kind = kindErr.Error()
			}
			return resp
		}
		var buf bytes.Buffer
		if err := revocation.Serialize(&buf); err != nil {
			return errResp("stake_create_revocation: serialize: %v", err)
		}
		return response{Result: hex.EncodeToString(buf.Bytes())}

	case "gcs_filter":
		// data: version(1) || b(1) || m(8 BE) || key(16) ||
		//       n_entries(4 BE) || n * (len(2 BE) || entry) ||
		//       n_match(4 BE) || n * (len(2 BE) || entry)
		// Dumps the serialized filter, N, hash, per-entry Match
		// verdicts, and the MatchAny verdict.
		if len(data) < 30 {
			return errResp("gcs_filter: truncated request")
		}
		version := data[0]
		bParam := data[1]
		m := binary.BigEndian.Uint64(data[2:10])
		var key [gcs.KeySize]byte
		copy(key[:], data[10:26])
		rest := data[26:]
		readEntries := func() ([][]byte, bool) {
			if len(rest) < 4 {
				return nil, false
			}
			n := int(binary.BigEndian.Uint32(rest[0:4]))
			rest = rest[4:]
			entries := make([][]byte, 0, n)
			for i := 0; i < n; i++ {
				if len(rest) < 2 {
					return nil, false
				}
				entryLen := int(binary.BigEndian.Uint16(rest[0:2]))
				rest = rest[2:]
				if len(rest) < entryLen {
					return nil, false
				}
				entries = append(entries, rest[:entryLen])
				rest = rest[entryLen:]
			}
			return entries, true
		}
		entries, ok := readEntries()
		if !ok {
			return errResp("gcs_filter: truncated entries")
		}
		matchEntries, ok := readEntries()
		if !ok {
			return errResp("gcs_filter: truncated match entries")
		}

		var filterBytes []byte
		var filterN uint32
		var filterHash chainhash.Hash
		matchFn := func([]byte) bool { return false }
		matchAnyFn := func([][]byte) bool { return false }
		switch version {
		case 1:
			f, err := gcs.NewFilterV1(bParam, key, entries)
			if err != nil {
				resp := response{Error: err.Error()}
				var kindErr gcs.ErrorKind
				if errors.As(err, &kindErr) {
					resp.Kind = kindErr.Error()
				}
				return resp
			}
			filterBytes, filterN, filterHash = f.Bytes(), f.N(), f.Hash()
			matchFn = func(d []byte) bool { return f.Match(key, d) }
			matchAnyFn = func(d [][]byte) bool { return f.MatchAny(key, d) }
		case 2:
			f, err := gcs.NewFilterV2(bParam, m, key, entries)
			if err != nil {
				resp := response{Error: err.Error()}
				var kindErr gcs.ErrorKind
				if errors.As(err, &kindErr) {
					resp.Kind = kindErr.Error()
				}
				return resp
			}
			filterBytes, filterN, filterHash = f.Bytes(), f.N(), f.Hash()
			matchFn = func(d []byte) bool { return f.Match(key, d) }
			matchAnyFn = func(d [][]byte) bool { return f.MatchAny(key, d) }
		default:
			return errResp("gcs_filter: bad version %d", version)
		}

		var w strings.Builder
		fmt.Fprintf(&w, "bytes=%x\n", filterBytes)
		fmt.Fprintf(&w, "n=%d\n", filterN)
		fmt.Fprintf(&w, "hash=%s\n", filterHash)
		for _, entry := range matchEntries {
			fmt.Fprintf(&w, "match=%t\n", matchFn(entry))
		}
		fmt.Fprintf(&w, "matchany=%t\n", matchAnyFn(matchEntries))
		return response{Result: hex.EncodeToString([]byte(w.String()))}

	case "gcs_blockcf2":
		// data: n_prev(2 BE) || n * (hash(32) || index(4 BE) || tree(1)
		//       || script_ver(2 BE) || script_len(2 BE) || script) ||
		//       serialized block.  Dumps the filter key, bytes, N, and
		//       hash, or the error.
		if len(data) < 2 {
			return errResp("gcs_blockcf2: truncated request")
		}
		nPrev := int(binary.BigEndian.Uint16(data[0:2]))
		rest := data[2:]
		type prevScript struct {
			version uint16
			script  []byte
		}
		prevs := make(map[wire.OutPoint]prevScript, nPrev)
		for i := 0; i < nPrev; i++ {
			if len(rest) < 41 {
				return errResp("gcs_blockcf2: truncated prev script")
			}
			var op wire.OutPoint
			copy(op.Hash[:], rest[0:32])
			op.Index = binary.BigEndian.Uint32(rest[32:36])
			op.Tree = int8(rest[36])
			ver := binary.BigEndian.Uint16(rest[37:39])
			scriptLen := int(binary.BigEndian.Uint16(rest[39:41]))
			rest = rest[41:]
			if len(rest) < scriptLen {
				return errResp("gcs_blockcf2: truncated prev script data")
			}
			prevs[op] = prevScript{version: ver, script: rest[:scriptLen]}
			rest = rest[scriptLen:]
		}
		var block wire.MsgBlock
		if err := block.Deserialize(bytes.NewReader(rest)); err != nil {
			return errResp("gcs_blockcf2: bad block: %v", err)
		}

		f, err := blockcf2.Regular(&block, prevScripterFunc(func(op *wire.OutPoint) (uint16, []byte, bool) {
			ps, ok := prevs[*op]
			return ps.version, ps.script, ok
		}))
		if err != nil {
			return response{Error: err.Error(), Kind: "PrevScriptError"}
		}
		filterKey := blockcf2.Key(&block.Header.MerkleRoot)
		var w strings.Builder
		fmt.Fprintf(&w, "key=%x\n", filterKey[:])
		fmt.Fprintf(&w, "bytes=%x\n", f.Bytes())
		fmt.Fprintf(&w, "n=%d\n", f.N())
		fmt.Fprintf(&w, "hash=%s\n", f.Hash())
		return response{Result: hex.EncodeToString([]byte(w.String()))}

	case "standalone_merkle":
		// data: leaf_index(4 BE) || n_leaves(4 BE) || n*32-byte leaves.
		// Dumps the merkle root, the inclusion proof for leaf_index, and
		// the proof verification result against the computed root.
		if len(data) < 8 {
			return errResp("standalone_merkle: truncated request")
		}
		leafIndex := binary.BigEndian.Uint32(data[0:4])
		nLeaves := int(binary.BigEndian.Uint32(data[4:8]))
		if len(data) != 8+nLeaves*32 {
			return errResp("standalone_merkle: bad leaf payload")
		}
		leaves := make([]chainhash.Hash, nLeaves)
		for i := 0; i < nLeaves; i++ {
			copy(leaves[i][:], data[8+i*32:40+i*32])
		}
		var w strings.Builder
		root := standalone.CalcMerkleRoot(leaves)
		fmt.Fprintf(&w, "root=%s\n", root)
		proof := standalone.GenerateInclusionProof(leaves, leafIndex)
		for _, h := range proof {
			fmt.Fprintf(&w, "proof=%s\n", h)
		}
		if int(leafIndex) < nLeaves {
			verified := standalone.VerifyInclusionProof(&root,
				&leaves[leafIndex], leafIndex, proof)
			fmt.Fprintf(&w, "verified=%t\n", verified)
		}
		return response{Result: hex.EncodeToString([]byte(w.String()))}

	case "standalone_tx_merkle":
		// data: n_regular(2 BE) || regular txs || stake txs, each tx
		// length-prefixed with 4 BE bytes.  Dumps the individual tx tree
		// roots and the DCP0005 combined root.
		if len(data) < 2 {
			return errResp("standalone_tx_merkle: truncated request")
		}
		nRegular := int(binary.BigEndian.Uint16(data[0:2]))
		rest := data[2:]
		var allTxns []*wire.MsgTx
		for len(rest) > 0 {
			if len(rest) < 4 {
				return errResp("standalone_tx_merkle: truncated tx length")
			}
			txLen := int(binary.BigEndian.Uint32(rest[0:4]))
			if len(rest) < 4+txLen {
				return errResp("standalone_tx_merkle: truncated tx")
			}
			var tx wire.MsgTx
			if err := tx.Deserialize(bytes.NewReader(rest[4 : 4+txLen])); err != nil {
				return errResp("standalone_tx_merkle: bad tx: %v", err)
			}
			allTxns = append(allTxns, &tx)
			rest = rest[4+txLen:]
		}
		if nRegular > len(allTxns) {
			return errResp("standalone_tx_merkle: bad regular count")
		}
		regular, stake := allTxns[:nRegular], allTxns[nRegular:]
		var w strings.Builder
		fmt.Fprintf(&w, "regular=%s\n", standalone.CalcTxTreeMerkleRoot(regular))
		fmt.Fprintf(&w, "stake=%s\n", standalone.CalcTxTreeMerkleRoot(stake))
		fmt.Fprintf(&w, "combined=%s\n",
			standalone.CalcCombinedTxTreeMerkleRoot(regular, stake))
		return response{Result: hex.EncodeToString([]byte(w.String()))}

	case "standalone_pow":
		// data: bits(4 BE) || pow_limit(32 BE) || pow hash(32).  Dumps
		// the compact conversion round trip, work, and the three check
		// functions' verdicts.
		if len(data) != 68 {
			return errResp("standalone_pow: bad request length")
		}
		bits := binary.BigEndian.Uint32(data[0:4])
		powLimit := new(big.Int).SetBytes(data[4:36])
		var powHash chainhash.Hash
		copy(powHash[:], data[36:68])
		var w strings.Builder
		target := standalone.CompactToBig(bits)
		fmt.Fprintf(&w, "target=%s\n", target)
		fmt.Fprintf(&w, "compact=%08x\n", standalone.BigToCompact(target))
		fmt.Fprintf(&w, "work=%s\n", standalone.CalcWork(bits))
		fmt.Fprintf(&w, "hashtobig=%s\n", standalone.HashToBig(&powHash))
		fmt.Fprintf(&w, "range=%s\n",
			standaloneErrKind(standalone.CheckProofOfWorkRange(bits, powLimit)))
		fmt.Fprintf(&w, "hash=%s\n",
			standaloneErrKind(standalone.CheckProofOfWorkHash(&powHash, bits)))
		fmt.Fprintf(&w, "pow=%s\n",
			standaloneErrKind(standalone.CheckProofOfWork(&powHash, bits, powLimit)))
		return response{Result: hex.EncodeToString([]byte(w.String()))}

	case "standalone_asert":
		// data: start_bits(4 BE) || pow_limit(32 BE) ||
		//       target_secs(8 BE) || time_delta(8 BE) ||
		//       height_delta(8 BE) || half_life(8 BE)
		if len(data) != 68 {
			return errResp("standalone_asert: bad request length")
		}
		startBits := binary.BigEndian.Uint32(data[0:4])
		powLimit := new(big.Int).SetBytes(data[4:36])
		targetSecs := int64(binary.BigEndian.Uint64(data[36:44]))  // nolint:gosec
		timeDelta := int64(binary.BigEndian.Uint64(data[44:52]))   // nolint:gosec
		heightDelta := int64(binary.BigEndian.Uint64(data[52:60])) // nolint:gosec
		halfLife := int64(binary.BigEndian.Uint64(data[60:68]))    // nolint:gosec
		diff := standalone.CalcASERTDiff(startBits, powLimit, targetSecs,
			timeDelta, heightDelta, halfLife)
		return response{Result: fmt.Sprintf("%08x", diff)}

	case "standalone_subsidy":
		// data: net_len(1) || net || height(8 BE) || voters(2 BE) ||
		//       variant(1: 0=orig,1=dcp0010,2=dcp0012).  Dumps every
		//       subsidy calculation variant for the height.
		if len(data) < 1 {
			return errResp("standalone_subsidy: empty request")
		}
		netLen := int(data[0])
		if len(data) != 1+netLen+11 {
			return errResp("standalone_subsidy: bad request length")
		}
		params, err := netParams(string(data[1 : 1+netLen]))
		if err != nil {
			return errResp("standalone_subsidy: %v", err)
		}
		rest := data[1+netLen:]
		height := int64(binary.BigEndian.Uint64(rest[0:8])) // nolint:gosec
		voters := binary.BigEndian.Uint16(rest[8:10])
		var variant standalone.SubsidySplitVariant
		switch rest[10] {
		case 1:
			variant = standalone.SSVDCP0010
		case 2:
			variant = standalone.SSVDCP0012
		default:
			variant = standalone.SSVOriginal
		}
		cache := standalone.NewSubsidyCache(params)
		var w strings.Builder
		fmt.Fprintf(&w, "full=%d\n", cache.CalcBlockSubsidy(height))
		fmt.Fprintf(&w, "work=%d\n", cache.CalcWorkSubsidy(height, voters))
		fmt.Fprintf(&w, "workv2f=%d\n", cache.CalcWorkSubsidyV2(height, voters, false))
		fmt.Fprintf(&w, "workv2t=%d\n", cache.CalcWorkSubsidyV2(height, voters, true))
		fmt.Fprintf(&w, "workv3=%d\n", cache.CalcWorkSubsidyV3(height, voters, variant))
		fmt.Fprintf(&w, "vote=%d\n", cache.CalcStakeVoteSubsidy(height))
		fmt.Fprintf(&w, "votev2f=%d\n", cache.CalcStakeVoteSubsidyV2(height, false))
		fmt.Fprintf(&w, "votev2t=%d\n", cache.CalcStakeVoteSubsidyV2(height, true))
		fmt.Fprintf(&w, "votev3=%d\n", cache.CalcStakeVoteSubsidyV3(height, variant))
		fmt.Fprintf(&w, "treasuryf=%d\n", cache.CalcTreasurySubsidy(height, voters, false))
		fmt.Fprintf(&w, "treasuryt=%d\n", cache.CalcTreasurySubsidy(height, voters, true))
		return response{Result: hex.EncodeToString([]byte(w.String()))}

	case "standalone_treasury":
		// data: height(8 BE) || expiry(4 BE) || tvi(8 BE) || mul(8 BE)
		if len(data) != 28 {
			return errResp("standalone_treasury: bad request length")
		}
		height := int64(binary.BigEndian.Uint64(data[0:8])) // nolint:gosec
		expiry := binary.BigEndian.Uint32(data[8:12])
		tvi := binary.BigEndian.Uint64(data[12:20])
		mul := binary.BigEndian.Uint64(data[20:28])
		var w strings.Builder
		fmt.Fprintf(&w, "istvi=%t\n",
			standalone.IsTreasuryVoteInterval(uint64(height), tvi)) // nolint:gosec
		fmt.Fprintf(&w, "expiry=%d\n", standalone.CalcTSpendExpiry(height, tvi, mul))
		start, end, err := standalone.CalcTSpendWindow(expiry, tvi, mul)
		fmt.Fprintf(&w, "window=%s %d %d\n", standaloneErrKind(err), start, end)
		fmt.Fprintf(&w, "inside=%t\n",
			standalone.InsideTSpendWindow(height, expiry, tvi, mul))
		return response{Result: hex.EncodeToString([]byte(w.String()))}

	case "standalone_tx":
		// data: max_tx_size(8 BE) || serialized tx.  Dumps coinbase and
		// treasury base identification plus the sanity check verdict.
		if len(data) < 8 {
			return errResp("standalone_tx: truncated request")
		}
		maxTxSize := binary.BigEndian.Uint64(data[0:8])
		var tx wire.MsgTx
		if err := tx.Deserialize(bytes.NewReader(data[8:])); err != nil {
			return errResp("standalone_tx: bad tx: %v", err)
		}
		var w strings.Builder
		fmt.Fprintf(&w, "coinbasepre=%t\n", standalone.IsCoinBaseTx(&tx, false))
		fmt.Fprintf(&w, "coinbasepost=%t\n", standalone.IsCoinBaseTx(&tx, true))
		fmt.Fprintf(&w, "treasurybase=%t\n", standalone.IsTreasuryBase(&tx))
		fmt.Fprintf(&w, "sanity=%s\n",
			standaloneErrKind(standalone.CheckTransactionSanity(&tx, maxTxSize)))
		return response{Result: hex.EncodeToString([]byte(w.String()))}

	case "blockheader_powhash":
		// data: a serialized 180-byte block header; dumps the v1
		// (BLAKE-256) and v2 (BLAKE3, DCP0011) proof of work hashes.
		var header wire.BlockHeader
		if err := header.Deserialize(bytes.NewReader(data)); err != nil {
			return errResp("blockheader_powhash: bad header: %v", err)
		}
		var w strings.Builder
		fmt.Fprintf(&w, "v1=%s\n", header.PowHashV1())
		fmt.Fprintf(&w, "v2=%s\n", header.PowHashV2())
		return response{Result: hex.EncodeToString([]byte(w.String()))}

	case "chaincfg_dump":
		params, err := netParams(string(data))
		if err != nil {
			return errResp("chaincfg_dump: %v", err)
		}
		dump, err := dumpParams(params)
		if err != nil {
			return errResp("chaincfg_dump: %v", err)
		}
		return response{Result: hex.EncodeToString([]byte(dump))}

	case "x509_verify_client":
		// crypto/tls's processCertsFromClient: the roots in one pool,
		// every certificate sent after the leaf in another, client
		// authentication as the key usage, at the given time.  A root Go
		// cannot parse is skipped, as AppendCertsFromPEM skips it.  The
		// Go version goes with the verdict because x509's chain search
		// is the toolchain's, not dcrd's.
		var in struct {
			Roots         []string `json:"roots"`
			Leaf          string   `json:"leaf"`
			Intermediates []string `json:"intermediates"`
			Time          int64    `json:"time"`
		}
		if err := json.Unmarshal(data, &in); err != nil {
			return errResp("x509_verify_client: %v", err)
		}
		parse := func(h string) (*x509.Certificate, error) {
			der, err := hex.DecodeString(h)
			if err != nil {
				return nil, err
			}
			return x509.ParseCertificate(der)
		}
		roots := x509.NewCertPool()
		for _, h := range in.Roots {
			if cert, err := parse(h); err == nil {
				roots.AddCert(cert)
			}
		}
		leaf, err := parse(in.Leaf)
		if err != nil {
			return errResp("x509_verify_client: leaf: %v", err)
		}
		opts := x509.VerifyOptions{
			Roots:         roots,
			CurrentTime:   time.Unix(in.Time, 0),
			Intermediates: x509.NewCertPool(),
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		for _, h := range in.Intermediates {
			cert, err := parse(h)
			if err != nil {
				return errResp("x509_verify_client: intermediate: %v", err)
			}
			opts.Intermediates.AddCert(cert)
		}
		if _, err := leaf.Verify(opts); err != nil {
			return response{Result: "refused: " + err.Error(), GoVersion: runtime.Version()}
		}
		return response{Result: "ok", GoVersion: runtime.Version()}

	case "ecdh":
		// crypto/tls's agreement with a peer's key share
		// (crypto/tls/key_schedule.go:127-141): the share through the
		// curve's NewPublicKey, then ECDH with the local key, here a
		// given one rather than a generated one.  A private key Go
		// refuses is an error in the request; a share it refuses, or an
		// agreement, is the verdict, with the Go that gave it.
		var in struct {
			Curve   string `json:"curve"`
			Private string `json:"private"`
			Public  string `json:"public"`
		}
		if err := json.Unmarshal(data, &in); err != nil {
			return errResp("ecdh: %v", err)
		}
		var curve ecdh.Curve
		switch in.Curve {
		case "X25519":
			curve = ecdh.X25519()
		case "P-256":
			curve = ecdh.P256()
		case "P-384":
			curve = ecdh.P384()
		case "P-521":
			curve = ecdh.P521()
		default:
			return errResp("ecdh: unknown curve %q", in.Curve)
		}
		private, err := hex.DecodeString(in.Private)
		if err != nil {
			return errResp("ecdh: private: %v", err)
		}
		public, err := hex.DecodeString(in.Public)
		if err != nil {
			return errResp("ecdh: public: %v", err)
		}
		key, err := curve.NewPrivateKey(private)
		if err != nil {
			return errResp("ecdh: private: %v", err)
		}
		peer, err := curve.NewPublicKey(public)
		if err != nil {
			return response{Result: "refused: " + err.Error(), GoVersion: runtime.Version()}
		}
		secret, err := key.ECDH(peer)
		if err != nil {
			return response{Result: "refused: " + err.Error(), GoVersion: runtime.Version()}
		}
		return response{Result: hex.EncodeToString(secret), GoVersion: runtime.Version()}

	case "x509_key_pair":
		// crypto/tls's X509KeyPair, which dcrd loads rpc.cert and rpc.key
		// with (tls.LoadX509KeyPair): the certificate's blocks, the first
		// key block, the key as parsePrivateKey reads it, and the key
		// checked against the certificate.  The key's type goes with the
		// verdict, so that a key read as another type than the caller's
		// shows.
		var in struct {
			CertPEM string `json:"cert_pem"`
			KeyPEM  string `json:"key_pem"`
		}
		if err := json.Unmarshal(data, &in); err != nil {
			return errResp("x509_key_pair: %v", err)
		}
		pair, err := tls.X509KeyPair([]byte(in.CertPEM), []byte(in.KeyPEM))
		if err != nil {
			return response{Result: "refused: " + err.Error(), GoVersion: runtime.Version()}
		}
		var kind string
		switch key := pair.PrivateKey.(type) {
		case *stdecdsa.PrivateKey:
			kind = "ECDSA " + key.Curve.Params().Name
		case ed25519.PrivateKey:
			kind = "Ed25519"
		case *rsa.PrivateKey:
			kind = fmt.Sprintf("RSA %d", key.N.BitLen())
		default:
			return errResp("x509_key_pair: a key of type %T", key)
		}
		return response{Result: "ok " + kind, GoVersion: runtime.Version()}

	case "sig_sign":
		// The signature crypto/tls or crypto/x509 makes with a key for a
		// TLS signature scheme or an x509 signature algorithm, named as
		// tls.SignatureScheme's and x509.SignatureAlgorithm's String name
		// them. Ed25519 signs the message itself, unhashed (directSigning,
		// crypto/tls/auth.go:146), which is ed25519.Sign and deterministic,
		// so a caller can compare its own signature byte for byte; ECDSA
		// signs the digest with ecdsa.SignASN1, and RSA with crypto/rsa's
		// SignPKCS1v15, or SignPSS with a salt the hash's length. An RSA
		// key comes as its components, in hex, from the caller's fixture,
		// since one generated here is never the same twice. With "raw",
		// the RSA encoding is built here by hand and raised to d with
		// math/big, for the keys crypto/rsa will not sign with, an
		// exponent above 2^31 - 1 among them; "encoding" and "salt_len"
		// then give a deliberately wrong PKCS#1 encoding or another PSS
		// salt length. A key Go refuses, or a name not taken here, is an
		// error in the request.
		var in struct {
			KeyPKCS8 string         `json:"key_pkcs8"`
			RSA      *rsaComponents `json:"rsa"`
			Scheme   string         `json:"scheme"`
			X509Alg  string         `json:"x509_alg"`
			Message  string         `json:"message"`
			Raw      bool           `json:"raw"`
			Encoding string         `json:"encoding"`
			SaltLen  *int           `json:"salt_len"`
		}
		if err := json.Unmarshal(data, &in); err != nil {
			return errResp("sig_sign: %v", err)
		}
		alg, err := lookupSigAlgorithm(in.Scheme, in.X509Alg)
		if err != nil {
			return errResp("sig_sign: %v", err)
		}
		message, err := hex.DecodeString(in.Message)
		if err != nil {
			return errResp("sig_sign: message: %v", err)
		}
		if in.Raw {
			if in.RSA == nil || (alg.kind != sigPKCS1v15 && alg.kind != sigPSS) {
				return errResp("sig_sign: raw signs with an RSA key's components alone")
			}
			key, err := in.RSA.values()
			if err != nil {
				return errResp("sig_sign: rsa: %v", err)
			}
			saltLen := alg.hash.Size()
			if in.SaltLen != nil {
				saltLen = *in.SaltLen
			}
			sig, err := rawRSASign(key, alg, message, in.Encoding, saltLen)
			if err != nil {
				return errResp("sig_sign: raw: %v", err)
			}
			return response{Result: hex.EncodeToString(sig), GoVersion: runtime.Version()}
		}
		if in.Encoding != "" || in.SaltLen != nil {
			return errResp("sig_sign: encoding and salt_len go with raw alone")
		}
		var key crypto.Signer
		switch {
		case in.RSA != nil && in.KeyPKCS8 == "":
			priv, err := in.RSA.privateKey()
			if err != nil {
				return errResp("sig_sign: rsa: %v", err)
			}
			key = priv
		case in.RSA == nil && in.KeyPKCS8 != "":
			der, err := hex.DecodeString(in.KeyPKCS8)
			if err != nil {
				return errResp("sig_sign: key_pkcs8: %v", err)
			}
			parsed, err := x509.ParsePKCS8PrivateKey(der)
			if err != nil {
				return errResp("sig_sign: key_pkcs8: %v", err)
			}
			signer, ok := parsed.(crypto.Signer)
			if !ok {
				return errResp("sig_sign: a key of type %T", parsed)
			}
			key = signer
		default:
			return errResp("sig_sign: one of key_pkcs8 and rsa")
		}
		sig, err := signWith(key, alg, message)
		if err != nil {
			return errResp("sig_sign: %v", err)
		}
		return response{Result: hex.EncodeToString(sig), GoVersion: runtime.Version()}

	case "sig_verify":
		// Go's verdict on a signature: the SubjectPublicKeyInfo through
		// x509.ParsePKIXPublicKey, which refuses what Go's certificate
		// parser refuses, then for an x509 signature algorithm
		// Certificate.CheckSignature, as Go checks a certificate's
		// signature, or for a TLS signature scheme what
		// verifyHandshakeSignature does with a handshake's
		// (crypto/tls/auth.go:22-66): ecdsa.VerifyASN1, ed25519.Verify,
		// rsa.VerifyPKCS1v15, or rsa.VerifyPSS with a salt the hash's
		// length. A key Go refuses is a refusal, like a signature.
		var in struct {
			SPKI      string `json:"spki"`
			X509Alg   string `json:"x509_alg"`
			TLSScheme string `json:"tls_scheme"`
			Message   string `json:"message"`
			Signature string `json:"signature"`
		}
		if err := json.Unmarshal(data, &in); err != nil {
			return errResp("sig_verify: %v", err)
		}
		alg, err := lookupSigAlgorithm(in.TLSScheme, in.X509Alg)
		if err != nil {
			return errResp("sig_verify: %v", err)
		}
		spki, err := hex.DecodeString(in.SPKI)
		if err != nil {
			return errResp("sig_verify: spki: %v", err)
		}
		message, err := hex.DecodeString(in.Message)
		if err != nil {
			return errResp("sig_verify: message: %v", err)
		}
		sig, err := hex.DecodeString(in.Signature)
		if err != nil {
			return errResp("sig_verify: signature: %v", err)
		}
		pub, err := x509.ParsePKIXPublicKey(spki)
		if err == nil {
			if in.X509Alg != "" {
				err = (&x509.Certificate{PublicKey: pub}).CheckSignature(alg.x509, message, sig)
			} else {
				err = verifyHandshakeSignature(alg, pub, message, sig)
			}
		}
		if err != nil {
			return response{Result: "refused: " + err.Error(), GoVersion: runtime.Version()}
		}
		return response{Result: "ok", GoVersion: runtime.Version()}

	case "rsa_keygen":
		// A test-only RSA key of exactly "bits" bits and the public
		// exponent "e": primes from crypto/rand.Prime, half the bits each,
		// each with p - 1 coprime to e, and d = e^-1 mod lcm(p - 1, q - 1),
		// as crypto/rsa's own generator computes it
		// (crypto/internal/fips140/rsa/keygen.go:61-79). Unlike
		// rsa.GenerateKey it takes any odd e from 3 up, an exponent
		// crypto/rsa refuses included, and any length from 64 bits, an odd
		// one included. Run once, to make the caller's fixture.
		var in struct {
			Bits int    `json:"bits"`
			E    uint64 `json:"e"`
		}
		if err := json.Unmarshal(data, &in); err != nil {
			return errResp("rsa_keygen: %v", err)
		}
		key, err := rsaKeygen(in.Bits, in.E)
		if err != nil {
			return errResp("rsa_keygen: %v", err)
		}
		detail, err := json.Marshal(key)
		if err != nil {
			return errResp("rsa_keygen: %v", err)
		}
		return response{Detail: detail, GoVersion: runtime.Version()}

	case "tls_pki":
		// Certificates for the TLS interop tests, each made by
		// x509.CreateCertificate as the caller describes it.
		return tlsPKI(data)

	case "tls_dial":
		// One connection by crypto/tls's client to a server under test,
		// and what it negotiated.
		return tlsDial(data)

	case "tls_listen":
		// A crypto/tls server for a client under test, serving one
		// connection in the background while later requests are
		// answered.
		return tlsListen(data)

	case "tls_listen_result":
		// What that server saw, once its connection is done.
		return tlsListenResult(data)

	case "build_info":
		// What a recorded comparison ran against: the toolchain, and the
		// signature modules as the build resolved them.  A replaced module
		// reads "<version> => <replacement path> [<replacement version>]".
		info, ok := debug.ReadBuildInfo()
		if !ok {
			return errResp("build_info: no build information in the binary")
		}
		modules := make(map[string]string, len(buildInfoModules))
		for _, dep := range info.Deps {
			if !slices.Contains(buildInfoModules, dep.Path) {
				continue
			}
			version := dep.Version
			if r := dep.Replace; r != nil {
				version += " => " + r.Path
				if r.Version != "" {
					version += " " + r.Version
				}
			}
			modules[dep.Path] = version
		}
		for _, path := range buildInfoModules {
			if modules[path] == "" {
				return errResp("build_info: no version for %s", path)
			}
		}
		return response{GoVersion: runtime.Version(), Modules: modules}

	default:
		return errResp("unknown cmd: %s", req.Cmd)
	}
}

// sigKind is how a signature is made.
type sigKind int

const (
	sigPKCS1v15 sigKind = iota
	sigPSS
	sigECDSA
	sigEd25519
)

// sigAlgorithm is what a TLS signature scheme or an x509 signature
// algorithm names: how a signature is made, over which hash (none for
// Ed25519, which signs the message itself), and the x509 algorithm when
// one named it.
type sigAlgorithm struct {
	kind sigKind
	hash crypto.Hash
	x509 x509.SignatureAlgorithm
}

// sigSchemes are the TLS signature schemes sig_sign and sig_verify take.
var sigSchemes = map[tls.SignatureScheme]sigAlgorithm{
	tls.PKCS1WithSHA256:        {kind: sigPKCS1v15, hash: crypto.SHA256},
	tls.PKCS1WithSHA384:        {kind: sigPKCS1v15, hash: crypto.SHA384},
	tls.PKCS1WithSHA512:        {kind: sigPKCS1v15, hash: crypto.SHA512},
	tls.PSSWithSHA256:          {kind: sigPSS, hash: crypto.SHA256},
	tls.PSSWithSHA384:          {kind: sigPSS, hash: crypto.SHA384},
	tls.PSSWithSHA512:          {kind: sigPSS, hash: crypto.SHA512},
	tls.ECDSAWithP256AndSHA256: {kind: sigECDSA, hash: crypto.SHA256},
	tls.ECDSAWithP384AndSHA384: {kind: sigECDSA, hash: crypto.SHA384},
	tls.ECDSAWithP521AndSHA512: {kind: sigECDSA, hash: crypto.SHA512},
	tls.Ed25519:                {kind: sigEd25519},
}

// sigX509Algorithms are the x509 signature algorithms sig_sign and
// sig_verify take.
var sigX509Algorithms = map[x509.SignatureAlgorithm]sigAlgorithm{
	x509.SHA256WithRSA:    {kind: sigPKCS1v15, hash: crypto.SHA256},
	x509.SHA384WithRSA:    {kind: sigPKCS1v15, hash: crypto.SHA384},
	x509.SHA512WithRSA:    {kind: sigPKCS1v15, hash: crypto.SHA512},
	x509.SHA256WithRSAPSS: {kind: sigPSS, hash: crypto.SHA256},
	x509.SHA384WithRSAPSS: {kind: sigPSS, hash: crypto.SHA384},
	x509.SHA512WithRSAPSS: {kind: sigPSS, hash: crypto.SHA512},
	x509.ECDSAWithSHA256:  {kind: sigECDSA, hash: crypto.SHA256},
	x509.ECDSAWithSHA384:  {kind: sigECDSA, hash: crypto.SHA384},
	x509.ECDSAWithSHA512:  {kind: sigECDSA, hash: crypto.SHA512},
	x509.PureEd25519:      {kind: sigEd25519},
}

// lookupSigAlgorithm finds the algorithm a TLS signature scheme or an
// x509 signature algorithm names, by its String name; exactly one of the
// two must be given.
func lookupSigAlgorithm(scheme, x509Alg string) (sigAlgorithm, error) {
	switch {
	case scheme != "" && x509Alg == "":
		for s, alg := range sigSchemes {
			if s.String() == scheme {
				return alg, nil
			}
		}
		return sigAlgorithm{}, fmt.Errorf("unknown scheme %q", scheme)
	case x509Alg != "" && scheme == "":
		for a, alg := range sigX509Algorithms {
			if a.String() == x509Alg {
				alg.x509 = a
				return alg, nil
			}
		}
		return sigAlgorithm{}, fmt.Errorf("unknown x509_alg %q", x509Alg)
	}
	return sigAlgorithm{}, errors.New("a TLS signature scheme or an x509 signature algorithm, one of the two")
}

// digestOf is message's digest under hash, or message itself for
// Ed25519's zero hash.
func digestOf(hash crypto.Hash, message []byte) []byte {
	if hash == 0 {
		return message
	}
	h := hash.New()
	h.Write(message)
	return h.Sum(nil)
}

// signWith signs message with key as crypto/tls signs a handshake and
// crypto/x509 a certificate for alg.
func signWith(key crypto.Signer, alg sigAlgorithm, message []byte) ([]byte, error) {
	digest := digestOf(alg.hash, message)
	switch k := key.(type) {
	case ed25519.PrivateKey:
		if alg.kind == sigEd25519 {
			return ed25519.Sign(k, message), nil
		}
	case *stdecdsa.PrivateKey:
		if alg.kind == sigECDSA {
			return stdecdsa.SignASN1(rand.Reader, k, digest)
		}
	case *rsa.PrivateKey:
		switch alg.kind {
		case sigPKCS1v15:
			return rsa.SignPKCS1v15(rand.Reader, k, alg.hash, digest)
		case sigPSS:
			return rsa.SignPSS(rand.Reader, k, alg.hash, digest,
				&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		}
	}
	return nil, fmt.Errorf("a key of type %T for this algorithm", key)
}

// verifyHandshakeSignature is crypto/tls's (crypto/tls/auth.go:22-66) for
// a key x509.ParsePKIXPublicKey gave.
func verifyHandshakeSignature(alg sigAlgorithm, pub crypto.PublicKey, signed, sig []byte) error {
	signed = digestOf(alg.hash, signed)
	switch alg.kind {
	case sigECDSA:
		key, ok := pub.(*stdecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("expected an ECDSA public key, got %T", pub)
		}
		if !stdecdsa.VerifyASN1(key, signed, sig) {
			return errors.New("ECDSA verification failure")
		}
		return nil
	case sigEd25519:
		key, ok := pub.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("expected an Ed25519 public key, got %T", pub)
		}
		if !ed25519.Verify(key, signed, sig) {
			return errors.New("Ed25519 verification failure")
		}
		return nil
	}
	key, ok := pub.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("expected an RSA public key, got %T", pub)
	}
	if alg.kind == sigPSS {
		return rsa.VerifyPSS(key, alg.hash, signed, sig,
			&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	}
	return rsa.VerifyPKCS1v15(key, alg.hash, signed, sig)
}

// rsaComponents is an RSA key as a test fixture holds it: each value in
// big-endian hex.
type rsaComponents struct {
	N string `json:"n"`
	E string `json:"e"`
	D string `json:"d"`
	P string `json:"p"`
	Q string `json:"q"`
}

// rsaValues is an rsaComponents read.
type rsaValues struct {
	n, e, d, p, q *big.Int
}

// values reads the components, each of which must be hex and not empty.
func (c *rsaComponents) values() (rsaValues, error) {
	var v rsaValues
	for _, f := range []struct {
		name, hex string
		dst       **big.Int
	}{{"n", c.N, &v.n}, {"e", c.E, &v.e}, {"d", c.D, &v.d}, {"p", c.P, &v.p}, {"q", c.Q, &v.q}} {
		b, err := hex.DecodeString(f.hex)
		if err != nil || len(b) == 0 {
			return rsaValues{}, fmt.Errorf("%s: not a hex value", f.name)
		}
		*f.dst = new(big.Int).SetBytes(b)
	}
	return v, nil
}

// privateKey is the key as crypto/rsa takes it, after its own checks,
// which refuse an exponent above 2^31 - 1
// (crypto/internal/fips140/rsa/rsa.go:360-362).
func (c *rsaComponents) privateKey() (*rsa.PrivateKey, error) {
	v, err := c.values()
	if err != nil {
		return nil, err
	}
	if !v.e.IsInt64() || v.e.Int64() > int64(^uint(0)>>1) {
		return nil, errors.New("e: wider than an int")
	}
	priv := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: v.n, E: int(v.e.Int64())},
		D:         v.d,
		Primes:    []*big.Int{v.p, v.q},
	}
	if err := priv.Validate(); err != nil {
		return nil, err
	}
	priv.Precompute()
	return priv, nil
}

// pkcs1Prefixes are the DER of a DigestInfo up to its digest, with the
// hash's NULL parameters (RFC 8017 §9.2, note 1).
var pkcs1Prefixes = map[crypto.Hash][]byte{
	crypto.SHA256: {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
		0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384: {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
		0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512: {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
		0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
}

// rawRSASign is an RSA signature made by hand: the encoding of message's
// digest for alg, PKCS#1 v1.5 or PSS, raised to d mod n with math/big, as
// many bytes as the modulus. It signs with any key, crypto/rsa's checks
// aside; the oracle's tests hold it to crypto/rsa on keys both take.
func rawRSASign(key rsaValues, alg sigAlgorithm, message []byte, encoding string, saltLen int) ([]byte, error) {
	k := (key.n.BitLen() + 7) / 8
	digest := digestOf(alg.hash, message)
	var em []byte
	var err error
	if alg.kind == sigPSS {
		if encoding != "" {
			return nil, errors.New("encoding goes with PKCS#1 v1.5 alone")
		}
		em, err = rawPSSEncode(alg.hash, digest, key.n.BitLen()-1, saltLen)
	} else {
		em, err = rawPKCS1v15Encode(alg.hash, digest, k, encoding)
	}
	if err != nil {
		return nil, err
	}
	m := new(big.Int).SetBytes(em)
	if m.Cmp(key.n) >= 0 {
		return nil, errors.New("the encoding is not below the modulus")
	}
	return new(big.Int).Exp(m, key.d, key.n).FillBytes(make([]byte, k)), nil
}

// rawPKCS1v15Encode is EMSA-PKCS1-v1_5 (RFC 8017 §9.2) of k bytes, or for
// encoding "no_null" the same with the hash's AlgorithmIdentifier missing
// its NULL, and for "short_padding" with the block type a byte late, `00
// 00 01 ff ...`, which Wycheproof's ShortPadding cases write.
func rawPKCS1v15Encode(hash crypto.Hash, digest []byte, k int, encoding string) ([]byte, error) {
	prefix, ok := pkcs1Prefixes[hash]
	if !ok {
		return nil, fmt.Errorf("no DigestInfo for %v", hash)
	}
	t := append(append([]byte{}, prefix...), digest...)
	lead := []byte{0x00, 0x01}
	switch encoding {
	case "":
	case "no_null":
		// 30 L 30 L' 06 09 <oid> 05 00 04 hLen, less the 05 00.
		t = append([]byte{0x30, prefix[1] - 2, 0x30, prefix[3] - 2}, prefix[4:15]...)
		t = append(append(t, prefix[17:]...), digest...)
	case "short_padding":
		lead = []byte{0x00, 0x00, 0x01}
	default:
		return nil, fmt.Errorf("unknown encoding %q", encoding)
	}
	pad := k - len(lead) - 1 - len(t)
	if pad < 8 {
		return nil, errors.New("a modulus too short for the encoding")
	}
	em := append(lead, bytes.Repeat([]byte{0xff}, pad)...)
	return append(append(em, 0x00), t...), nil
}

// rawPSSEncode is EMSA-PSS-ENCODE (RFC 8017 §9.1.1) with MGF1 over hash
// and a random salt of saltLen bytes.
func rawPSSEncode(hash crypto.Hash, mHash []byte, emBits, saltLen int) ([]byte, error) {
	hLen := hash.Size()
	emLen := (emBits + 7) / 8
	if saltLen < 0 || emLen < hLen+saltLen+2 {
		return nil, errors.New("a modulus too short for the salt")
	}
	salt := make([]byte, saltLen)
	rand.Read(salt)
	h := hash.New()
	h.Write(make([]byte, 8))
	h.Write(mHash)
	h.Write(salt)
	mPrime := h.Sum(nil)
	db := make([]byte, emLen-hLen-1)
	db[len(db)-saltLen-1] = 0x01
	copy(db[len(db)-saltLen:], salt)
	for i, b := range mgf1(hash, mPrime, len(db)) {
		db[i] ^= b
	}
	db[0] &= 0xff >> (8*emLen - emBits)
	return append(append(db, mPrime...), 0xbc), nil
}

// mgf1 is MGF1 over hash (RFC 8017 §B.2.1): length bytes from seed.
func mgf1(hash crypto.Hash, seed []byte, length int) []byte {
	var out []byte
	for counter := uint32(0); len(out) < length; counter++ {
		h := hash.New()
		h.Write(seed)
		h.Write(binary.BigEndian.AppendUint32(nil, counter))
		out = h.Sum(out)
	}
	return out[:length]
}

// rsaKeygen makes an RSA key of exactly bits bits with the public exponent
// e, as rsa_keygen describes.
func rsaKeygen(bits int, e uint64) (rsaComponents, error) {
	if bits < 64 || bits > 16384 {
		return rsaComponents{}, fmt.Errorf("bits: %d, not from 64 to 16384", bits)
	}
	if e < 3 || e%2 == 0 {
		return rsaComponents{}, fmt.Errorf("e: %d, not odd and from 3", e)
	}
	E := new(big.Int).SetUint64(e)
	one := big.NewInt(1)
	for {
		// crypto/rand.Prime sets each prime's top two bits, so a product
		// of primes of these lengths has bits bits.
		p, err := rand.Prime(rand.Reader, (bits+1)/2)
		if err != nil {
			return rsaComponents{}, err
		}
		q, err := rand.Prime(rand.Reader, bits/2)
		if err != nil {
			return rsaComponents{}, err
		}
		n := new(big.Int).Mul(p, q)
		pm1 := new(big.Int).Sub(p, one)
		qm1 := new(big.Int).Sub(q, one)
		if p.Cmp(q) == 0 || n.BitLen() != bits ||
			new(big.Int).GCD(nil, nil, E, pm1).Cmp(one) != 0 ||
			new(big.Int).GCD(nil, nil, E, qm1).Cmp(one) != 0 {
			continue
		}
		lcm := new(big.Int).Mul(pm1, qm1)
		lcm.Div(lcm, new(big.Int).GCD(nil, nil, pm1, qm1))
		d := new(big.Int).ModInverse(E, lcm)
		if d == nil {
			continue
		}
		return rsaComponents{
			N: hex.EncodeToString(n.Bytes()),
			E: hex.EncodeToString(E.Bytes()),
			D: hex.EncodeToString(d.Bytes()),
			P: hex.EncodeToString(p.Bytes()),
			Q: hex.EncodeToString(q.Bytes()),
		}, nil
	}
}

// prevScripterFunc adapts a function to the blockcf2.PrevScripter
// interface.
type prevScripterFunc func(*wire.OutPoint) (uint16, []byte, bool)

func (f prevScripterFunc) PrevScript(op *wire.OutPoint) (uint16, []byte, bool) {
	return f(op)
}

// standaloneErrKind renders "ok" or the standalone ErrorKind name for a
// check result; errors without a standalone kind render their message.
func standaloneErrKind(err error) string {
	if err == nil {
		return "ok"
	}
	var kindErr standalone.ErrorKind
	if errors.As(err, &kindErr) {
		return kindErr.Error()
	}
	return err.Error()
}

// stakeErrKind renders "ok" or the stake ErrorKind name for a check
// result; errors without a stake kind render their message.
func stakeErrKind(err error) string {
	if err == nil {
		return "ok"
	}
	var kindErr stake.ErrorKind
	if errors.As(err, &kindErr) {
		return kindErr.Error()
	}
	return err.Error()
}

// netParams maps a network name to its chaincfg parameters.
func netParams(name string) (*chaincfg.Params, error) {
	switch name {
	case "mainnet":
		return chaincfg.MainNetParams(), nil
	case "testnet3":
		return chaincfg.TestNet3Params(), nil
	case "simnet":
		return chaincfg.SimNetParams(), nil
	case "regnet":
		return chaincfg.RegNetParams(), nil
	}
	return nil, fmt.Errorf("unknown network %q", name)
}

// dumpStdAddr renders every observable surface of a decoded address as
// canonical line-oriented text. The format must stay byte-identical to the
// dump built by dcroxide's stdaddr differential test.
func dumpStdAddr(addr stdaddr.Address, amount, voteFee, revokeFee int64) string {
	var w strings.Builder
	fmt.Fprintf(&w, "type=%T\n", addr)
	fmt.Fprintf(&w, "string=%s\n", addr.String())
	ver, script := addr.PaymentScript()
	fmt.Fprintf(&w, "payment=%d:%x\n", ver, script)
	if spk, ok := addr.(stdaddr.SerializedPubKeyer); ok {
		fmt.Fprintf(&w, "serializedpubkey=%x\n", spk.SerializedPubKey())
	}
	if pkher, ok := addr.(stdaddr.AddressPubKeyHasher); ok {
		fmt.Fprintf(&w, "pkh=%s\n", pkher.AddressPubKeyHash().String())
	}
	if h160er, ok := addr.(stdaddr.Hash160er); ok {
		fmt.Fprintf(&w, "hash160=%x\n", *h160er.Hash160())
	}
	if sa, ok := addr.(stdaddr.StakeAddress); ok {
		ver, script := sa.VotingRightsScript()
		fmt.Fprintf(&w, "votingrights=%d:%x\n", ver, script)
		ver, script = sa.RewardCommitmentScript(amount, voteFee, revokeFee)
		fmt.Fprintf(&w, "rewardcommitment=%d:%x\n", ver, script)
		ver, script = sa.StakeChangeScript()
		fmt.Fprintf(&w, "stakechange=%d:%x\n", ver, script)
		ver, script = sa.PayVoteCommitmentScript()
		fmt.Fprintf(&w, "payvote=%d:%x\n", ver, script)
		ver, script = sa.PayRevokeCommitmentScript()
		fmt.Fprintf(&w, "payrevoke=%d:%x\n", ver, script)
		ver, script = sa.PayFromTreasuryScript()
		fmt.Fprintf(&w, "payfromtreasury=%d:%x\n", ver, script)
	}
	return w.String()
}

// dumpParams renders every network parameter as canonical line-oriented
// text. The format must stay byte-identical to dcroxide's Params::dump —
// that equality across all four networks is the chaincfg parity test.
func dumpParams(p *chaincfg.Params) (string, error) {
	var w strings.Builder
	fmt.Fprintf(&w, "name=%s\n", p.Name)
	fmt.Fprintf(&w, "net=0x%08x\n", uint32(p.Net))
	fmt.Fprintf(&w, "defaultport=%s\n", p.DefaultPort)
	for _, seed := range p.DNSSeeds {
		fmt.Fprintf(&w, "dnsseed=%s %t\n", seed.Host, seed.HasFiltering)
	}
	for _, seeder := range p.Seeders() {
		fmt.Fprintf(&w, "seeder=%s\n", seeder)
	}
	fmt.Fprintf(&w, "genesishash=%s\n", p.GenesisHash.String())
	blockBytes, err := p.GenesisBlock.Bytes()
	if err != nil {
		return "", fmt.Errorf("serialize genesis block: %w", err)
	}
	fmt.Fprintf(&w, "genesisblock=%s\n", hex.EncodeToString(blockBytes))
	fmt.Fprintf(&w, "powlimit=%064x\n", p.PowLimit)
	fmt.Fprintf(&w, "powlimitbits=0x%08x\n", p.PowLimitBits)
	fmt.Fprintf(&w, "reducemindifficulty=%t\n", p.ReduceMinDifficulty)
	fmt.Fprintf(&w, "mindiffreductiontime=%d\n", int64(p.MinDiffReductionTime/time.Second))
	fmt.Fprintf(&w, "generatesupported=%t\n", p.GenerateSupported)
	sizes := make([]string, 0, len(p.MaximumBlockSizes))
	for _, s := range p.MaximumBlockSizes {
		sizes = append(sizes, strconv.Itoa(s))
	}
	fmt.Fprintf(&w, "maximumblocksizes=%s\n", strings.Join(sizes, ","))
	fmt.Fprintf(&w, "maxtxsize=%d\n", p.MaxTxSize)
	fmt.Fprintf(&w, "targettimeperblock=%d\n", int64(p.TargetTimePerBlock/time.Second))
	fmt.Fprintf(&w, "workdiffalpha=%d\n", p.WorkDiffAlpha)
	fmt.Fprintf(&w, "workdiffwindowsize=%d\n", p.WorkDiffWindowSize)
	fmt.Fprintf(&w, "workdiffwindows=%d\n", p.WorkDiffWindows)
	fmt.Fprintf(&w, "targettimespan=%d\n", int64(p.TargetTimespan/time.Second))
	fmt.Fprintf(&w, "retargetadjustmentfactor=%d\n", p.RetargetAdjustmentFactor)
	fmt.Fprintf(&w, "workdiffv2blake3startbits=0x%08x\n", p.WorkDiffV2Blake3StartBits)
	fmt.Fprintf(&w, "workdiffv2halflifesecs=%d\n", p.WorkDiffV2HalfLifeSecs)
	fmt.Fprintf(&w, "basesubsidy=%d\n", p.BaseSubsidy)
	fmt.Fprintf(&w, "mulsubsidy=%d\n", p.MulSubsidy)
	fmt.Fprintf(&w, "divsubsidy=%d\n", p.DivSubsidy)
	fmt.Fprintf(&w, "subsidyreductioninterval=%d\n", p.SubsidyReductionInterval)
	fmt.Fprintf(&w, "workrewardproportion=%d\n", p.WorkRewardProportion)
	fmt.Fprintf(&w, "workrewardproportionv2=%d\n", p.WorkRewardProportionV2)
	fmt.Fprintf(&w, "stakerewardproportion=%d\n", p.StakeRewardProportion)
	fmt.Fprintf(&w, "stakerewardproportionv2=%d\n", p.StakeRewardProportionV2)
	fmt.Fprintf(&w, "blocktaxproportion=%d\n", p.BlockTaxProportion)
	fmt.Fprintf(&w, "assumevalid=%s\n", p.AssumeValid.String())
	if p.MinKnownChainWork != nil {
		fmt.Fprintf(&w, "minknownchainwork=%064x\n", p.MinKnownChainWork)
	} else {
		fmt.Fprintf(&w, "minknownchainwork=nil\n")
	}
	fmt.Fprintf(&w, "rulechangeactivationquorum=%d\n", p.RuleChangeActivationQuorum)
	fmt.Fprintf(&w, "rulechangeactivationmultiplier=%d\n", p.RuleChangeActivationMultiplier)
	fmt.Fprintf(&w, "rulechangeactivationdivisor=%d\n", p.RuleChangeActivationDivisor)
	fmt.Fprintf(&w, "rulechangeactivationinterval=%d\n", p.RuleChangeActivationInterval)
	versions := make([]uint32, 0, len(p.Deployments))
	for version := range p.Deployments {
		versions = append(versions, version)
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i] < versions[j] })
	for _, version := range versions {
		for _, dep := range p.Deployments[version] {
			fmt.Fprintf(&w,
				"deployment version=%d id=%s mask=0x%04x forced=%s start=%d expire=%d desc=%s\n",
				version, dep.Vote.Id, dep.Vote.Mask, dep.ForcedChoiceID,
				dep.StartTime, dep.ExpireTime, dep.Vote.Description)
			for _, c := range dep.Vote.Choices {
				fmt.Fprintf(&w, "choice id=%s bits=0x%04x abstain=%t no=%t desc=%s\n",
					c.Id, c.Bits, c.IsAbstain, c.IsNo, c.Description)
			}
		}
	}
	fmt.Fprintf(&w, "blockenforcenumrequired=%d\n", p.BlockEnforceNumRequired)
	fmt.Fprintf(&w, "blockrejectnumrequired=%d\n", p.BlockRejectNumRequired)
	fmt.Fprintf(&w, "blockupgradenumtocheck=%d\n", p.BlockUpgradeNumToCheck)
	fmt.Fprintf(&w, "acceptnonstdtxs=%t\n", p.AcceptNonStdTxs)
	fmt.Fprintf(&w, "networkaddressprefix=%s\n", p.NetworkAddressPrefix)
	fmt.Fprintf(&w, "pubkeyaddrid=%s\n", hex.EncodeToString(p.PubKeyAddrID[:]))
	fmt.Fprintf(&w, "pubkeyhashaddrid=%s\n", hex.EncodeToString(p.PubKeyHashAddrID[:]))
	fmt.Fprintf(&w, "pkhedwardsaddrid=%s\n", hex.EncodeToString(p.PKHEdwardsAddrID[:]))
	fmt.Fprintf(&w, "pkhschnorraddrid=%s\n", hex.EncodeToString(p.PKHSchnorrAddrID[:]))
	fmt.Fprintf(&w, "scripthashaddrid=%s\n", hex.EncodeToString(p.ScriptHashAddrID[:]))
	fmt.Fprintf(&w, "privatekeyid=%s\n", hex.EncodeToString(p.PrivateKeyID[:]))
	fmt.Fprintf(&w, "hdprivatekeyid=%s\n", hex.EncodeToString(p.HDPrivateKeyID[:]))
	fmt.Fprintf(&w, "hdpublickeyid=%s\n", hex.EncodeToString(p.HDPublicKeyID[:]))
	fmt.Fprintf(&w, "slip0044cointype=%d\n", p.SLIP0044CoinType)
	fmt.Fprintf(&w, "legacycointype=%d\n", p.LegacyCoinType)
	fmt.Fprintf(&w, "minimumstakediff=%d\n", p.MinimumStakeDiff)
	fmt.Fprintf(&w, "ticketpoolsize=%d\n", p.TicketPoolSize)
	fmt.Fprintf(&w, "ticketsperblock=%d\n", p.TicketsPerBlock)
	fmt.Fprintf(&w, "ticketmaturity=%d\n", p.TicketMaturity)
	fmt.Fprintf(&w, "ticketexpiry=%d\n", p.TicketExpiry)
	fmt.Fprintf(&w, "coinbasematurity=%d\n", p.CoinbaseMaturity)
	fmt.Fprintf(&w, "sstxchangematurity=%d\n", p.SStxChangeMaturity)
	fmt.Fprintf(&w, "ticketpoolsizeweight=%d\n", p.TicketPoolSizeWeight)
	fmt.Fprintf(&w, "stakediffalpha=%d\n", p.StakeDiffAlpha)
	fmt.Fprintf(&w, "stakediffwindowsize=%d\n", p.StakeDiffWindowSize)
	fmt.Fprintf(&w, "stakediffwindows=%d\n", p.StakeDiffWindows)
	fmt.Fprintf(&w, "stakeversioninterval=%d\n", p.StakeVersionInterval)
	fmt.Fprintf(&w, "maxfreshstakeperblock=%d\n", p.MaxFreshStakePerBlock)
	fmt.Fprintf(&w, "stakeenabledheight=%d\n", p.StakeEnabledHeight)
	fmt.Fprintf(&w, "stakevalidationheight=%d\n", p.StakeValidationHeight)
	fmt.Fprintf(&w, "stakebasesigscript=%s\n", hex.EncodeToString(p.StakeBaseSigScript))
	fmt.Fprintf(&w, "stakemajoritymultiplier=%d\n", p.StakeMajorityMultiplier)
	fmt.Fprintf(&w, "stakemajoritydivisor=%d\n", p.StakeMajorityDivisor)
	fmt.Fprintf(&w, "organizationpkscript=%s\n", hex.EncodeToString(p.OrganizationPkScript))
	fmt.Fprintf(&w, "organizationpkscriptversion=%d\n", p.OrganizationPkScriptVersion)
	var ledgerBuf bytes.Buffer
	for _, payout := range p.BlockOneLedger {
		var tmp [8]byte
		binary.LittleEndian.PutUint16(tmp[0:2], payout.ScriptVersion)
		ledgerBuf.Write(tmp[0:2])
		binary.LittleEndian.PutUint32(tmp[0:4], uint32(len(payout.Script)))
		ledgerBuf.Write(tmp[0:4])
		ledgerBuf.Write(payout.Script)
		binary.LittleEndian.PutUint64(tmp[0:8], uint64(payout.Amount))
		ledgerBuf.Write(tmp[0:8])
	}
	ledgerHash := blake256.Sum256(ledgerBuf.Bytes())
	fmt.Fprintf(&w, "blockoneledger count=%d hash=%s\n",
		len(p.BlockOneLedger), hex.EncodeToString(ledgerHash[:]))
	for _, key := range p.PiKeys {
		fmt.Fprintf(&w, "pikey=%s\n", hex.EncodeToString(key))
	}
	fmt.Fprintf(&w, "treasuryvoteinterval=%d\n", p.TreasuryVoteInterval)
	fmt.Fprintf(&w, "treasuryvoteintervalmultiplier=%d\n", p.TreasuryVoteIntervalMultiplier)
	fmt.Fprintf(&w, "treasuryvotequorummultiplier=%d\n", p.TreasuryVoteQuorumMultiplier)
	fmt.Fprintf(&w, "treasuryvotequorumdivisor=%d\n", p.TreasuryVoteQuorumDivisor)
	fmt.Fprintf(&w, "treasuryvoterequiredmultiplier=%d\n", p.TreasuryVoteRequiredMultiplier)
	fmt.Fprintf(&w, "treasuryvoterequireddivisor=%d\n", p.TreasuryVoteRequiredDivisor)
	fmt.Fprintf(&w, "treasuryexpenditurewindow=%d\n", p.TreasuryExpenditureWindow)
	fmt.Fprintf(&w, "treasuryexpenditurepolicy=%d\n", p.TreasuryExpenditurePolicy)
	fmt.Fprintf(&w, "treasuryexpenditurebootstrap=%d\n", p.TreasuryExpenditureBootstrap)
	return w.String(), nil
}

// handleLine answers one request line, echoing its id.
func handleLine(line []byte) response {
	var req request
	if err := json.Unmarshal(line, &req); err != nil {
		return errResp("bad request: %v", err)
	}
	resp := handle(req)
	resp.ID = req.ID
	return resp
}

// readLine returns the next line from in without its newline, or io.EOF once
// in is exhausted; a last line with no newline is returned before the io.EOF.
// A line that fits in in's buffer comes back as a slice of it, valid until the
// next read. A line longer than maxLineBytes is read through its newline and
// discarded, and reported as errLineTooLong, so the line after it can still be
// served.
func readLine(in *bufio.Reader) ([]byte, error) {
	var line []byte
	n := 0
	for {
		chunk, err := in.ReadSlice('\n')
		if err == nil {
			chunk = chunk[:len(chunk)-1]
			if n == 0 {
				return chunk, nil
			}
		}
		n += len(chunk)
		if n <= maxLineBytes {
			line = append(line, chunk...)
		} else {
			line = nil
		}
		switch {
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case err == nil, errors.Is(err, io.EOF) && n > 0:
			if n > maxLineBytes {
				return nil, errLineTooLong
			}
			return line, nil
		default:
			return nil, err
		}
	}
}

// lineBuffered reports whether in already holds a complete line, so that the
// next readLine returns without waiting on the input.
func lineBuffered(in *bufio.Reader) bool {
	buffered, _ := in.Peek(in.Buffered())
	return bytes.IndexByte(buffered, '\n') >= 0
}

// serve answers each request line read from in with answer, as main does with
// handleLine, writing the responses to out, until in is exhausted. out is
// flushed before any read that could wait on the input, so no client waits on
// an answer still sitting in out, and answers to requests that arrived
// together go out together. A request that never returns holds back the
// answers to those that arrived with it.
func serve(in *bufio.Reader, out *bufio.Writer, answer func(line []byte) response) error {
	// Answers already given reach the client whatever ends serving,
	// including a request that panics: nothing recovers the panic, so this
	// runs as it unwinds, before the process dies.
	defer out.Flush()

	enc := json.NewEncoder(out)
	for {
		if out.Buffered() > 0 && !lineBuffered(in) {
			if err := out.Flush(); err != nil {
				return fmt.Errorf("flush: %w", err)
			}
		}
		line, err := readLine(in)
		var resp response
		switch {
		case errors.Is(err, io.EOF):
			if err := out.Flush(); err != nil {
				return fmt.Errorf("flush: %w", err)
			}
			return nil
		case errors.Is(err, errLineTooLong):
			resp = errResp("bad request: %v", err)
		case err != nil:
			return fmt.Errorf("read: %w", err)
		case len(bytes.TrimSpace(line)) == 0:
			continue
		default:
			resp = answer(line)
		}
		if err := enc.Encode(&resp); err != nil {
			return fmt.Errorf("write: %w", err)
		}
	}
}

func main() {
	in := bufio.NewReaderSize(os.Stdin, 1<<20)
	out := bufio.NewWriterSize(os.Stdout, 1<<20)
	if err := serve(in, out, handleLine); err != nil {
		fmt.Fprintf(os.Stderr, "dcrd-oracle: %v\n", err)
		os.Exit(1)
	}
}
