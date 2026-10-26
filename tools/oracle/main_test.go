// Copyright (c) 2026 The dcroxide developers
// Use of this source code is governed by an ISC license that can be found in
// the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/decred/dcrd/crypto/blake256"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// These mirror unexported constants of dcrd's ecdsa package, which the rows
// and checks copied from its tests below use.
const (
	compactSigMagicOffset        = 27
	compactSigCompPubKey         = 4
	pubKeyRecoveryCodeOddnessBit = 1 << 0
)

// hexToBytes converts the passed hex string into bytes and will panic if there
// is an error. It must only be called with hard-coded values.
func hexToBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("invalid hex in source file: " + s)
	}
	return b
}

// call answers one command through handle, its data the parts concatenated.
func call(cmd string, parts ...[]byte) response {
	return handle(request{Cmd: cmd, Data: hex.EncodeToString(bytes.Join(parts, nil))})
}

// keyEncodings returns the three serializations ParsePubKey accepts for the
// public key of the passed private key: compressed, uncompressed and hybrid.
func keyEncodings(privKey []byte) map[string][]byte {
	pubKey := secp256k1.PrivKeyFromBytes(privKey).PubKey()
	uncompressed := pubKey.SerializeUncompressed()
	hybrid := bytes.Clone(uncompressed)
	hybrid[0] = secp256k1.PubKeyFormatHybridEven
	if uncompressed[64]&1 == 1 {
		hybrid[0] = secp256k1.PubKeyFormatHybridOdd
	}
	return map[string][]byte{
		"compressed":   pubKey.SerializeCompressed(),
		"uncompressed": uncompressed,
		"hybrid":       hybrid,
	}
}

// signTest is one row of dcrd's signTests, copied from the dcrd
// dcrec/secp256k1/v4 module's ecdsa/signature_test.go.
type signTest struct {
	name     string // test description
	key      string // hex encoded private key
	msg      string // hex encoded message to sign before hashing
	hash     string // hex encoded hash of the message to sign
	nonce    string // hex encoded nonce to use in the signature calculation
	rfc6979  bool   // whether or not the nonce is an RFC6979 nonce
	wantSigR string // hex encoded expected signature R
	wantSigS string // hex encoded expected signature S
	wantCode byte   // expected public key recovery code
}

// signTests returns the RFC6979 rows of signTests in the dcrd dcrec/secp256k1/v4
// module's ecdsa/signature_test.go, copied verbatim. The four rows with
// explicit random nonces are left out: TestSignAndRecoverCompact skips them,
// and no oracle command signs with a chosen nonce. As in dcrd, the hash and
// nonce of every row are checked against blake256 and NonceRFC6979 first.
func signTests(t *testing.T) []signTest {
	t.Helper()

	tests := []signTest{{
		name:     "key 0x1, blake256(0x01020304), rfc6979 nonce",
		key:      "0000000000000000000000000000000000000000000000000000000000000001",
		msg:      "01020304",
		hash:     "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
		nonce:    "4154324ecd4158938f1df8b5b659aeb639c7fbc36005934096e514af7d64bcc2",
		rfc6979:  true,
		wantSigR: "c6c4137b0e5fbfc88ae3f293d7e80c8566c43ae20340075d44f75b009c943d09",
		wantSigS: "00ba213513572e35943d5acdd17215561b03f11663192a7252196cc8b2a99560",
		wantCode: 0,
	}, {
		name:     "key 0x2, blake256(0x01020304), rfc6979 nonce",
		key:      "0000000000000000000000000000000000000000000000000000000000000002",
		msg:      "01020304",
		hash:     "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
		nonce:    "55f96f24cf7531f527edfe3b9222eca12d575367c32a7f593a828dc3651acf49",
		rfc6979:  true,
		wantSigR: "e6f137b52377250760cc702e19b7aee3c63b0e7d95a91939b14ab3b5c4771e59",
		wantSigS: "44b9bc4620afa158b7efdfea5234ff2d5f2f78b42886f02cf581827ee55318ea",
		wantCode: pubKeyRecoveryCodeOddnessBit,
	}, {
		name:     "key 0x1, blake256(0x0102030405), rfc6979 nonce",
		key:      "0000000000000000000000000000000000000000000000000000000000000001",
		msg:      "0102030405",
		hash:     "dc063eba3c8d52a159e725c1a161506f6cb6b53478ad5ef3f08d534efa871d9f",
		nonce:    "aa87a543c68f2568bb107c9946afa5233bf94fb6a7a063544505282621021629",
		rfc6979:  true,
		wantSigR: "dda8308cdbda2edf51ccf598b42b42b19597e102eb2ed4a04a16dd57084d3b40",
		wantSigS: "0b6d67bab4929624e28f690407a15efc551354544fdc179970ff401eec2e5dc9",
		wantCode: pubKeyRecoveryCodeOddnessBit,
	}, {
		name:     "key 0x2, blake256(0x0102030405), rfc6979 nonce",
		key:      "0000000000000000000000000000000000000000000000000000000000000002",
		msg:      "0102030405",
		hash:     "dc063eba3c8d52a159e725c1a161506f6cb6b53478ad5ef3f08d534efa871d9f",
		nonce:    "a13d652abd54b6e862548e5d12716df14dc192d93f3fa13536fdf4e56c54f233",
		rfc6979:  true,
		wantSigR: "122663fd29e41a132d3c8329cf05d61ebcca9351074cc277dcd868faba58d87d",
		wantSigS: "353a44f2d949c04981e4e4d9c1f93a9e0644e63a5eaa188288c5ad68fd288d40",
		wantCode: 0,
	}, {
		name:     "random key 1, blake256(0x01), rfc6979 nonce",
		key:      "a1becef2069444a9dc6331c3247e113c3ee142edda683db8643f9cb0af7cbe33",
		msg:      "01",
		hash:     "4a6c419a1e25c85327115c4ace586decddfe2990ed8f3d4d801871158338501d",
		nonce:    "edb3a01063a0c6ccfc0d77295077cbd322cf364bfa64b7eeea3b20305135d444",
		rfc6979:  true,
		wantSigR: "ef392791d87afca8256c4c9c68d981248ee34a09069f50fa8dfc19ae34cd92ce",
		wantSigS: "0a2b9cb69fd794f7f204c272293b8585a294916a21a11fd94ec04acae2dc6d21",
		wantCode: 0,
	}, {
		name:     "random key 2, blake256(0x02), rfc6979 nonce",
		key:      "59930b76d4b15767ec0e8c8e5812aa2e57db30c6af7963e2a6295ba02af5416b",
		msg:      "02",
		hash:     "49af37ab5270015fe25276ea5a3bb159d852943df23919522a202205fb7d175c",
		nonce:    "af2a59085976494567ef0fc2ecede587b2d1d8e9898cc46e72d7f3e33156e057",
		rfc6979:  true,
		wantSigR: "886c9cccb356b3e1deafef2c276a4f8717ab73c1244c3f673cfbff5897de0e06",
		wantSigS: "609394185495f978ae84b69be90c69947e5dd8dcb4726da604fcbd139d81fc55",
		wantCode: 0,
	}, {
		name:     "random key 3, blake256(0x03), rfc6979 nonce",
		key:      "c5b205c36bb7497d242e96ec19a2a4f086d8daa919135cf490d2b7c0230f0e91",
		msg:      "03",
		hash:     "b706d561742ad3671703c247eb927ee8a386369c79644131cdeb2c5c26bf6c5d",
		nonce:    "82d82b696a386d6d7a111c4cb943bfd39de8e5f6195e7eed9d3edb40fe1419fa",
		rfc6979:  true,
		wantSigR: "6589d5950cec1fe2e7e20593b5ffa3556de20c176720a1796aa77a0cec1ec5a7",
		wantSigS: "2a26deba3241de852e786f5b4e2b98d3efb958d91fe9773b331dbcca9e8be800",
		wantCode: 0,
	}, {
		name:     "random key 4, blake256(0x04), rfc6979 nonce",
		key:      "65b46d4eb001c649a86309286aaf94b18386effe62c2e1586d9b1898ccf0099b",
		msg:      "04",
		hash:     "4c6eb9e38415034f4c93d3304d10bef38bf0ad420eefd0f72f940f11c5857786",
		nonce:    "7afd696a9e770961d2b2eaec77ab7c22c734886fa57bc4a50a9f1946168cd06f",
		rfc6979:  true,
		wantSigR: "81db1d6dca08819ad936d3284a359091e57c036648d477b96af9d8326965a7d1",
		wantSigS: "1bdf719c4be69351ba7617a187ac246912101aea4b5a7d6dfc234478622b43c6",
		wantCode: pubKeyRecoveryCodeOddnessBit,
	}, {
		name:     "random key 5, blake256(0x05), rfc6979 nonce",
		key:      "915cb9ba4675de06a182088b182abcf79fa8ac989328212c6b866fa3ec2338f9",
		msg:      "05",
		hash:     "bdd15db13448905791a70b68137445e607cca06cc71c7a58b9b2e84a06c54d08",
		nonce:    "2a6ae70ea5cf1b932331901d640ece54551f5f33bf9484d5f95c676b5612b527",
		rfc6979:  true,
		wantSigR: "47fd51aecbc743477cb59aa29d18d11d75fb206ae1cdd044216e4f294e33d5b6",
		wantSigS: "3d50edc03066584d50b8d19d681865a23960b37502ede5bf452bdca56744334a",
		wantCode: pubKeyRecoveryCodeOddnessBit,
	}, {
		name:     "random key 6, blake256(0x06), rfc6979 nonce",
		key:      "93e9d81d818f08ba1f850c6dfb82256b035b42f7d43c1fe090804fb009aca441",
		msg:      "06",
		hash:     "19b7506ad9c189a9f8b063d2aee15953d335f5c88480f8515d7d848e7771c4ae",
		nonce:    "0b847a0ae0cbe84dfca66621f04f04b0f2ec190dce10d43ba8c3915c0fcd90ed",
		rfc6979:  true,
		wantSigR: "c99800bc7ac7ea11afe5d7a264f4c26edd63ae9c7ecd6d0d19992980bcda1d34",
		wantSigS: "2844d4c9020ddf9e96b86c1a04788e0f371bd562291fd17ee017db46259d04fb",
		wantCode: pubKeyRecoveryCodeOddnessBit,
	}, {
		name:     "random key 7, blake256(0x07), rfc6979 nonce",
		key:      "c249bbd5f533672b7dcd514eb1256854783531c2b85fe60bf4ce6ea1f26afc2b",
		msg:      "07",
		hash:     "53d661e71e47a0a7e416591200175122d83f8af31be6a70af7417ad6f54d0038",
		nonce:    "0f8e20694fe766d7b79e5ac141e3542f2f3c3d2cc6d0f60e0ec263a46dbe6d49",
		rfc6979:  true,
		wantSigR: "7a57a5222fb7d615eaa0041193f682262cebfa9b448f9c519d3644d0a3348521",
		wantSigS: "574923b7b5aec66b62f1589002db29342c9f5ed56d5e80f5361c0307ff1561fa",
		wantCode: 0,
	}, {
		name:     "random key 8, blake256(0x08), rfc6979 nonce",
		key:      "ec0be92fcec66cf1f97b5c39f83dfd4ddcad0dad468d3685b5eec556c6290bcc",
		msg:      "08",
		hash:     "9bff7982eab6f7883322edf7bdc86a23c87ca1c07906fbb1584f57b197dc6253",
		nonce:    "ab7df49257d18f5f1b730cc7448f46bd82eb43e6e220f521fa7d23802310e24d",
		rfc6979:  true,
		wantSigR: "64f90b09c8b1763a3eeefd156e5d312f80a98c24017811c0163b1c0b01323668",
		wantSigS: "7d7bf4ff295ecfc9578eadc8378b0eea0c0362ad083b0fd1c9b3c06f4537f6ff",
		wantCode: pubKeyRecoveryCodeOddnessBit,
	}, {
		name:     "random key 9, blake256(0x09), rfc6979 nonce",
		key:      "6847b071a7cba6a85099b26a9c3e57a964e4990620e1e1c346fecc4472c4d834",
		msg:      "09",
		hash:     "4c2231813064f8500edae05b40195416bd543fd3e76c16d6efb10c816d92e8b6",
		nonce:    "48ea6c907e1cda596048d812439ccf416eece9a7de400c8a0e40bd48eb7e613a",
		rfc6979:  true,
		wantSigR: "81fc600775d3cdcaa14f8629537299b8226a0c8bfce9320ce64a8d14e3f95bae",
		wantSigS: "3607997d36b48bce957ae9b3d450e0969f6269554312a82bf9499efc8280ea6d",
		wantCode: 0,
	}, {
		name:     "random key 10, blake256(0x0a), rfc6979 nonce",
		key:      "b7548540f52fe20c161a0d623097f827608c56023f50442cc00cc50ad674f6b5",
		msg:      "0a",
		hash:     "e81db4f0d76e02805155441f50c861a8f86374f3ae34c7a3ff4111d3a634ecb1",
		nonce:    "95c07e315cd5457e84270ca01019563c8eeaffb18ab4f23e88a44a0ff01c5f6f",
		rfc6979:  true,
		wantSigR: "0d4cbf2da84f7448b083fce9b9c4e1834b5e2e98defcec7ec87e87c739f5fe78",
		wantSigS: "0997db60683e12b4494702347fc7ae7f599e5a95c629c146e0fc615a1a2acac5",
		wantCode: pubKeyRecoveryCodeOddnessBit,
	}}

	for _, test := range tests {
		calcHash := blake256.Sum256(hexToBytes(test.msg))
		if !bytes.Equal(calcHash[:], hexToBytes(test.hash)) {
			t.Fatalf("%s: mismatched test hash -- calculated %x, given %s",
				test.name, calcHash, test.hash)
		}
		calcNonce := secp256k1.NonceRFC6979(hexToBytes(test.key),
			hexToBytes(test.hash), nil, nil, 0)
		calcNonceBytes := calcNonce.Bytes()
		if !bytes.Equal(calcNonceBytes[:], hexToBytes(test.nonce)) {
			t.Fatalf("%s: mismatched test nonce -- calculated %x, given %s",
				test.name, calcNonceBytes, test.nonce)
		}
	}
	return tests
}

// TestSignAndRecoverCompact runs dcrd's TestSignAndRecoverCompact through
// ecdsa_sign_compact and ecdsa_recover_compact: every RFC6979 row of
// signTests, signed for a compressed and an uncompressed key, gives dcrd's
// expected compact signature, which recovers the signer's key, serialized as
// the signature's recovery code says, and the compressed flag.
func TestSignAndRecoverCompact(t *testing.T) {
	for _, test := range signTests(t) {
		key := hexToBytes(test.key)
		hash := hexToBytes(test.hash)
		pubKey := secp256k1.PrivKeyFromBytes(key).PubKey()
		for _, compressed := range []bool{true, false} {
			wantSig := hexToBytes("00" + test.wantSigR + test.wantSigS)
			wantSig[0] = compactSigMagicOffset + test.wantCode
			flag := []byte{0}
			wantKey := pubKey.SerializeUncompressed()
			if compressed {
				wantSig[0] += compactSigCompPubKey
				flag[0] = 1
				wantKey = pubKey.SerializeCompressed()
			}

			resp := call("ecdsa_sign_compact", flag, key, hash)
			if resp.Error != "" || resp.Result != hex.EncodeToString(wantSig) {
				t.Errorf("%s (compressed %v): sign got %+v, want result %x",
					test.name, compressed, resp, wantSig)
				continue
			}

			resp = call("ecdsa_recover_compact", hash, wantSig)
			want := response{
				Result:        hex.EncodeToString(wantKey),
				WasCompressed: strconv.FormatBool(compressed),
			}
			if !reflect.DeepEqual(resp, want) {
				t.Errorf("%s (compressed %v): recover got %+v, want %+v",
					test.name, compressed, resp, want)
			}
		}
	}
}

// TestRecoverCompactErrors runs dcrd's TestRecoverCompactErrors through
// ecdsa_recover_compact, expecting dcrd's error kind by name for each row.
// The rows are copied verbatim from the function of that name in the dcrd
// dcrec/secp256k1/v4 module's ecdsa/signature_test.go, but for the ecdsa.
// qualifier on the error kinds. Between them they reach all 8 of the kinds
// RecoverCompact returns.
func TestRecoverCompactErrors(t *testing.T) {
	tests := []struct {
		name string // test description
		sig  string // hex encoded signature to recover pubkey from
		hash string // hex encoded hash of message
		err  error  // expected error
	}{{
		name: "empty signature",
		sig:  "",
		hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
		err:  ecdsa.ErrSigInvalidLen,
	}, {
		// Signature created from private key 0x02, blake256(0x01020304).
		name: "no compact sig recovery code (otherwise valid sig)",
		sig: "e6f137b52377250760cc702e19b7aee3c63b0e7d95a91939b14ab3b5c4771e59" +
			"44b9bc4620afa158b7efdfea5234ff2d5f2f78b42886f02cf581827ee55318ea",
		hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
		err:  ecdsa.ErrSigInvalidLen,
	}, {
		// Signature created from private key 0x02, blake256(0x01020304).
		name: "signature one byte too long (S padded with leading zero)",
		sig: "1f" +
			"e6f137b52377250760cc702e19b7aee3c63b0e7d95a91939b14ab3b5c4771e59" +
			"0044b9bc4620afa158b7efdfea5234ff2d5f2f78b42886f02cf581827ee55318ea",
		hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
		err:  ecdsa.ErrSigInvalidLen,
	}, {
		// Signature created from private key 0x02, blake256(0x01020304).
		name: "compact sig recovery code too low (otherwise valid sig)",
		sig: "1a" +
			"e6f137b52377250760cc702e19b7aee3c63b0e7d95a91939b14ab3b5c4771e59" +
			"44b9bc4620afa158b7efdfea5234ff2d5f2f78b42886f02cf581827ee55318ea",
		hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
		err:  ecdsa.ErrSigInvalidRecoveryCode,
	}, {
		// Signature created from private key 0x02, blake256(0x01020304).
		name: "compact sig recovery code too high (otherwise valid sig)",
		sig: "23" +
			"e6f137b52377250760cc702e19b7aee3c63b0e7d95a91939b14ab3b5c4771e59" +
			"44b9bc4620afa158b7efdfea5234ff2d5f2f78b42886f02cf581827ee55318ea",
		hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
		err:  ecdsa.ErrSigInvalidRecoveryCode,
	}, {
		// Signature invented since finding a signature with an r value that is
		// exactly the group order prior to the modular reduction is not
		// calculable without breaking the underlying crypto.
		name: "R == group order",
		sig: "1f" +
			"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141" +
			"44b9bc4620afa158b7efdfea5234ff2d5f2f78b42886f02cf581827ee55318ea",
		hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
		err:  ecdsa.ErrSigRTooBig,
	}, {
		// Signature invented since finding a signature with an r value that
		// would be valid modulo the group order and is still 32 bytes is not
		// calculable without breaking the underlying crypto.
		name: "R > group order and still 32 bytes (order + 1)",
		sig: "1f" +
			"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142" +
			"44b9bc4620afa158b7efdfea5234ff2d5f2f78b42886f02cf581827ee55318ea",
		hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
		err:  ecdsa.ErrSigRTooBig,
	}, {
		// Signature invented since the only way a signature could have an r
		// value of zero is if the nonce were zero which is invalid.
		name: "R == 0",
		sig: "1f" +
			"0000000000000000000000000000000000000000000000000000000000000000" +
			"44b9bc4620afa158b7efdfea5234ff2d5f2f78b42886f02cf581827ee55318ea",
		hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
		err:  ecdsa.ErrSigRIsZero,
	}, {
		// Signature invented since finding a signature with an s value that is
		// exactly the group order prior to the modular reduction is not
		// calculable without breaking the underlying crypto.
		name: "S == group order",
		sig: "1f" +
			"e6f137b52377250760cc702e19b7aee3c63b0e7d95a91939b14ab3b5c4771e59" +
			"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
		hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
		err:  ecdsa.ErrSigSTooBig,
	}, {
		// Signature invented since finding a signature with an s value that
		// would be valid modulo the group order and is still 32 bytes is not
		// calculable without breaking the underlying crypto.
		name: "S > group order and still 32 bytes (order + 1)",
		sig: "1f" +
			"e6f137b52377250760cc702e19b7aee3c63b0e7d95a91939b14ab3b5c4771e59" +
			"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142",
		hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
		err:  ecdsa.ErrSigSTooBig,
	}, {
		// Signature created by forcing the key/hash/nonce choices such that s
		// is zero and is therefore invalid.  The signing code will not produce
		// such a signature in practice.
		name: "S == 0",
		sig: "1f" +
			"e6f137b52377250760cc702e19b7aee3c63b0e7d95a91939b14ab3b5c4771e59" +
			"0000000000000000000000000000000000000000000000000000000000000000",
		hash: "393bec84f1a04037751c0d6c2817f37953eaa204ac0898de7adb038c33a20438",
		err:  ecdsa.ErrSigSIsZero,
	}, {
		// Signature invented since finding a private key needed to create a
		// valid signature with an r value that is >= group order prior to the
		// modular reduction is not possible without breaking the underlying
		// crypto.
		name: "R >= field prime minus group order with overflow bit",
		sig: "21" +
			"000000000000000000000000000000014551231950b75fc4402da1722fc9baee" +
			"44b9bc4620afa158b7efdfea5234ff2d5f2f78b42886f02cf581827ee55318ea",
		hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
		err:  ecdsa.ErrSigOverflowsPrime,
	}, {
		// Signature invented since finding a private key needed to create a
		// valid signature with an r value that is > group order prior to the
		// modular reduction is not possible without breaking the underlying
		// crypto.
		name: "R > group order with overflow bit",
		sig: "21" +
			"000000000000000000000000000000014551231950b75fc4402da1722fc9baed" +
			"44b9bc4620afa158b7efdfea5234ff2d5f2f78b42886f02cf581827ee55318ea",
		hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
		err:  ecdsa.ErrPointNotOnCurve,
	}, {
		// Signature created from private key 0x01, blake256(0x0102030407) over
		// the secp256r1 curve (note the r1 instead of k1).
		name: "pubkey not on the curve, signature valid for secp256r1 instead",
		sig: "1f" +
			"2a81d1b3facc22185267d3f8832c5104902591bc471253f1cfc5eb25f4f740f2" +
			"72e65d019f9b09d769149e2be0b55de9b0224d34095bddc6a5dba90bfda33c45",
		hash: "9165e957708bc95cf62d020769c150b2d7b08e7ab7981860815b1eaabd41d695",
		err:  ecdsa.ErrPointNotOnCurve,
	}, {
		// Signature created from private key 0x01, blake256(0x01020304) and
		// manually setting s = -e*k^-1.
		name: "calculated pubkey point at infinity",
		sig: "1f" +
			"c6c4137b0e5fbfc88ae3f293d7e80c8566c43ae20340075d44f75b009c943d09" +
			"1281d8d90a5774045abd57b453c7eadbc830dbadec89ae8dd7639b9cc55641d0",
		hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
		err:  ecdsa.ErrPointNotOnCurve,
	}}

	kinds := make(map[string]bool)
	for _, test := range tests {
		resp := call("ecdsa_recover_compact", hexToBytes(test.hash),
			hexToBytes(test.sig))
		if resp.Kind != test.err.Error() || resp.Error == "" ||
			resp.Result != "" || resp.WasCompressed != "" {
			t.Errorf("%s: got %+v, want kind %v", test.name, resp, test.err)
		}
		kinds[resp.Kind] = true
	}
	if len(kinds) != 8 {
		t.Errorf("the rows reach %d error kinds, want 8: %v", len(kinds), kinds)
	}
}

// TestVerifyRaw runs ecdsa_verify_raw over dcrd's signing rows, which verify,
// and the rows of dcrd's TestVerifyFailures, which do not, with the key in
// each format ParsePubKey takes, then checks the kinds reported for a key
// that does not parse and for r or s at or above the group order.
func TestVerifyRaw(t *testing.T) {
	verify := func(key, hash, r, s []byte) response {
		return call("ecdsa_verify_raw", []byte{byte(len(key))}, key, hash, r, s)
	}
	for _, test := range signTests(t) {
		hash := hexToBytes(test.hash)
		r, s := hexToBytes(test.wantSigR), hexToBytes(test.wantSigS)
		otherHash := bytes.Clone(hash)
		otherHash[31] ^= 1
		for format, key := range keyEncodings(hexToBytes(test.key)) {
			resp := verify(key, hash, r, s)
			if !reflect.DeepEqual(resp, response{Result: "true"}) {
				t.Errorf("%s (%s key): got %+v, want true", test.name, format, resp)
			}
			resp = verify(key, otherHash, r, s)
			if !reflect.DeepEqual(resp, response{Result: "false"}) {
				t.Errorf("%s (%s key, other hash): got %+v, want false",
					test.name, format, resp)
			}
		}
	}

	// The rows of TestVerifyFailures in the dcrd dcrec/secp256k1/v4 module's
	// ecdsa/signature_test.go, copied verbatim.
	failures := []struct {
		name string // test description
		key  string // hex encoded private key
		hash string // hex encoded hash of the message to sign
		r, s string // hex encoded r and s components of signature to verify
	}{{
		name: "signature R is 0",
		key:  "0000000000000000000000000000000000000000000000000000000000000001",
		hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
		r:    "0000000000000000000000000000000000000000000000000000000000000000",
		s:    "00ba213513572e35943d5acdd17215561b03f11663192a7252196cc8b2a99560",
	}, {
		name: "signature S is 0",
		key:  "0000000000000000000000000000000000000000000000000000000000000001",
		hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
		r:    "c6c4137b0e5fbfc88ae3f293d7e80c8566c43ae20340075d44f75b009c943d09",
		s:    "0000000000000000000000000000000000000000000000000000000000000000",
	}, {
		name: "u1G + u2Q is the point at infinity",
		key:  "0000000000000000000000000000000000000000000000000000000000000001",
		hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
		r:    "3cfe45621a29fac355260a14b9adc0fe43ac2f13e918fc9ddfa117e964b61a8a",
		s:    "00ba213513572e35943d5acdd17215561b03f11663192a7252196cc8b2a99560",
	}, {
		name: "signature R < P-N, but invalid",
		key:  "0000000000000000000000000000000000000000000000000000000000000001",
		hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
		r:    "000000000000000000000000000000014551231950b75fc4402da1722fc9baed",
		s:    "00ba213513572e35943d5acdd17215561b03f11663192a7252196cc8b2a99560",
	}}
	for _, test := range failures {
		for format, key := range keyEncodings(hexToBytes(test.key)) {
			resp := verify(key, hexToBytes(test.hash), hexToBytes(test.r),
				hexToBytes(test.s))
			if !reflect.DeepEqual(resp, response{Result: "false"}) {
				t.Errorf("%s (%s key): got %+v, want false", test.name, format, resp)
			}
		}
	}

	// A signature that verifies, from the first signing row, to vary one
	// field at a time.
	one := hexToBytes("0000000000000000000000000000000000000000000000000000000000000001")
	key := keyEncodings(one)["compressed"]
	hash := hexToBytes("c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7")
	r := hexToBytes("c6c4137b0e5fbfc88ae3f293d7e80c8566c43ae20340075d44f75b009c943d09")
	s := hexToBytes("00ba213513572e35943d5acdd17215561b03f11663192a7252196cc8b2a99560")
	order := hexToBytes("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
	badFormat := append([]byte{0x05}, key[1:]...)
	mismatched := keyEncodings(one)["hybrid"]
	mismatched[0] ^= 1
	kindTests := []struct {
		name      string
		key, r, s []byte
		wantKind  error
	}{
		{"R == group order", key, order, s, ecdsa.ErrSigRTooBig},
		{"S == group order", key, r, order, ecdsa.ErrSigSTooBig},
		{"R and S == group order", key, order, order, ecdsa.ErrSigRTooBig},
		{"empty key", nil, r, s, secp256k1.ErrPubKeyInvalidLen},
		{"33-byte key, format 0x05", badFormat, r, s, secp256k1.ErrPubKeyInvalidFormat},
		{"hybrid key, mismatched oddness", mismatched, r, s,
			secp256k1.ErrPubKeyMismatchedOddness},
		{"bad key before R == group order", badFormat, order, s,
			secp256k1.ErrPubKeyInvalidFormat},
	}
	for _, test := range kindTests {
		resp := verify(test.key, hash, test.r, test.s)
		if resp.Kind != test.wantKind.Error() || resp.Error == "" || resp.Result != "" {
			t.Errorf("%s: got %+v, want kind %v", test.name, resp, test.wantKind)
		}
	}

	// Malformed requests are refused without a kind.
	for name, data := range map[string][]byte{
		"empty":                 nil,
		"key length past end":   {33},
		"one byte short":        append([]byte{33}, make([]byte, 33+95)...),
		"one byte over":         append([]byte{33}, make([]byte, 33+97)...),
		"key length 0, 95 more": append([]byte{0}, make([]byte, 95)...),
	} {
		resp := call("ecdsa_verify_raw", data)
		if resp.Error == "" || resp.Kind != "" || resp.Result != "" {
			t.Errorf("%s: got %+v, want an error without a kind", name, resp)
		}
	}
}

// TestSignRequests checks ecdsa_sign_compact refuses requests of the wrong
// length or with a compressed flag other than 0 or 1, and that both signing
// commands refuse a key that reduces to zero mod N, for which dcrd's signing
// loop never returns over a zero hash.
func TestSignRequests(t *testing.T) {
	key := hexToBytes("0000000000000000000000000000000000000000000000000000000000000001")
	hash := hexToBytes("c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7")
	zero := make([]byte, 32)
	order := hexToBytes("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
	for name, parts := range map[string][][]byte{
		"flag 2":         {{2}, key, hash},
		"no flag":        {key, hash},
		"hash one short": {{1}, key, hash[:31]},
		"hash one over":  {{1}, key, hash, {0}},
		"key 0":          {{1}, zero, hash},
		"key 0, hash 0":  {{0}, zero, zero},
		"key N, hash N":  {{1}, order, order},
	} {
		resp := call("ecdsa_sign_compact", parts...)
		if resp.Error == "" || resp.Result != "" {
			t.Errorf("%s: got %+v, want an error", name, resp)
		}
	}
	for name, parts := range map[string][][]byte{
		"key 0":         {zero, hash},
		"key 0, hash 0": {zero, zero},
		"key N, hash N": {order, order},
	} {
		resp := call("ecdsa_sign", parts...)
		if resp.Error == "" || resp.Result != "" {
			t.Errorf("ecdsa_sign %s: got %+v, want an error", name, resp)
		}
	}
}

// TestBuildInfo checks build_info reports the running toolchain and the
// versions go.mod pins for the two signature modules, and no other module.
// The modules are named here rather than read from buildInfoModules, so that
// dropping one from that list fails the test.
func TestBuildInfo(t *testing.T) {
	modules := []string{
		"github.com/decred/dcrd/dcrec/secp256k1/v4",
		"github.com/decred/dcrd/dcrec/edwards/v2",
	}
	goMod, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	want := make(map[string]string)
	for _, line := range strings.Split(string(goMod), "\n") {
		fields := strings.Fields(line)
		for _, path := range modules {
			if len(fields) >= 2 && fields[0] == path {
				want[path] = fields[1]
			}
		}
	}
	if len(want) != len(modules) {
		t.Fatalf("go.mod requires %v, want all of %v", want, modules)
	}

	resp := call("build_info")
	if resp.Error != "" || resp.GoVersion != runtime.Version() {
		t.Fatalf("got %+v, want go_version %s", resp, runtime.Version())
	}
	if !reflect.DeepEqual(resp.Modules, want) {
		t.Errorf("modules: got %v, want %v", resp.Modules, want)
	}
}

// serveAll runs serve over input, as main does, and returns its output.
func serveAll(t *testing.T, input io.Reader) string {
	t.Helper()
	var out bytes.Buffer
	w := bufio.NewWriterSize(&out, 1<<20)
	if err := serve(bufio.NewReaderSize(input, 1<<20), w, handleLine); err != nil {
		t.Fatalf("serve: %v", err)
	}
	return out.String()
}

// repeated reads as n copies of b, without holding them.
type repeated struct {
	b byte
	n int
}

func (r *repeated) Read(p []byte) (int, error) {
	if r.n == 0 {
		return 0, io.EOF
	}
	p = p[:min(len(p), r.n)]
	for i := range p {
		p[i] = r.b
	}
	r.n -= len(p)
	return len(p), nil
}

// TestRequestID checks a request's id comes back on its response, and that a
// request without one is answered exactly as before ids existed. The lines
// are sent together, the last without a newline.
func TestRequestID(t *testing.T) {
	digest := blake256.Sum256(nil)
	result := hex.EncodeToString(digest[:])
	tests := []struct {
		line   string // request line
		want   string // its response, or "" for a line that gets none
		prefix bool   // want is only the start of the response
	}{
		{`{"cmd":"blake256","data":""}`, `{"result":"` + result + `"}`, false},
		{`{"id":7,"cmd":"blake256","data":""}`,
			`{"id":7,"result":"` + result + `"}`, false},
		{"", "", false},
		{"  ", "", false},
		{`{"cmd":"blake256","id":0}`, `{"id":0,"result":"` + result + `"}`, false},
		{`{"id":18446744073709551615,"cmd":"nope"}`,
			`{"id":18446744073709551615,"error":"unknown cmd: nope"}`, false},
		{`{"id":3,"cmd":"blake256","data":"zz"}`,
			`{"id":3,"error":"blake256: bad hex argument: `, true},
		// A request that does not decode gets an answer without an id.
		// encoding/json's error texts vary between Go releases, so these
		// match on the start alone.
		{`{"id":-1,"cmd":"blake256"}`, `{"error":"bad request: `, true},
		{`not json`, `{"error":"bad request: `, true},
		{`{"id":9,"cmd":"blake256"}`, `{"id":9,"result":"` + result + `"}`, false},
	}
	lines := make([]string, 0, len(tests))
	for _, test := range tests {
		lines = append(lines, test.line)
	}
	got := strings.Split(serveAll(t, strings.NewReader(strings.Join(lines, "\n"))), "\n")
	if got[len(got)-1] != "" {
		t.Fatalf("output does not end in a newline: %q", got)
	}
	got = got[:len(got)-1]
	i := 0
	for _, test := range tests {
		if test.want == "" {
			continue
		}
		switch {
		case i >= len(got):
			t.Fatalf("%s: no response", test.line)
		case test.prefix && !strings.HasPrefix(got[i], test.want),
			!test.prefix && got[i] != test.want:
			t.Errorf("%s: got %s, want %s", test.line, got[i], test.want)
		}
		i++
	}
	if i != len(got) {
		t.Errorf("got %d responses, want %d: %q", len(got), i, got)
	}
}

// TestLineLimit checks a line of exactly maxLineBytes is served, and that a
// longer one, ending one byte past the limit or several reads past it, is
// answered with one error and read through its newline, so the line after it
// is still served.
func TestLineLimit(t *testing.T) {
	digest := blake256.Sum256(nil)
	result := hex.EncodeToString(digest[:])
	request := `{"cmd":"blake256","data":""}`
	input := io.MultiReader(
		strings.NewReader(request),
		&repeated{' ', maxLineBytes - len(request)},
		strings.NewReader("\n"),
		&repeated{'x', maxLineBytes + 1},
		strings.NewReader("\n"),
		&repeated{'x', maxLineBytes + 3<<20},
		strings.NewReader("\n"+`{"id":2,"cmd":"blake256","data":""}`+"\n"),
	)

	tooLong := `{"error":"bad request: line exceeds 67108864 bytes"}` + "\n"
	want := `{"result":"` + result + `"}` + "\n" + tooLong + tooLong +
		`{"id":2,"result":"` + result + `"}` + "\n"
	if got := serveAll(t, input); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

// TestLineLimitMemory checks an over-long line is not held: reading one eight
// times maxLineBytes long allocates less than its length all told, where
// holding it whole would allocate more than that for the last copy alone.
func TestLineLimitMemory(t *testing.T) {
	const length = 8 * maxLineBytes
	in := bufio.NewReaderSize(io.MultiReader(&repeated{'x', length},
		strings.NewReader("\n")), 1<<20)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := readLine(in)
	runtime.ReadMemStats(&after)
	if !errors.Is(err, errLineTooLong) {
		t.Fatalf("got error %v, want %v", err, errLineTooLong)
	}
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc >= length {
		t.Errorf("reading a %d-byte line allocated %d bytes", length, alloc)
	}
}

// writeRecorder records each write made to it.
type writeRecorder struct {
	writes []string
}

func (w *writeRecorder) Write(p []byte) (int, error) {
	w.writes = append(w.writes, string(p))
	return len(p), nil
}

// TestBatchedRequests checks two requests that arrive in one read are both
// answered, in one write.
func TestBatchedRequests(t *testing.T) {
	input := `{"id":1,"cmd":"blake256","data":""}` + "\n" +
		`{"id":2,"cmd":"hash_string","data":"` + strings.Repeat("00", 32) + `"}` + "\n"
	var rec writeRecorder
	err := serve(bufio.NewReaderSize(strings.NewReader(input), 1<<20),
		bufio.NewWriterSize(&rec, 1<<20), handleLine)
	if err != nil {
		t.Fatalf("serve: %v", err)
	}
	if len(rec.writes) != 1 {
		t.Fatalf("got %d writes, want 1: %q", len(rec.writes), rec.writes)
	}
	lines := strings.Split(strings.TrimSuffix(rec.writes[0], "\n"), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], `{"id":1,"result":`) ||
		!strings.HasPrefix(lines[1], `{"id":2,"result":`) {
		t.Errorf("got %q, want the answers to ids 1 and 2", rec.writes[0])
	}
}

// TestWaitingClient checks a client that sends a request and waits, with its
// input left open, has its answer, including when the start of its next
// request has already arrived.
func TestWaitingClient(t *testing.T) {
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	defer inW.Close()
	defer outR.Close()
	done := make(chan error, 1)
	go func() {
		done <- serve(bufio.NewReaderSize(inR, 1<<20), bufio.NewWriterSize(outW, 1<<20),
			handleLine)
		outW.Close()
	}()
	replies := make(chan string)
	go func() {
		r := bufio.NewReader(outR)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				close(replies)
				return
			}
			replies <- line
		}
	}()
	await := func(wantPrefix string) {
		t.Helper()
		select {
		case line := <-replies:
			if !strings.HasPrefix(line, wantPrefix) {
				t.Fatalf("got %q, want a line starting %q", line, wantPrefix)
			}
		case <-time.After(30 * time.Second):
			t.Fatalf("no answer starting %q within 30s", wantPrefix)
		}
	}
	send := func(s string) {
		t.Helper()
		if _, err := io.WriteString(inW, s); err != nil {
			t.Fatal(err)
		}
	}

	send(`{"id":1,"cmd":"blake256","data":""}` + "\n")
	await(`{"id":1,"result":`)
	send(`{"id":2,"cmd":"blake256","data":""}` + "\n" + `{"id":3,`)
	await(`{"id":2,"result":`)
	send(`"cmd":"blake256","data":""}` + "\n")
	await(`{"id":3,"result":`)
	inW.Close()
	if err := <-done; err != nil {
		t.Fatalf("serve: %v", err)
	}
}

// TestPanickingRequest checks a request that panics still takes serve down,
// and only once the answer to the request that arrived ahead of it, in the
// same read, is written out.
func TestPanickingRequest(t *testing.T) {
	answer := func(line []byte) response {
		if bytes.Contains(line, []byte(`"cmd":"panic"`)) {
			panic("request panicked")
		}
		return handleLine(line)
	}
	input := `{"id":1,"cmd":"blake256","data":""}` + "\n" +
		`{"id":2,"cmd":"panic"}` + "\n" +
		`{"id":3,"cmd":"blake256","data":""}` + "\n"
	var out bytes.Buffer
	panicked := func() (p any) {
		defer func() { p = recover() }()
		_ = serve(bufio.NewReaderSize(strings.NewReader(input), 1<<20),
			bufio.NewWriterSize(&out, 1<<20), answer)
		return nil
	}()
	if panicked != "request panicked" {
		t.Fatalf("serve returned or panicked with %v, want the request's panic",
			panicked)
	}
	digest := blake256.Sum256(nil)
	want := `{"id":1,"result":"` + hex.EncodeToString(digest[:]) + `"}` + "\n"
	if got := out.String(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
