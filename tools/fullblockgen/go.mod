module github.com/jzbz/dcroxide/tools/fullblockgen

go 1.27.0

// Pinned to the parity target, dcrd master commit 036b7090.  dcrd's own
// go.mod replaces several modules with in-tree directories whose source
// differs from the published release, and a `replace` does not apply to
// consumers, so those (wire, txscript, secp256k1, edwards) are pinned to the
// pseudo-version at that commit and the generator links the same code the dcrd
// binary does.  The remaining pins are byte-identical to the in-tree sources
// at that commit.  Do not bump them independently of a parity-target change.
require github.com/decred/dcrd/blockchain/v5 v5.1.2-0.20260821101557-036b70904431

require (
	github.com/agl/ed25519 v0.0.0-20170116200512-5312a6153412 // indirect
	github.com/dchest/siphash v1.2.3 // indirect
	github.com/decred/base58 v1.0.6 // indirect
	github.com/decred/dcrd/chaincfg/chainhash v1.0.5 // indirect
	github.com/decred/dcrd/chaincfg/v3 v3.3.0 // indirect
	github.com/decred/dcrd/crypto/blake256 v1.1.0 // indirect
	github.com/decred/dcrd/crypto/rand v1.0.1 // indirect
	github.com/decred/dcrd/crypto/ripemd160 v1.0.2 // indirect
	github.com/decred/dcrd/dcrec v1.0.1 // indirect
	github.com/decred/dcrd/dcrec/edwards/v2 v2.0.5-0.20260821101557-036b70904431 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.2-0.20260821101557-036b70904431 // indirect
	github.com/decred/dcrd/dcrutil/v4 v4.0.3 // indirect
	github.com/decred/dcrd/txscript/v4 v4.1.3-0.20260821101557-036b70904431 // indirect
	github.com/decred/dcrd/wire v1.7.6-0.20260821101557-036b70904431 // indirect
	github.com/decred/slog v1.2.0 // indirect
	github.com/klauspost/cpuid/v2 v2.0.9 // indirect
	golang.org/x/crypto v0.33.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	lukechampine.com/blake3 v1.3.0 // indirect
)
