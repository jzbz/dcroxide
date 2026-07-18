module github.com/jzbz/dcroxide/tools/oracle

go 1.24.0

// Pinned to the parity target, dcrd master commit 452c1a6c: every module
// dcrd's go.mod replaces with an in-tree dir whose source differs from
// its published release uses the pseudo-version at that commit (stake,
// standalone, edwards, secp256k1, gcs, txscript, wire), so the oracle
// links the same code the dcrd binary at 452c1a6c does.  The remaining
// pins (chainhash, chaincfg, blake256, dcrutil, uint256, base58) are
// byte-identical to the in-tree sources at that commit.
require (
	github.com/decred/base58 v1.0.6
	github.com/decred/dcrd/blockchain/stake/v5 v5.0.3-0.20260716050852-452c1a6c35df
	github.com/decred/dcrd/blockchain/standalone/v2 v2.3.1-0.20260716050852-452c1a6c35df
	github.com/decred/dcrd/chaincfg/chainhash v1.0.5
	github.com/decred/dcrd/chaincfg/v3 v3.3.0
	github.com/decred/dcrd/crypto/blake256 v1.1.0
	github.com/decred/dcrd/dcrec/edwards/v2 v2.0.5-0.20260716050852-452c1a6c35df
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.2-0.20260716050852-452c1a6c35df
	github.com/decred/dcrd/dcrutil/v4 v4.0.3
	github.com/decred/dcrd/gcs/v4 v4.1.2-0.20260716050852-452c1a6c35df
	github.com/decred/dcrd/math/uint256 v1.0.2
	github.com/decred/dcrd/txscript/v4 v4.1.3-0.20260716050852-452c1a6c35df
	github.com/decred/dcrd/wire v1.7.6-0.20260716050852-452c1a6c35df
)

require github.com/decred/dcrd/dcrec v1.0.1

require (
	github.com/agl/ed25519 v0.0.0-20170116200512-5312a6153412 // indirect
	github.com/dchest/siphash v1.2.3 // indirect
	github.com/decred/dcrd/crypto/rand v1.0.1 // indirect
	github.com/decred/dcrd/crypto/ripemd160 v1.0.2 // indirect
	github.com/decred/dcrd/database/v3 v3.0.3 // indirect
	github.com/decred/slog v1.2.0 // indirect
	github.com/klauspost/cpuid/v2 v2.0.9 // indirect
	golang.org/x/crypto v0.33.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	lukechampine.com/blake3 v1.3.0 // indirect
)
