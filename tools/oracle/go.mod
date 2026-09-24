module github.com/jzbz/dcroxide/tools/oracle

go 1.24.0

// Pinned to the parity target, dcrd master commit b9634e01: every module
// dcrd's go.mod replaces with an in-tree dir whose source differs from its
// published release uses the pseudo-version at that commit (stake, standalone,
// secp256k1, gcs, txscript, wire, and now chaincfg and blake256), so the
// oracle links the same code the dcrd binary at b9634e01 does.  edwards is
// pinned to the target pseudo-version too, although dcrd's go.mod does not
// replace it and dcrd links the v2.0.4 release: the in-tree non-test sources
// at b9634e01 are byte-identical to v2.0.4's, so both link the same code.  The
// remaining in-tree pins (chainhash, dcrutil, uint256, ripemd160, dcrec) are
// byte-identical to the in-tree sources at that commit.  base58 is not an
// in-tree module: dcrd's own go.mod requires github.com/decred/base58 v1.0.6
// from its separate repository, and this pin matches that requirement.
//
// Re-derived at b9634e01 rather than carried forward: for each of the sixteen
// in-tree modules, its directory at the target (nested modules excluded) was
// diffed against its latest tag in the same major.  Every tag-pinned module
// showed no difference in .go, go.mod or go.sum; every pseudo-pinned module
// differed in .go files; none differed in go.mod or go.sum alone.
//
// chaincfg and blake256 moved into the pseudo-version set when the target
// advanced past 452c1a6c: `b9b64533` adds the dcr-seed.jz.bz mainnet seeder to
// chaincfg, and blake256 picked up nolint directives.  Neither was still
// byte-identical to its published tag, which is the condition that decides
// which set a module belongs in -- re-check it on every target move rather
// than carrying the old split forward.  crypto/rand and database are pinned on
// the same rule even though their only divergence from their tags is comments,
// so the invariant stays mechanically checkable: every dcrd module either sits
// at the target pseudo-version or is byte-identical to its tag, with nothing
// resting on a judgement about whether a diff was cosmetic.
require (
	github.com/decred/base58 v1.0.6
	github.com/decred/dcrd/blockchain/stake/v5 v5.0.3-0.20260905015707-b9634e01770b
	github.com/decred/dcrd/blockchain/standalone/v2 v2.3.1-0.20260905015707-b9634e01770b
	github.com/decred/dcrd/chaincfg/chainhash v1.0.5
	github.com/decred/dcrd/chaincfg/v3 v3.3.1-0.20260905015707-b9634e01770b
	github.com/decred/dcrd/crypto/blake256 v1.1.1-0.20260905015707-b9634e01770b
	github.com/decred/dcrd/dcrec/edwards/v2 v2.0.5-0.20260905015707-b9634e01770b
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.2-0.20260905015707-b9634e01770b
	github.com/decred/dcrd/dcrutil/v4 v4.0.3
	github.com/decred/dcrd/gcs/v4 v4.1.2-0.20260905015707-b9634e01770b
	github.com/decred/dcrd/math/uint256 v1.0.2
	github.com/decred/dcrd/txscript/v4 v4.1.3-0.20260905015707-b9634e01770b
	github.com/decred/dcrd/wire v1.7.6-0.20260905015707-b9634e01770b
)

require github.com/decred/dcrd/dcrec v1.0.1

require (
	github.com/agl/ed25519 v0.0.0-20170116200512-5312a6153412 // indirect
	github.com/dchest/siphash v1.2.3 // indirect
	github.com/decred/dcrd/crypto/rand v1.0.2-0.20260905015707-b9634e01770b // indirect
	github.com/decred/dcrd/crypto/ripemd160 v1.0.2 // indirect
	github.com/decred/dcrd/database/v3 v3.0.4-0.20260905015707-b9634e01770b // indirect
	github.com/decred/slog v1.2.0 // indirect
	github.com/klauspost/cpuid/v2 v2.0.9 // indirect
	golang.org/x/crypto v0.33.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	lukechampine.com/blake3 v1.3.0 // indirect
)
