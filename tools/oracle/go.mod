module github.com/jzbz/dcroxide/tools/oracle

go 1.24.0

// Pinned to the parity target, dcrd master commit 382ff4dd: every module
// dcrd's go.mod replaces with an in-tree dir whose source differs from its
// latest published tag uses the pseudo-version at that commit (standalone,
// secp256k1, gcs, txscript, chaincfg and blake256), so the oracle links the
// same code the dcrd binary at 382ff4dd does.  edwards is pinned to the target
// pseudo-version too, although dcrd's go.mod does not replace it and dcrd
// links the v2.0.4 release: the in-tree non-test sources at 382ff4dd are
// byte-identical to v2.0.4's, so both link the same code.  The remaining
// in-tree pins (stake, wire, chainhash, dcrutil, uint256, ripemd160, dcrec)
// are byte-identical to the in-tree sources at that commit.  base58 is not an
// in-tree module: dcrd's own go.mod requires github.com/decred/base58 v1.0.6
// from its separate repository, and this pin matches that requirement.
//
// Re-derived at 382ff4dd rather than carried forward: for each of the sixteen
// in-tree modules, its directory (nested modules excluded) was diffed between
// 6f6cf21b and 382ff4dd, and at 382ff4dd against its latest tag in the same
// major as the module proxy lists it.  Three of dcrd's nested modules were
// tagged after 6f6cf21b: wire v1.8.0 (`efa17f60`), blockchain/stake v5.0.3
// (`7e3dd854`) and mixing v0.7.5 (`46fc30ad`).  The oracle links the first
// two, and both moved from the pseudo-version to the new tag: at 382ff4dd each
// directory is byte-identical to its tag in .go, go.mod and go.sum.  Neither
// changed code between the pins: wire changed copyright lines in four .go
// files and two tests, and stake changed one test's copyright line and its
// go.mod and go.sum (now requiring wire v1.8.0 and secp256k1 v4.4.1).  No
// other linked module's directory changed.  Against the tags, every tag-pinned
// module showed no difference in .go, go.mod or go.sum (the only file
// differing is the LICENSE the module zip copies in from the repository root);
// every pseudo-pinned module differed in .go files; none differed in go.mod or
// go.sum alone.  So the split is the one recorded at 6f6cf21b with stake and
// wire moved to the tag side.  The pseudo-versions were computed by `go get`
// at the full commit hash, followed by `go mod tidy`, not written by hand.
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
	github.com/decred/dcrd/blockchain/stake/v5 v5.0.3
	github.com/decred/dcrd/blockchain/standalone/v2 v2.3.1-0.20261013223639-382ff4ddb2aa
	github.com/decred/dcrd/chaincfg/chainhash v1.0.5
	github.com/decred/dcrd/chaincfg/v3 v3.3.1-0.20261013223639-382ff4ddb2aa
	github.com/decred/dcrd/crypto/blake256 v1.1.1-0.20261013223639-382ff4ddb2aa
	github.com/decred/dcrd/dcrec/edwards/v2 v2.0.5-0.20261013223639-382ff4ddb2aa
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.2-0.20261013223639-382ff4ddb2aa
	github.com/decred/dcrd/dcrutil/v4 v4.0.3
	github.com/decred/dcrd/gcs/v4 v4.1.2-0.20261013223639-382ff4ddb2aa
	github.com/decred/dcrd/math/uint256 v1.0.2
	github.com/decred/dcrd/txscript/v4 v4.1.3-0.20261013223639-382ff4ddb2aa
	github.com/decred/dcrd/wire v1.8.0
)

require github.com/decred/dcrd/dcrec v1.0.1

require (
	github.com/agl/ed25519 v0.0.0-20170116200512-5312a6153412 // indirect
	github.com/dchest/siphash v1.2.3 // indirect
	github.com/decred/dcrd/crypto/rand v1.0.2-0.20261013223639-382ff4ddb2aa // indirect
	github.com/decred/dcrd/crypto/ripemd160 v1.0.2 // indirect
	github.com/decred/dcrd/database/v3 v3.0.4-0.20261013223639-382ff4ddb2aa // indirect
	github.com/decred/slog v1.2.0 // indirect
	github.com/klauspost/cpuid/v2 v2.0.9 // indirect
	golang.org/x/crypto v0.33.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	lukechampine.com/blake3 v1.3.0 // indirect
)
