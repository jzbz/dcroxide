module github.com/jzbz/dcroxide/tools/oracle

go 1.24.0

// Pinned to the parity pin, dcrd master commit 3360ae4d: every module
// dcrd's go.mod replaces with an in-tree dir whose source differs from its
// latest published tag uses the pseudo-version at that commit (standalone,
// secp256k1, gcs, txscript, chaincfg and blake256), so the oracle links the
// same code the dcrd binary at 3360ae4d does.  edwards sits at the pin's
// pseudo-version too, although dcrd's go.mod does not replace it and dcrd
// links the v2.0.4 release: the in-tree non-test sources at 3360ae4d are
// byte-identical to v2.0.4's, so both link the same code.  The remaining
// in-tree pins (stake, wire, chainhash, dcrutil, uint256, ripemd160, dcrec)
// are byte-identical to the in-tree sources at that commit.  base58 is not an
// in-tree module: dcrd's own go.mod requires github.com/decred/base58 v1.0.6
// from its separate repository, and this pin matches that requirement.
//
// Checked again at 3360ae4d rather than carried forward: no module was tagged
// after 382ff4dd, and none of the sixteen in-tree modules' directories (nested
// modules excluded) changed between 382ff4dd and 3360ae4d, the one commit
// between them changing only internal/rpcserver in dcrd's root module, which
// the oracle does not link.  So the comparison against the tags made at
// 382ff4dd still holds, and with it the split: every pseudo-pinned module
// moves to the new commit, and each one's files, as the module proxy serves
// them, are byte-identical at both commits.  At 382ff4dd, three of dcrd's
// nested modules had been tagged since 6f6cf21b: wire v1.8.0 (`efa17f60`),
// blockchain/stake v5.0.3 (`7e3dd854`) and mixing v0.7.5 (`46fc30ad`); the
// oracle links the first two, at their tags, each byte-identical to its
// directory in .go, go.mod and go.sum.  Against the tags, every tag-pinned
// module showed no difference in .go, go.mod or go.sum (the only file
// differing is the LICENSE the module zip copies in from the repository root);
// every pseudo-pinned module differed in .go files; none differed in go.mod or
// go.sum alone.  The pseudo-versions were computed by `go get` at the full
// commit hash, followed by `go mod tidy`, not written by hand.
//
// chaincfg and blake256 moved into the pseudo-version set when the pin
// advanced past 452c1a6c: `b9b64533` adds the dcr-seed.jz.bz mainnet seeder to
// chaincfg, and blake256 picked up nolint directives.  Neither was still
// byte-identical to its published tag, which is the condition that decides
// which set a module belongs in -- re-check it on every pin move rather
// than carrying the old split forward.  crypto/rand and database are pinned on
// the same rule even though their only divergence from their tags is comments,
// so the invariant stays mechanically checkable: every dcrd module either sits
// at the pin's pseudo-version or is byte-identical to its tag, with nothing
// resting on a judgement about whether a diff was cosmetic.
require (
	github.com/decred/base58 v1.0.6
	github.com/decred/dcrd/blockchain/stake/v5 v5.0.3
	github.com/decred/dcrd/blockchain/standalone/v2 v2.3.1-0.20261019113547-3360ae4dbef8
	github.com/decred/dcrd/chaincfg/chainhash v1.0.5
	github.com/decred/dcrd/chaincfg/v3 v3.3.1-0.20261019113547-3360ae4dbef8
	github.com/decred/dcrd/crypto/blake256 v1.1.1-0.20261019113547-3360ae4dbef8
	github.com/decred/dcrd/dcrec/edwards/v2 v2.0.5-0.20261019113547-3360ae4dbef8
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.2-0.20261019113547-3360ae4dbef8
	github.com/decred/dcrd/dcrutil/v4 v4.0.3
	github.com/decred/dcrd/gcs/v4 v4.1.2-0.20261019113547-3360ae4dbef8
	github.com/decred/dcrd/math/uint256 v1.0.2
	github.com/decred/dcrd/txscript/v4 v4.1.3-0.20261019113547-3360ae4dbef8
	github.com/decred/dcrd/wire v1.8.0
)

require github.com/decred/dcrd/dcrec v1.0.1

require (
	github.com/agl/ed25519 v0.0.0-20170116200512-5312a6153412 // indirect
	github.com/dchest/siphash v1.2.3 // indirect
	github.com/decred/dcrd/crypto/rand v1.0.2-0.20261019113547-3360ae4dbef8 // indirect
	github.com/decred/dcrd/crypto/ripemd160 v1.0.2 // indirect
	github.com/decred/dcrd/database/v3 v3.0.4-0.20261019113547-3360ae4dbef8 // indirect
	github.com/decred/slog v1.2.0 // indirect
	github.com/klauspost/cpuid/v2 v2.0.9 // indirect
	golang.org/x/crypto v0.33.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	lukechampine.com/blake3 v1.3.0 // indirect
)
