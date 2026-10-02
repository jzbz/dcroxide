module github.com/jzbz/dcroxide/tools/fullblockgen

go 1.27.0

// Pinned to the parity target, dcrd master commit 6f6cf21b, by the rule
// tools/oracle/go.mod's header records: every dcrd module the generator links
// either sits at the pseudo-version at that commit or is a published tag whose
// .go, go.mod and go.sum files are byte-identical to the in-tree module there.
// dcrd's own go.mod replaces its modules with in-tree directories, and a
// `replace` does not apply to consumers, so the modules that differ from their
// latest tag (blockchain, chaincfg, blake256, crypto/rand, secp256k1, edwards,
// txscript, wire) are pinned to the pseudo-version and the generator links the
// same code dcrd's own fullblocks test does.  The remaining pins (chainhash,
// dcrutil, ripemd160, dcrec) are byte-identical to the in-tree sources at that
// commit.  The pseudo-versions were computed by `go get` at the full commit
// hash, followed by `go mod tidy`.
//
// Until 6f6cf21b this module kept chaincfg, blake256 and crypto/rand on their
// v3.3.0, v1.1.0 and v1.0.1 tags although the rule already called for the
// pseudo-version: the in-tree sources add a mainnet seeder name, nolint
// directives and comments, none of which reaches the regression network the
// battery runs on, so the vectors generated at 036b7090 were unaffected.  Do
// not bump any pin independently of a parity-target change.
require github.com/decred/dcrd/blockchain/v5 v5.1.2-0.20260927225945-6f6cf21bd26d

require (
	github.com/agl/ed25519 v0.0.0-20170116200512-5312a6153412 // indirect
	github.com/dchest/siphash v1.2.3 // indirect
	github.com/decred/base58 v1.0.6 // indirect
	github.com/decred/dcrd/chaincfg/chainhash v1.0.5 // indirect
	github.com/decred/dcrd/chaincfg/v3 v3.3.1-0.20260927225945-6f6cf21bd26d // indirect
	github.com/decred/dcrd/crypto/blake256 v1.1.1-0.20260927225945-6f6cf21bd26d // indirect
	github.com/decred/dcrd/crypto/rand v1.0.2-0.20260927225945-6f6cf21bd26d // indirect
	github.com/decred/dcrd/crypto/ripemd160 v1.0.2 // indirect
	github.com/decred/dcrd/dcrec v1.0.1 // indirect
	github.com/decred/dcrd/dcrec/edwards/v2 v2.0.5-0.20260927225945-6f6cf21bd26d // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.2-0.20260927225945-6f6cf21bd26d // indirect
	github.com/decred/dcrd/dcrutil/v4 v4.0.3 // indirect
	github.com/decred/dcrd/txscript/v4 v4.1.3-0.20260927225945-6f6cf21bd26d // indirect
	github.com/decred/dcrd/wire v1.7.6-0.20260927225945-6f6cf21bd26d // indirect
	github.com/decred/slog v1.2.0 // indirect
	github.com/klauspost/cpuid/v2 v2.0.9 // indirect
	golang.org/x/crypto v0.33.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	lukechampine.com/blake3 v1.3.0 // indirect
)
