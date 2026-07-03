module github.com/jzbz/dcroxide/tools/oracle

go 1.24.0

// Pinned to the versions required by dcrd release-v2.1.5 (the parity target).
require (
	github.com/decred/dcrd/chaincfg/chainhash v1.0.5
	github.com/decred/dcrd/crypto/blake256 v1.1.0
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0
	github.com/decred/dcrd/wire v1.7.5
)

require (
	github.com/klauspost/cpuid/v2 v2.0.9 // indirect
	lukechampine.com/blake3 v1.3.0 // indirect
)
