// SPDX-License-Identifier: ISC

// Command fullblockgen dumps dcrd's full block test battery
// (`fullblocktests.Generate`) in the line-delimited form replayed by
// dcroxide's `fullblock_vectors` test.
//
// The battery is dcrd's own scripted regression-network chain — fully signed
// blocks with real tickets, votes, revocations and reorganizations, alongside
// hundreds of specifically invalid variants and their expected rejection
// kinds. Running the generator inside dcrd's package is what makes the dump an
// oracle rather than a transcription: the expectations are dcrd's, at the
// pinned parity target, not this project's reading of them.
//
// The module is pinned to the parity target in go.mod. Regenerate whenever the
// target moves across a commit that touches `blockchain/fullblocktests` —
// `a38c0195` did, changing two instances from ErrImmatureSpend to
// ErrMissingTxOut once stake transactions were explicitly barred from spending
// same-block outputs.
//
// Rows, one per test instance, mirroring what the replay expects:
//
//	now <unix seconds>              generation time; the battery builds its
//	                                too-far-in-the-future block relative to
//	                                the wall clock, so the replay needs it
//	accept <name> <main> <orphan> <blockhex>
//	reject <name> <kind> <blockhex>
//	orphanorreject <name> <blockhex>
//	tip <name> <hash>               hash in internal byte order
//	noncanon <name> <rawhex>
//	skipnano <name> <kind>          a rejection that only exists for in-memory
//	                                blocks: the wire encoding stores whole
//	                                seconds, so a sub-second timestamp cannot
//	                                survive serialization and the instance
//	                                cannot be replayed from bytes
//
// Usage:
//
//	fullblockgen > ../../crates/dcroxide-blockchain/tests/data/fullblock_vectors.txt
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/decred/dcrd/blockchain/v5/fullblocktests"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fullblockgen: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	tests, err := fullblocktests.Generate(false)
	if err != nil {
		return fmt.Errorf("generating battery: %w", err)
	}

	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()

	fmt.Fprintf(out, "now %d\n", time.Now().Unix())

	for _, instances := range tests {
		for _, instance := range instances {
			switch ti := instance.(type) {
			case fullblocktests.AcceptedBlock:
				raw, err := ti.Block.Bytes()
				if err != nil {
					return fmt.Errorf("serializing %s: %w", ti.Name, err)
				}
				fmt.Fprintf(out, "accept %s %t %t %s\n", ti.Name, ti.IsMainChain,
					ti.IsOrphan, hex.EncodeToString(raw))

			case fullblocktests.RejectedBlock:
				// A sub-second timestamp is rejected in memory but cannot be
				// expressed on the wire, so the instance is recorded as
				// unreplayable rather than dropped silently.
				if ti.Block.Header.Timestamp.Nanosecond() != 0 {
					fmt.Fprintf(out, "skipnano %s %v\n", ti.Name, ti.RejectKind)
					continue
				}
				raw, err := ti.Block.Bytes()
				if err != nil {
					return fmt.Errorf("serializing %s: %w", ti.Name, err)
				}
				fmt.Fprintf(out, "reject %s %v %s\n", ti.Name, ti.RejectKind,
					hex.EncodeToString(raw))

			case fullblocktests.OrphanOrRejectedBlock:
				raw, err := ti.Block.Bytes()
				if err != nil {
					return fmt.Errorf("serializing %s: %w", ti.Name, err)
				}
				fmt.Fprintf(out, "orphanorreject %s %s\n", ti.Name, hex.EncodeToString(raw))

			case fullblocktests.ExpectedTip:
				hash := ti.Block.BlockHash()
				fmt.Fprintf(out, "tip %s %s\n", ti.Name, hex.EncodeToString(hash[:]))

			case fullblocktests.RejectedNonCanonicalBlock:
				fmt.Fprintf(out, "noncanon %s %s\n", ti.Name, hex.EncodeToString(ti.RawBlock))

			default:
				return fmt.Errorf("unknown test instance type %T", instance)
			}
		}
	}
	return nil
}
