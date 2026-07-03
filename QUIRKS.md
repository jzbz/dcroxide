# Quirks ledger

dcrd's behavior at the pinned tag (`release-v2.1.5`) is the specification —
including where it deviates from written documentation (DCPs, `docs/`). Every
intentional reproduction of such a deviation is recorded here, with a test
pinning it so it cannot silently regress.

Entry format:

```
## QK-NNNN — short title

- **Where:** dcrd package / dcroxide crate + item
- **What:** the behavior, and what the docs/spec say instead
- **Why reproduced:** consensus / wire / RPC compatibility rationale
- **Pinned by:** test name(s)
```

No entries yet.
