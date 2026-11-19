# A chain Go builds and drops for its key usage

Three PEM files, written by a Go program with `crypto/x509` during a review
of the client certificate verifier: one of the random chains it generated to
compare the verifier before and after a change, kept because it was the one
case where the verifier's error stopped matching Go's. The keys were not kept.

- `roots.pem`: the client CA pool, `CN=n1` (extended key usage serverAuth)
  and `CN=n0`.
- `sent.pem`: the certificates the client sends, four blocks: `CN=n12`
  issued by `CN=n10` (`pathlen:1`), a `CN=n10` whose issuer is named
  `CN=n10`, with extended key usage serverAuth, and a `CN=n10` issued by
  `CN=n1`, sent twice.
- `leaf.pem`: the client's certificate, `CN=n100`, issued by `CN=n12`, with
  extended key usage clientAuth.

Each is valid from 2026-09-20 14:13:20 to 2027-09-21 14:13:20 UTC. At
1790000000 (2026-09-21), Go 1.27's search builds one chain, leaf, `n12`,
the self-named `n10`, the `n10` that `n1` issued, `n1`, and `Verify` drops it
for its key usage, the intermediate's and the root's: `x509: certificate
specifies an incompatible key usage`. webpki's search, given `n1` as an
anchor, also reaches it through a path whose signature fails (the other
`n10` as the issuer of `n12`), and ranks that failure above the usage.

`a_chain_go_drops_for_its_usage_is_refused_for_it`, in `src/clientcert.rs`,
holds the verifier to Go's error here, and to Go's own verdict through the
oracle when it is present.
