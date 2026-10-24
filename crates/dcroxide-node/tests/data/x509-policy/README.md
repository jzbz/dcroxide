# Go's certificate policy vectors

The `policy_*.pem` files are copied unchanged from Go 1.27.1's
`src/crypto/x509/testdata`. Go's `TestPoliciesValid` and `TestParsePolicies`
(`crypto/x509/verify_test.go`, `crypto/x509/parser_test.go`) read all but
three of them; `policy_intermediate_duplicate`, `policy_intermediate_invalid`
and `policy_intermediate_require_duplicate` sit beside them unread. Go took
them, with the test cases, from BoringSSL's X.509 tests. `LICENSE` is Go's
licence, under which Go distributes them.

`rpcrun.rs`'s `go_policies_valid_matches_gos_vectors` replays Go's
`TestPoliciesValid` table over them, and
`policies_go_refuses_to_parse_are_refused` its `TestParsePolicies`, with the
three unread intermediates, which Go's parser refuses too.
