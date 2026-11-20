# Issuers whose signature Go verifies and the provider does not

Four PEM files, written by a short Go 1.27.3 program with `crypto/x509`:
two client CA pools of one root each, and a client leaf under each. The keys
were not kept.

- `p224-root.pem`: `CN=p224-root`, self-signed, on a P-224 key, with basic
  constraints (cA) and key usage certificate signing.
- `p224-leaf.pem`: `CN=p224-leaf`, on a P-256 key, issued by `p224-root`
  under ecdsa-with-SHA256, with extended key usage clientAuth.
- `rsa1024-root.pem`: `CN=rsa1024-root`, self-signed, on an RSA-1024 key,
  with the same extensions as `p224-root`.
- `rsa1024-leaf.pem`: `CN=rsa1024-leaf`, on the same P-256 key, issued by
  `rsa1024-root` under sha256WithRSAEncryption, with extended key usage
  clientAuth.

Each is valid from 2024-01-01 00:00:00 to 2049-12-31 23:59:59 UTC. The
program checked each leaf's signature with Go's `CheckSignatureFrom` before
writing it, so Go's `Verify` builds the chain leaf, root from each pool. The
provider has no P-224 algorithm, and keeps ring's least RSA key of 2048
bits, so neither signature verifies there.

`a_search_through_an_issuer_the_provider_cannot_verify_is_left_to_webpki`,
in `src/clientcert.rs`, holds the chain search's replay to leaving these
refusals to webpki rather than vouching for Go's unknown authority, and
holds Go's acceptance through the oracle when it is present.
