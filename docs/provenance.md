# Provenance and licenses

This project is an original MoonBit DNSSEC verification library, not a line-by-line
port. AI assistance was used for design, implementation, tests, documentation and
verification orchestration. Responsibility remains with the participant.

| Source | License / status | Use and retained boundary |
| --- | --- | --- |
| moonbitstack/mooncrypt 0.3.1 | Apache-2.0 | imported Ed25519/ECDSA/RSA/SHA1 APIs; no copied primitive implementation |
| geniuszby/moonzoneguard 0.3.0 | Apache-2.0 | imported ResourceRecord and dnskey_ds_sha256 for key tags and SHA256 DS; no copied zone planner or digest implementation |
| MoonBit core | upstream package license | builtin data models/debug/base64 through imports |
| RFC4034/4035/5155/1982/2181/3597 | IETF specifications | behavior/reference only; no copied prose or code |
| Node.js built-in crypto / OpenSSL | installed runtime | independently generated public DNSKEY/message/signature/hash fixtures; no copied library code or retained private keys |

Normative documents:
- https://www.rfc-editor.org/rfc/rfc4034
- https://www.rfc-editor.org/rfc/rfc4035
- https://www.rfc-editor.org/rfc/rfc5155
- https://www.rfc-editor.org/rfc/rfc1982
- https://www.rfc-editor.org/rfc/rfc2181
- https://www.rfc-editor.org/rfc/rfc3597

Dependencies:
- https://mooncakes.io/docs/moonbitstack/mooncrypt@0.3.1/
- https://mooncakes.io/docs/geniuszby/moonzoneguard@0.3.0/
- https://github.com/moonbitstack/mooncrypt
- https://github.com/geniuszby/moonzoneguard

The standard Apache license text is retained in LICENSE. Dependency source is not
vendored or redistributed as this project's original implementation. Publication
package dependency metadata points to their own separately licensed packages.
Fixtures are synthetic documentation-range domains/addresses with public-only keys;
they are not captured private traffic or third-party proprietary datasets.
