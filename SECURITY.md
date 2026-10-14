# Security boundary

MoonDNSSEC 0.1.0 is unaudited. Passing tests is not a security certification. Do not
replace a mature production resolver without independent review and additional
interoperability, operational and adversarial testing. Crypto correctness depends
on MoonCrypt; SHA256 DS/key-tag association depends on MoonZoneGuard.

## Caller trust responsibilities

The caller must establish the authenticity of an out-of-band anchor. Every use of
authenticate_with_key is an explicit trust assertion. Parsed keys, unsigned network
records, filenames and claimed identities are not anchors. Use anchor_keys and
signed delegate_keys for an anchored chain. Keep DNS response query binding,
bailiwick, referral selection, positive wildcard proof closure, transports and
negative-cache SOA processing in the resolver. Signature-authenticated RRset is
not equivalent to a Secure full DNS response.

## Untrusted input

Input is an uncompressed individual resource record, not a packet slice with
compression pointers. Absolute names, DNS length bounds, RDATA length, record count,
signing bytes, signature/key cross-product, proof count, chain/ancestor depth and
NSEC3 iterations are checked. Known unimplemented name-bearing RDATA types fail
closed. Arbitrary opaque types follow RFC3597 and are not interpreted as packets.
Limits do not bound all application memory or network fetching outside the library.

Only fresh, same-zone, single-record, non-wildcard-expanded authenticated denial
sets are accepted. NSEC3 parameter mixing, aliases, delegation boundaries, existing
query/wildcard owners, incomplete closest-encloser proof and opt-out general
NXDOMAIN do not become Secure. Exact insecure delegation is a distinct result.
No automatic opt-out delegation discovery or NSEC empty-nonterminal inference exists.

## State and clock

All trust-state fields are private. Arrays returned to callers are copies. Bytes
are immutable under the tested compiler. External construction/mutation rejection
is exercised by scripts/check_encapsulation.py. No serialization/import constructor
allows turning an arbitrary cached object into TrustedKeys or AuthenticatedSet.

A caller-supplied UInt time uses DNSSEC serial arithmetic. Validity intervals must
be shorter than half the serial space; policy skew is limited to one hour. Zero
lifetime can represent a just-expired signature inside tolerance but cannot be
reused as a fresh proof/cache record. A backwards clock change invalidates cached
trust rather than refreshing it. Callers must choose a reliable wall clock and
must not repeatedly rebuild anchors at an old timestamp to extend trust.

## Reporting

Report non-sensitive issues in the repository issue tracker. For an exploitable
vulnerability, use GitHub private vulnerability reporting if available; otherwise
request a private channel without posting exploit details or credentials. No
response-time guarantee or audited/production-support claim is made.
