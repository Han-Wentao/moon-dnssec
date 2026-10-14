# Architecture and invariants

## Layers

1. model/name/key/signature/record: bounded policies and canonical uncompressed input.
2. association: adapter to the existing MoonZoneGuard SHA256 DNSKEY fingerprint.
3. signed_input/crypto: RFC4034 canonical input and MoonCrypt signature verification.
4. authenticate/trust/chain: explicit trust, complete DNSKEY authentication and DS hops.
5. bitmap/nsec/nsec3: strict proof record decoding without any trust assertion.
6. freshness/nsec_nxdomain/nsec3_nxdomain: authenticated denial closure and cache output.

All work is synchronous, deterministic for supplied bytes/time/policy, and offline.
Neither parsing nor a DS digest association establishes cryptographic trust.

## Canonical signing data

Names are lowercased only for ASCII A..Z octets, keeping binary label octets intact.
DNS name order compares labels from the root side, then byte strings; presentation
string ordering is wrong. Name size is at most 255 wire bytes; each label is at most
63. Known supported embedded-name RDATA is canonicalized with no compression.

An RRset has one owner and one type, implicit IN class. RRSIG signer contains the
owner. Label-count reconstruction cannot move the signing owner outside that zone.
Signing data starts with the RRSIG header/signer (without signature), then canonical
RRs ordered by RDATA and deduplicated. Wire TTL is the RRSIG original TTL, not the
received/cache TTL. Bounds are checked before sort and concatenation.

## Trust transitions

anchor_keys requires the supplied anchor to occur in the complete DNSKEY RRset and
a valid RRSIG under that key. Revoked/non-zone keys cannot verify, though their bytes
may occur in the signed set. Only enabled signing algorithms enter TrustedKeys.

delegate_keys requires a distinct child below the supplied parent. First verify
the parent-side DS RRset, then require a supported DS association to a child key,
then use that key to authenticate the entire child DNSKEY set. No DS is not enough
to label a delegation insecure. Depth, candidate cross-products and inherited
freshness are bounded; every failure leaves no partially trusted child result.

## Denial

Public Nsec/Nsec3 parser results are untrusted inspection data. Denial entrypoints
consume only AuthenticatedSet. Proofs must be fresh, same signer zone/type,
single-record and not wildcard-expanded. Exact-name NODATA excludes requested type
and CNAME. NS without SOA marks a delegation; DS absence at such an exact owner is
InsecureDelegation, while general parent-side denial below a cut is Indeterminate.
DS denial at the signer's own apex cannot be used as parent evidence.

NXDOMAIN needs a proven closest encloser, nonexistence of the next-closer name, and
nonexistence of its wildcard. NSEC requires an explicit exact-owner closest-encloser
record. NSEC3 hashes ancestors under one parameter set; hashing depth and iterations
are bounded. Interval endpoints are excluded. NSEC3 opt-out interval coverage does
not authorize Secure general NXDOMAIN. Wildcard NODATA, empty-nonterminal inference
for NSEC and complete positive-wildcard response validation are outside this release.

## Freshness and API encapsulation

Lifetime is the minimum of received TTL, original TTL, remaining RRSIG validity and
all ancestor trust bounds. Cached objects use serial elapsed time, not new signature
verification at a falsely repeated old clock. Cache records are copied and receive
residual TTL. Proof lifetime is not RFC2308 negative-cache TTL.

AuthenticatedSet, TrustedKeys, Name, Record, Dnskey and proof structures hide fields;
only validated constructors or genuine authentication can produce trusted state.
Four compiler-negative probes prevent consumer construction or array mutation.
Whitebox tests can construct artificial states for branch testing; public API
integration tests separately prove genuine signature-to-denial transitions.
