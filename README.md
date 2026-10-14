# MoonDNSSEC

Bounded **offline DNSSEC authentication** for caller-supplied, uncompressed IN-class
resource-record sets. Module: **Han-Wentao/moon-dnssec@0.1.0**. Apache-2.0.

This is a verification library, not a recursive resolver, packet parser, zone-file
parser or DNSSEC deployment planner. Parsing DNSKEY or finding a DS record does not
establish trust. No audited-security or production-readiness claim is made.

## Install

In a MoonBit module run:

    moon add Han-Wentao/moon-dnssec@0.1.0

Add this to the consuming package's moon.pkg:

    import {
      "Han-Wentao/moon-dnssec" @dns,
    }

The release also requires MoonCrypt 0.3.1 and MoonZoneGuard 0.3.0. Use a current
MoonBit toolchain; the locally tested toolchain is recorded in docs/ci.md.

## Run the three workflows

    moon test --target js --deny-warn
    moon run --target js examples/offline

Expected output:

    resolver: signed child answer; cache TTL=40
    authoritative: canonical signing bytes=66
    audit: NSEC NXDOMAIN=Secure
    audit: NSEC3 NXDOMAIN=Secure

The example uses public, synthetic snapshots independently signed by Node.js
OpenSSL. No private signing material is included. Time is explicitly 150/160 in
these fixtures; substituting today's wall clock must reject their expired RRSIGs.

1. **Resolver integrators** supply a trusted anchor, complete DNSKEY sets, signed
   parent DS and child DNSKEY sets, then authenticate an answer and obtain residual
   cache TTLs. The library never fetches records or treats network presence as trust.
2. **Authoritative DNS tooling** supplies signed output and rebuilds canonical
   signing input to check signatures, key tags, label reconstruction and time
   windows. Returned bytes can be compared with independently produced signing data.
3. **Offline security audits** replay signed NSEC/NSEC3 proof snapshots and a query,
   receiving bounded NODATA/NXDOMAIN/delegation classifications or explicit failures.
   A parsed NSEC structure alone cannot be supplied as authenticated evidence.

## API flow

All operations return Result values. Use matching rather than unwrap on untrusted
production input (unwrap in the executable is for fixed successful fixtures only).

- Name::parse accepts absolute ASCII presentation names; Name::from_wire accepts
  canonicalizable binary labels without compression. Root is a single zero byte.
- Record::new(owner, type, ttl, rdata) checks wire-field bounds. Records are IN class.
- Dnskey::parse, Ds::parse and Rrsig::parse decode bounded record data.
- anchor_keys authenticates a **complete DNSKEY RRset** under an out-of-band key.
- delegate_keys verifies signed parent DS, associates child keys, authenticates the
  complete child DNSKEY set, and bounds depth and inherited freshness.
- authenticate_rrset accepts TrustedKeys; authenticate_with_key is the lower-level
  explicit caller-trust assertion API. Neither makes a complete DNS response secure.
- signing_input sorts/deduplicates canonical RDATA, substitutes original TTL and
  reconstructs wildcard owners from RRSIG labels.
- nsec_nodata / nsec3_nodata require exact-name authenticated proofs.
- nsec_nxdomain / nsec3_nxdomain require closest-encloser, next-closer and wildcard
  denial. Missing proof closure returns Indeterminate, not an invented success.
- AuthenticatedSet::cache_records returns a copied array with residual TTL.

Public interfaces are checked into pkg.generated.mbti. Executable source in
examples/offline/main.mbt is a complete usage reference; integration/proof_test.mbt
uses only public APIs for real signed NSEC/NSEC3 proof closure.

## Supported protocols and deliberate limits

| Area | Enabled | Not enabled |
| --- | --- | --- |
| Signatures | RSA/SHA256 (8), RSA/SHA512 (10), P256/SHA256 (13), P384/SHA384 (14), Ed25519 (15) | RSA/SHA1, Ed448, algorithm negotiation/network policy |
| RSA shape | 1024..4096-bit full-length odd modulus; bounded exponent; PKCS1 v1.5 | larger RSA keys, PSS DNSSEC variants |
| DS association | digest type 2 SHA256, reused from MoonZoneGuard | SHA1/SHA384 DS acceptance; non-ASCII DS owners |
| Name-bearing RDATA | NS, CNAME, PTR, DNAME, MX, SRV, SOA, NSEC | known unimplemented name-bearing types fail closed |
| Other RDATA | A/AAAA length checks, TXT character-string checks, opaque RFC3597 data | full semantic parsing of every IANA RR type |
| Denial | exact-name NODATA; explicit closest-encloser NXDOMAIN; exact insecure delegation | wildcard NODATA, inferred NSEC empty nonterminals, opt-out delegation discovery |
| NSEC3 | SHA1, salt/iterations limits, base32hex, one parameter set | opt-out general NXDOMAIN is Indeterminate |
| Trust | explicit anchor and supplied signed delegations | RFC5011 rollover, root bootstrap, online chain discovery |

Binary names can be parsed, but the reused DS/key-tag association API accepts only
ASCII host labels. This is a real limitation, not an assertion of full IDN support.

**Wildcard-expanded positive RRsets are signature-authenticated only.** Consult
is_wildcard_expansion and supply response-level wildcard/existence proof closure in
the resolver. This release does not implement that complete positive-response policy.
Denial lifetime is proof/trust freshness, not a substitute for negative-cache SOA
MINIMUM handling under RFC2308. The caller owns message assembly, bailiwick, query
matching, transport, clock selection, anchor authenticity and negative caching.

## Resource and freshness policies

Defaults: 256 records, 1 MiB signing input, 32 signature/key candidates, 64 denial
proofs, 16 delegation/ancestor depth, 100 NSEC3 iterations. validate applies hard
upper bounds. Signature validity uses RFC1982 serial arithmetic; intervals spanning
half the serial space and clock skew above one hour are rejected. TTLs never extend
signature or ancestor trust lifetime; expiry and backwards clock changes fail closed.

Types carrying trust have private fields and cannot be constructed by consumers.
Exported arrays are copies; negative external compiler checks verify construction
and field mutation rejection. No process-global mutable trust store is used.

## Verification and project boundaries

36 named tests cover core policies, canonical data, five independent OpenSSL crypto
vectors, DNSKEY anchors, signed delegation, signed NSEC/NSEC3 public-API integration,
truncation, alias/delegation boundaries and caching. Four negative compiler probes
verify encapsulation. See docs/ci.md for commands and platform distinctions.

See SECURITY.md for threat model and reporting; docs/architecture.md for invariants;
docs/competition/duplicate-check.md for bounded semantic research and adjacent
projects. MoonZoneGuard already provides DS association/deployment diagnostics:
this library **reuses**, rather than duplicates, that association capability and
adds offline cryptographic proof authentication. MoonCrypt provides primitives;
this project does not implement new cryptographic arithmetic.

## License, references and AI assistance

Apache-2.0; see LICENSE and NOTICE. Original DNSSEC validation glue/data models were
implemented with AI assistance, including tests and documentation. The participant
remains responsible for correctness, provenance and maintenance. Specifications are
RFC4034, RFC4035, RFC5155, RFC1982, RFC2181 and RFC3597; normative RFC text and upstream
implementations are not copied. Dependencies and their license boundaries are listed
in docs/provenance.md.
