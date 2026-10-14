# Strict semantic duplication review — 2026-10-14

## Decision and fingerprint

MoonDNSSEC authenticates supplied uncompressed IN RRsets from explicit anchors:
canonical RRSIG input, cryptographic validation, complete DNSKEY sets, signed DS
chains, fresh NSEC/NSEC3 exact NODATA and supported closest-encloser NXDOMAIN.
Resolver integrators, authoritative tooling and offline auditors reuse a stable API.
It is not a DNS server, parser, rollout planner or new crypto primitive.

Within the recorded accessible scope, no maintained direct substitute for this
core workflow was found. This is a bounded judgment, not global uniqueness or an
official eligibility verdict. DS association genuinely overlaps MoonZoneGuard and
is **imported**, not independently reimplemented or represented as novel work.

## Three distinct candidate domains

Scores are judgments, 1–5: breadth/users/reuse/duplication/depth/validation/schedule/
maintenance. Hard duplication failure overrides totals.

| Candidate | Scores / total | Source evidence | Decision |
|---|---|---|---|
| DNSSEC authentication/denial | 5,5,5,3,5,5,4,4 / 36 | MoonZoneGuard DNSSEC source/tests; DNS parsers; crypto interfaces | Pass with dependency reuse and limited offline scope |
| Survival/Cox analysis | 5,4,5,1,4,5,4,4 / 32 | Lyl66655/moon-survival 0.2.4, src/cox_ph.mbt and cox_ph_test.mbt | Reject: existing model/fitting workflow directly substitutes |
| DWARF DIE reader | 4,4,5,1,5,4,3,3 / 29 | wuhaiting321/moonbit-dwarfscope (dwarfscope 0.1.1), src/dwarf_die/abbrev.mbt and die_test.mbt | Reject: abbreviation/DIE parsing directly overlaps |

Permanent registry searched; full relevant fingerprints read. Rejected MoonCT
remains rejected for RFC6962 Merkle overlap with MoonSecureCodec/MoonEvidence.
No renamed continuation or old code/history reuse. MoonDNSSEC was reserved before
implementation and has a separate directory/repository/history.

## Executed searches and limitations

Installed osc2026-guide Project Research Guide was executed as retrieval guidance,
not a uniqueness certificate. MoonCakes searches used limit 100: DNSSEC, DNSKEY,
RRSIG, NSEC3, DNS validation, authenticated denial, canonical RRset, DS DNSKEY,
DNS安全, DNSSEC验证; other domains survival/Cox and DWARF. Public module pages,
exact versions, GitHub metadata, non-truncated recursive trees, representative
source/tests/interfaces were fetched. Adjacent tests were read, not executed.

GitHub MoonBit DNSSEC/DNSKEY/NSEC3/RRSIG queries and official awesome-moonbit README
were checked. Release recheck 2026-10-14 repeated searches and reverse code queries:
authenticate_rrset (0), closest encloser (0), NSEC3 (6), RRSIG (3), each with
incomplete_results=false. Nonzero hits inspected. Known MoonZoneGuard source is
absent from code hits, proving index gaps. No same-name package/zero hits is NOT
uniqueness proof. General web search returned no usable evidence and was not
counted. Timestamped raw evidence remains outside this public repository.

## Actual-source comparison matrix

| Existing source | Users / inputs / task | Output / interface / algorithm | Class and scope distinction |
|---|---|---|---|
| [geniuszby/moonzoneguard](https://github.com/geniuszby/moonzoneguard), 0.3.0, DNSSEC_LINK.md, dnssec_link.mbt, dnssec_link_wbtest.mbt | Operators, supplied zones, deployment analysis | SHA256 DS association/key tag, rollout diagnostics; explicitly unchecked RRSIG | Highly adjacent; identical association reused as dependency, not new code. No authenticated RRset/chain/denial substitute |
| [O6lvl4/dns-checker](https://github.com/O6lvl4/dns-checker), src/dnssec/dnssec.mbt | Native DNS diagnostic lookups | DNSKEY/DS presence; valid:true is diagnostic, not signature verification | Same domain, distinct core task |
| [chgttyyr/moon_dns](https://github.com/chgttyyr/moon_dns), 0.1.0, src/codec/codec.mbt and codec_golden_test.mbt | Authoritative server, packets/zones | RFC1035/6891 codec, compression and dispatch | Adjacent; packet/zone parser and server are explicitly excluded |
| [Juwan-Hwang/moon-certified](https://github.com/Juwan-Hwang/moon-certified), 0.1.1, net/dns/dns.mbt and dns_test.mbt | Algorithm users, DNS messages | Query construction/name/message parsing | Adjacent, not trust/proof authentication |
| [usagi-star/mooncap](https://github.com/usagi-star/mooncap), 0.1.0, src/decode/dns.mbt and dns_test.mbt | Capture analysts, packet bytes | Bounded message decoding/typed errors | Release recheck inspected actual source/tests; not cryptographic authentication |
| [moonbit-community/win32.mbt](https://github.com/moonbit-community/win32.mbt), generated/windows/win32/network_management/dns/types_0.mbt | Windows API consumers | DNSNSEC3DATA aliases and generated constants | Binding hits, not portable MoonBit proof workflow |
| [moonbitstack/moonzero](https://github.com/moonbitstack/moonzero), restconf.mbt | REST service configuration | ErrSignatureConfig request-signature settings | RRSIG substring false positive; actual source is HTTP config, not DNSSEC |
| [moonbitstack/mooncrypt](https://github.com/moonbitstack/mooncrypt), 0.3.1, hash/RSA/ECDSA/Ed25519 interfaces/tests | Crypto consumers, byte keys/signatures | Hash and signature primitives | Imported dependency; arithmetic not copied/reimplemented |

Metadata inspected 2026-10-14 reported last pushes: MoonZoneGuard/MoonCrypt
2026-09-27, MoonDNS 2026-09-28, moon-certified 2026-08-27, survival/dwarfscope
2026-08-24. Recent activity is not security certification. These inspected core
repositories report Apache-2.0; see provenance for dependency license handling.

## Independent project versus extending the planner

MoonZoneGuard's central model is zone/deployment diagnosis. MoonDNSSEC needs a
security boundary around privately constructed authenticated objects, complete
DNSKEY verification, propagated freshness and signed denial closure. Resolver and
replay consumers do not need rollout models. Embedding this security-sensitive
workflow into a planner couples unrelated responsibilities; the shared association
API is instead reused and the planner can import this validator. This is a real
core-task distinction, not a claim that every shared standard utility is unique.
Eligibility remains the organizer's judgment if imported association itself is
considered disqualifying despite the distinct core.

## Release boundary

SHA256 DS only; algorithms 8/10/13/14/15; ASCII association labels; exact NODATA
and explicit closest-encloser NXDOMAIN. No positive-wildcard full-response policy,
opt-out discovery, RFC5011, root bootstrap, inferred empty-nonterminal NSEC or
production audit claim. Source recheck found no additional direct core substitute
in recorded scope and added mooncap/binding/HTTP comparisons. Inaccessible/private
projects and incomplete public indexes prevent an absolute uniqueness conclusion.
