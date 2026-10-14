# Reproducible engineering evidence

Audit: 2026-10-14; module Han-Wentao/moon-dnssec 0.1.0.

## Substantive scope

Run `python scripts/audit_scope.py`. Root production .mbt files only; excludes tests, examples, interfaces, dependencies, generated build artifacts and docs. 18 production files: **2114 physical lines; 1837 nonblank/noncomment lines**. Stricter latter measure exceeds 1500 without fixtures or padding.

## Actual local verification

moon info then moon fmt and moon fmt --check passed; .mbti private-field changes reviewed. Strict --deny-warn check/build passed JS, wasm-gc and plain wasm. 36 named tests passed JS and wasm-gc (same suite, not 72 distinct tests). Both runnable targets printed TTL=40, canonical bytes=66, Secure supported NSEC/NSEC3 NXDOMAIN. Four external compiler construction/mutation attacks were rejected. Local native untested; Linux CI must establish it. Plain wasm compile-only. No benchmark or full-coverage claim.

Windows toolchain: moon 0.1.20260920 (914d7da), moonc 0.10.14+7d59c7ec9-dev. CI records the current official installer version and is unpinned; see docs/ci.md. This local report is not proof of remote CI success.

## Conservative commit review

24 pre-documentation milestones below were inspected for coherent source/test changes. Excluding CI-only 61fcdd4 gives **23 substantive implementation/test/example/security commits**, exceeding 20. Documentation, formatting/interface-only work and subsequent CI compatibility fixes are not added to this count. No empty/fake commits or rewritten history. Feature checkpoints ran real tests and final combined strict checks were rerun.

### 1ee98f3 feat: establish bounded validation policies and failure semantics

.gitignore
AGENTS.md
model.mbt
model_wbtest.mbt
moon.mod
moon.pkg
### 5ca0b23 feat: canonicalize bounded DNS names and signature wildcard owners

name.mbt
name_wbtest.mbt
### f39a1ef feat: validate DNSKEY and DS wire records with explicit algorithm policy

key.mbt
key_wbtest.mbt
### 910ff7f feat: reuse MoonZoneGuard for DNSKEY tags and SHA256 DS association

association.mbt
association_wbtest.mbt
moon.pkg
### 66cd63f feat: decode RRSIG and validate serial-time windows across wraparound

signature.mbt
signature_wbtest.mbt
### 869edf0 feat: canonicalize supported uncompressed RDATA and fail closed on name types

record.mbt
record_wbtest.mbt
### e3ae55f feat: construct bounded sorted deduplicated RFC4034 signing inputs

signed_input.mbt
signed_input_wbtest.mbt
### 81031d4 feat: verify five DNSSEC algorithms with independent OpenSSL fixtures

crypto.mbt
crypto_wbtest.mbt
moon.pkg
### 3cca13a feat: authenticate RRsets under explicit trust with bounded signature lifetime

authenticate.mbt
authenticate_wbtest.mbt
### 73de484 feat: authenticate DNSKEY trust anchors and enforce whole-search key budgets

trust.mbt
trust_wbtest.mbt
### cd8ad32 feat: bind signed parent DS to child DNSKEY and propagate trust freshness

chain.mbt
chain_wbtest.mbt
### 24eed9a feat: strictly decode and reencode DNS denial type bitmap windows

bitmap.mbt
bitmap_wbtest.mbt
### 74dd79c feat: expose TTL-safe authenticated cache snapshots and denial prerequisites

freshness.mbt
freshness_wbtest.mbt
### 9d5a05d feat: validate authenticated NSEC exact absence and parent-side DS denial

nsec.mbt
nsec_wbtest.mbt
### 70ec6f9 feat: require complete NSEC closest-encloser and wildcard NXDOMAIN proofs

nsec_nxdomain.mbt
nsec_nxdomain_wbtest.mbt
### e552828 feat: bound RFC5155 hashing and validate base32hex owner labels

moon.pkg
nsec3_hash.mbt
nsec3_hash_wbtest.mbt
### 703184c feat: authenticate exact NSEC3 NODATA and delegation denial with strict parameters

nsec3.mbt
nsec3_wbtest.mbt
### 37fc586 feat: close NSEC3 closest-encloser proofs without opt-out security upgrades

nsec3_nxdomain.mbt
nsec3_nxdomain_wbtest.mbt
### 305bccf test: exercise public signed denial workflows and adversarial parser boundaries

adversarial_wbtest.mbt
integration/moon.pkg
integration/proof_test.mbt
### 3af88be feat: demonstrate resolver chain, canonical signing, and offline denial audits

examples/offline/main.mbt
examples/offline/moon.pkg
### b49f1c9 test: cover signed DS mismatch, trust budgets, alias denial and RDATA policies

delegation_failure_wbtest.mbt
examples/offline/pkg.generated.mbti
integration/pkg.generated.mbti
pkg.generated.mbti
policy_paths_wbtest.mbt
### f36a1ae fix: hide mutable proof internals and reject external trust forgery

authenticate.mbt
bitmap.mbt
integration/proof_test.mbt
key.mbt
name.mbt
nsec.mbt
nsec3.mbt
pkg.generated.mbti
record.mbt
scripts/check_encapsulation.py
signature.mbt
trust.mbt
### 61fcdd4 ci: check build and test four targets with interface and encapsulation gates

.github/workflows/ci.yml
docs/ci.md
### 5583e77 fix: enforce NSEC ancestor depth before processing denial proofs

nsec_nxdomain.mbt
nsec_nxdomain_wbtest.mbt
