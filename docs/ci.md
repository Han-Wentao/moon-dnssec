# Reproducible verification

Run from the module root:

```sh
moon version --all
moon info && moon fmt
moon fmt --check
moon check --target wasm-gc --deny-warn
moon build --target wasm-gc --deny-warn
moon test --target wasm-gc --deny-warn
moon check --target js --deny-warn
moon build --target js --deny-warn
moon test --target js --deny-warn
moon run --target js examples/offline
python scripts/check_encapsulation.py
moon coverage analyze
```

GitHub Actions runs strict check/build for wasm-gc, wasm, js and native;
it runs the tests/example for wasm-gc, js and native. Plain wasm is compile-only
in this workflow, not a claim of runtime testing. Native runtime is verified by
the Linux CI job, not assumed available on Windows.

Initial implementation toolchain: moon 0.1.20260920 (914d7da), moonc
v0.10.14+7d59c7ec9-dev. Final local verification uses an isolated official stable
moon 0.1.20261012 (748b63c), moonc 0.10.15+943464bfa, matching the observed CI
version. Source annotations use the stable formatter spelling Int32/UInt32.
The initial CI run passed all four target jobs but failed the format gate; the
source was reformatted with that stable toolchain without weakening the check. CI uses the official current installer and logs the actual
version. Historic version archive URLs were unavailable during preflight;
the compiler is **not pinned**, so future builds can expose compatibility changes.
Module dependency versions are pinned in moon.mod. No security keys or platform
credentials are required in CI. Coverage is a diagnostic artifact, not an assertion
of 100% coverage. The four negative compiler checks must fail for the expected
encapsulation diagnostic and clean up only their own temporary source files.
