name = "Han-Wentao/moon-dnssec"

version = "0.1.0"

readme = "README.md"

repository = "https://github.com/Han-Wentao/moon-dnssec"

license = "Apache-2.0"

keywords = [ "dnssec", "rrsig", "nsec", "nsec3", "validation" ]

description = "Bounded offline DNSSEC authentication and denial proofs for supplied RRsets"

preferred_target = "wasm-gc"

import {
  "moonbitstack/mooncrypt@0.3.1",
  "geniuszby/moonzoneguard@0.3.0",
}
