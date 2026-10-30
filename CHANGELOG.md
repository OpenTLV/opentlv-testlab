<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 Marek Cingel -->

# Changelog

## [Unreleased]

### Changed

- Install the OpenTLV Lua package under test from luarocks.org with `luarocks` in every
  setup, verifying the downloaded source rock, built Core commit and installed files
  against the pin. External libraries remain cached. (#4)

### Added

- Lua differential runner with independent OpenTLV Lua and lua-asn1 adapters over the
  same bytes, normalized parse trees and values, and pass/mismatch/unsupported/inconclusive
  outcomes. Crashes, timeouts, resource limits and changed dependencies are run failures,
  and Fast runs seed fixtures and a deliberate real-library mismatch probe. (#4)
- Reproducible Lua dependency setup using lua-asn1's upstream Makefile, an
  integrity-checked cache keyed by source/runtime/platform/configuration, and
  fresh OpenTLV Lua v0.3.0 source-rock installation with package provenance.
  Extend Fast CI with cache-policy tests, installed-library checks and setup logs. (#3)
- Pin `kunkku/lua-asn1` v2.2.1 by commit and source hashes; document its MIT
  license, Lua runtime requirements and concrete BER comparison matrix against
  OpenTLV Lua, including unsupported features and known upstream differences.
  Add an executable capability audit and initial Fast CI gate. (#2)
