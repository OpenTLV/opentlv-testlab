<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 Marek Cingel -->

# Changelog

## [Unreleased]

### Added

- Reproducible Lua dependency setup using lua-asn1's upstream Makefile, an
  integrity-checked cache keyed by source/runtime/platform/configuration, and
  fresh OpenTLV Lua v0.3.0 source-rock installation with package provenance.
  Extend Fast CI with cache-policy tests, installed-library checks and setup logs. (#3)
- Pin `kunkku/lua-asn1` v2.2.1 by commit and source hashes; document its MIT
  license, Lua runtime requirements and concrete BER comparison matrix against
  OpenTLV Lua, including unsupported features and known upstream differences.
  Add an executable capability audit and initial Fast CI gate. (#2)
