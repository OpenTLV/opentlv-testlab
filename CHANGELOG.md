<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 Marek Cingel -->

# Changelog

## [Unreleased]

### Changed

- Normalize the LICENSE copyright holder to `Marek Cingel`, matching the source headers
  and every other OpenTLV repository. (#6)
- Install the OpenTLV Lua package under test from luarocks.org with `luarocks` in every
  setup, verifying the downloaded source rock, built Core commit and installed files
  against the pin. External libraries remain cached. (#4)

### Fixed

- Correct the capability check count, a broken dependency-setup link and the verification
  notes that still described hosted Fast and Extended as pending. (#8)

### Added

- Contributor documentation: the README now takes a contributor from installation to a
  reproduced comparison, and covers the commands, supported BER subset, fixture contribution,
  result interpretation, version and cache policy, CI and limits. The guides add step-by-step
  fixture and pin-change procedures, and a new test checks documented links, commands, the
  fixture example and corpus totals. (#8)
- Manual `Extended` workflow and `scripts/run_extended.py`: on x86-64 and arm64 Ubuntu it
  runs a cold and a repeated setup, an offline cache check, the standalone capability audit,
  both corpora with repeat and second-install comparisons and the mismatch probe, and
  uploads a summary, reports, provenance and logs. Fast stays the pull request gate, and
  Extended otherwise runs only on pull requests that change the suite. Document both in
  `docs/ci.md`. (#7)
- Actionable differential reports: input bytes, operation, schema, expectation, both
  libraries' outputs and errors, runtime, package versions, TestLab commit and per-failure
  reproduction commands, with possible defects kept apart from declared unsupported or
  inconclusive fixtures. Run failures also write a report naming any failing input. Add
  `--report` and `--fixture`, upload reports from Fast, and require the deliberate mismatch
  probe's report to reproduce itself. (#6)
- Deterministic ASN.1 BER differential corpus of primitive, constructed, nested, tag and
  length boundary, truncated and malformed cases, with a declared support classification,
  category, description and pin-checked reproduction metadata. Fast runs it through both
  adapters, and the capability audit gains the probes that its reasons cite. (#5)
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
