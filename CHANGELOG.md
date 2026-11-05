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

- BER and CER differential: `scripts/run_ber_cer_differential.py` decodes and encodes 154
  hand-written fixtures, 99 BER and 55 CER, with OpenTLV Lua v0.3.0 and the asn1c reference, and
  judges each library against X.690. A new independent reference, `scripts/x690.py`, validates
  every fixture and reads BER encoders' output by logical value, so BER bytes are never required to
  match. CER is compared byte for byte for one type and value. Fixtures cover high tags, definite,
  indefinite and alternative lengths, end-of-contents, constructed, nested and segmented strings,
  alternate BER forms, CER canonical forms and segmentation, truncation and malformed input, and 62
  reuse the bytes of the #1 and #21 corpora. Each check is classified as pass, mismatch,
  confirmed, limitation, not comparable or inconclusive, with cited reasons, and reports give
  per-encoding coverage with denominators. No OpenTLV defect was found. Six new asn1c capability
  probes record its constructed-string, explicit-tag, BIT STRING and OBJECT IDENTIFIER
  deviations. A separate Fast job runs the corpus and a deliberate mismatch probe, `check_report.py`
  reruns its reports, and `docs/ber-cer-differential.md` documents the checks, corpus, results and
  limits. (#22)
- DER canonical differential: `scripts/run_der_differential.py` decodes and encodes 98
  hand-written fixtures with OpenTLV Lua v0.3.0 and the asn1c reference, and judges each library
  against X.690 instead of trusting either. Fixtures cover high tag numbers, short and long length
  boundaries, zero-length, primitive, constructed and nested values, and noncanonical and malformed
  variants. Encoders are compared byte for byte only for the same type and value, and each library
  decodes the other's encoding. Errors are normalized to `empty`, `truncated`, `trailing` and
  `invalid`, and asn1c's DER verdict requires its canonical re-encoding. A fixture declares what a
  library cannot decide, citing documentation or a capability probe, and a limitation that no
  longer shows fails the run. Reports give the outcome matrix, coverage denominators, every
  observation and per-fixture reproduction. No OpenTLV defect was found. A separate Fast job runs
  the corpus and a deliberate mismatch probe, `check_report.py` now also reruns DER reports, and
  `docs/der-differential.md` documents the checks, corpus, limitations and results. (#21)
- Optional asn1c reference adapter: `scripts/setup_asn1c.py` builds `vlm/asn1c` v0.9.29 from
  its digest-pinned release archive into an exact-key cache, generates the versioned
  `TestLabReference-1` schema twice to require deterministic output, and compiles the generated
  code with a C adapter that returns normalized typed values, DER re-encodings and error
  categories. 71 committed probes classify BER decoding, DER decoding and encoding and CER as
  supported, unsupported or not comparable, and setup and `scripts/check_asn1c.py` fail on any
  changed observation. A separate Fast job runs it; `docs/asn1c-reference.md` records the pin,
  provenance, license, alternatives, contract and findings. No OpenTLV dependency or Core option
  is added. (#20)
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
