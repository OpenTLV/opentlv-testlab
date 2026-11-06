<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 Marek Cingel -->

# Rust BER/DER coverage, triage and ergonomics report

This report delivers [#32](https://github.com/OpenTLV/opentlv-testlab/issues/32), the evidence for
[epic #19](https://github.com/OpenTLV/opentlv-testlab/issues/19). It covers the
[Core/Rust/der-parser runner](rust-differential.md) on the reviewed
[`rust-ber-der-1` corpus](rust-reference.md#fixture-contract) with these pins:

| Participant | Package under test | Exact identity |
| --- | --- | --- |
| Core | OpenTLV Core v0.8.0, fresh release source | `345c77acb29266036df5f27d04ce315bb61853cc` |
| Rust binding | crates.io `opentlv`/`opentlv-sys` 0.2.2, safe public API | `1b860286e342fb8872b591029a4efca19eb1895c` |
| External reference | crates.io `der-parser` 10.0.0, using `asn1-rs` 0.7.2 | `07da5016415d5a3c4dd39b11ed26f915f52fc4e0dc197d87908bc916e51bc1a6` (archive) |

Every number below is scoped to the committed fixtures and the capability matrix. None of them
measures X.690 conformance or Core API coverage, and agreement alone never decides a verdict.

## Reproduce the report

The machine-readable sources are [`triage.json`](../differential/rust/triage.json),
[`ergonomics.json`](../differential/rust/ergonomics.json), the
[capability matrix](../differential/rust/capabilities.json), the
[gap inventory](../differential/rust-binding/gaps.json) and the
[divergence baseline](../differential/rust/divergences.json). The generator reads them with the
corpus and writes `build/rust-reports/report.json` and `report.md`:

```sh
python3 scripts/report_rust_differential.py
python3 scripts/setup_rust_differential.py
python3 scripts/check_rust_regressions.py
python3 scripts/report_rust_differential.py --comparison build/rust-reports/comparison.json --reproduce
```

The first command needs no build. It derives the denominators and checks the triage and
ergonomics evidence:

- Every unsupported, inconclusive and diverging fixture has exactly one finding.
- A defect rests on a diverging shared fixture and a cited X.690 rule.
- Each Rust gap matches the published inventory.
- Each ergonomics claim still matches the committed adapter text it cites.

With `--comparison`, the generator also passes the run through the regression gate. It then
requires executed per-participant coverage to equal the gated coverage. `--reproduce` reruns every
minimized case through all three verified adapters and fails on any changed observation. Fast runs
all three steps after the regression gate and uploads both reports.

## Coverage

The report uses three separate denominators:

- **Shared scenarios** are the reviewed fixtures that every participant can decide. Unsupported
  and inconclusive fixtures stay out of the agreement denominator.
- **Core-to-Rust exposure** counts the capability-matrix features that Core supports and the
  published Rust API exposes.
- **External overlap** counts the Core-supported features that der-parser and Rust also support.

| Encoding | Fixtures | Shared | Unsupported | Inconclusive | All three agree | Core | Rust binding | der-parser |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| BER | 35 | 28/35 (80.0%) | 1 | 6 | 26/28 (92.86%) | 28/28 (100.0%) | 28/28 (100.0%) | 26/28 (92.86%) |
| DER | 28 | 24/28 (85.71%) | 1 | 3 | 20/24 (83.33%) | 24/24 (100.0%) | 24/24 (100.0%) | 20/24 (83.33%) |
| All | 63 | 52/63 (82.54%) | 2 | 9 | 46/52 (88.46%) | 52/52 (100.0%) | 52/52 (100.0%) | 46/52 (88.46%) |

| Measure | Numerator / denominator |
| --- | ---: |
| Reviewed fixtures that all three participants can decide (shared) | 52/63 (82.54%) |
| Shared fixtures where all three meet the X.690 expectation | 46/52 (88.46%) |
| Core-supported matrix features exposed by published Rust 0.2.2 | 11/13 (84.62%) |
| Core-supported matrix features also supported by der-parser and Rust | 6/13 (46.15%) |

The participant columns count shared fixtures where that participant alone meets the independent
expectation. Core and the binding meet all of them; the six reference differences are triaged
below. Of the 13 Core-supported features, the published binding lacks `schema` (Rust #52), and
`cer` is untested. The capability matrix is coarser than the
[gap inventory](rust-binding.md#capability-and-gap-matrix): three missing API families sit inside
features that the binding otherwise supports.

## Capability matrix

| Feature | Core | Rust binding | der-parser BER | der-parser DER |
| --- | --- | --- | --- | --- |
| `framing` | supported | supported | supported | supported |
| `indefinite` | supported | supported | supported | supported |
| `tree` | supported | supported | supported | supported |
| `root-contents` | supported | supported | supported | supported |
| `ber-noncanonical-contents` | not-comparable | not-comparable | supported | not-comparable |
| `nested-der-contents` | supported | supported | not-comparable | not-comparable |
| `opaque-constructed` | supported | supported | unsupported | unsupported |
| `constructed-strings` | supported | supported | not-comparable | not-comparable |
| `schema` | supported | unsupported | not-comparable | not-comparable |
| `malformed-framing` | supported | supported | supported | supported |
| `single-root` | supported | supported | supported | supported |
| `wide-length` | not-tested | not-tested | not-tested | not-tested |
| `limits` | supported | supported | not-comparable | not-comparable |
| `encoding` | supported | supported | unsupported | unsupported |
| `cer` | supported | not-tested | unsupported | unsupported |

The [reference guide](rust-reference.md#capability-intersection) explains each status and the
evidence behind it.

## Bugs

There are 14 findings: 2 defects, 7 limitations and 5 inconclusive. **No OpenTLV Core or Rust
binding defect was found.** A missing operation or API is a limitation, never a defect.

### Defects

Both defects are in the external reference's header parser, `asn1-rs` 0.7.2. They are already
public upstream in [asn1-rs #149](https://github.com/rusticata/asn1-rs/issues/149), which a third
party filed before TestLab ran. TestLab did not file a duplicate.

- `reference-nonminimal-identifier`: the reference accepts a first subsequent identifier octet of
  `80`, which violates X.690 8.1.2.4.2 c. It also accepts the high-tag form for tag numbers below 31
  (X.690 8.1.2.2). Minimized reproductions are BER `1f 80 1f 00` and DER `1f 1e 00`; Core and the
  binding reject both.
- `reference-nonminimal-der-length`: in DER, the reference accepts a long-form length below 128 and
  a leading zero length octet (X.690 10.1). The minimized reproduction is DER `05 81 00`.

### Limitations and inconclusive findings

| Finding | Class | Participants | Fixtures | Minimized | Upstream |
| --- | --- | --- | --- | --- | --- |
| `reference-nonminimal-identifier` | defect | der-parser | `ber-high-tag-leading-80`, `der-high-tag-form-for-30` | BER `1f 80 1f 00`, DER `1f 1e 00` | [open](https://github.com/rusticata/asn1-rs/issues/149) |
| `reference-nonminimal-der-length` | defect | der-parser | `der-length-long-form-for-1`, `der-length-leading-zero` | DER `05 81 00` | [open](https://github.com/rusticata/asn1-rs/issues/149) |
| `reference-truncated-identifier-category` | limitation | der-parser | `ber-high-tag-unterminated`, `der-truncated-identifier` | BER `1f` | not-reported |
| `core-ber-high-form-low-tag` | limitation | Core, Rust binding | - | BER `1f 1e 00` | documented |
| `reference-nested-der-contents` | limitation | der-parser | `der-nested-boolean-true-01` | DER `30 03 01 01 01` | [open](https://github.com/rusticata/der-parser/issues/95) |
| `reference-eoc-objects` | inconclusive | der-parser | `ber-eoc-root`, `ber-eoc-in-definite` | BER `00 00` | not-reported |
| `schema-rules-not-exercised` | inconclusive | Core, Rust binding, der-parser | `der-default-encoded`, `der-set-of-unsorted` | - | [open](https://github.com/OpenTLV/opentlv-rust/issues/52) |
| `constructed-string-representation` | inconclusive | der-parser | `ber-constructed-octets`, `ber-constructed-bit-string` | - | not-reported |
| `ber-boolean-typed-validity` | inconclusive | Core, Rust binding, der-parser | `ber-boolean-true-01` | - | not-reported |
| `wide-length-envelope` | inconclusive | Core, Rust binding, der-parser | `ber-length-nine-octets` | - | not-reported |
| `reference-opaque-constructed` | limitation | der-parser | `ber-private-class-indefinite`, `der-explicit-context` | - | documented |
| `rust-asn1-helpers` | limitation | Rust binding | - | - | [open](https://github.com/OpenTLV/opentlv-rust/issues/50) |
| `rust-asn1-codecs` | limitation | Rust binding | - | - | [open](https://github.com/OpenTLV/opentlv-rust/issues/51) |
| `rust-der-schema` | limitation | Rust binding | - | - | [open](https://github.com/OpenTLV/opentlv-rust/issues/52) |

[`triage.json`](../differential/rust/triage.json) gives each finding's component, rule, summary and
disclosure decision. Each fixture's bytes, expectation and reproduction command are in the
[corpus](../differential/fixtures/rust-ber-der.json) and in every comparison report. Three findings
need a short note:

- `core-ber-high-form-low-tag` came from minimization, not from the corpus. Core v0.8.0 `ber.h`
  says: "For raw-tag compatibility, high-tag-number encodings of numbers below 31 remain accepted."
  Strict DER rejects them. This is deliberate, documented behavior, so it is not a defect. Adding a
  fixture for it would be a separate, reviewed corpus change.
- `reference-truncated-identifier-category` is a diagnostic difference only. Every participant
  rejects the input, and X.690 defines no error categories, so nothing is reported upstream.
- `reference-nested-der-contents` matches the open upstream report
  [der-parser #95](https://github.com/rusticata/der-parser/issues/95). The corpus keeps it
  inconclusive, because generic `parse_der` documents no nested DER contract.

### Disclosure

Non-canonical DER acceptance can matter to consumers that depend on unique encodings. The two
defects are therefore assessed as potentially security-relevant. Both were already public, and
neither `asn1-rs` nor `der-parser` publishes a security policy or private reporting channel.
TestLab holds no private or untriaged finding from this work. The
[disclosure policy](differential-fuzzing.md#disclosure-policy) is unchanged: public CI runs only
committed, triaged fixtures, and the minimized cases above are triaged, public and committed.

## Ergonomics assessment

This assessment records what a consumer had to write to get the normalized observations. It is
reproducible and unscored, and nothing in it counts toward functional coverage.
[`ergonomics.json`](../differential/rust/ergonomics.json) anchors every claim in a committed
adapter or manifest, and the generator fails if an anchor goes stale.

| Participant | Adapter code lines | Library entry points | Registry packages | Unsafe code |
| --- | ---: | ---: | ---: | --- |
| Core | 115 | 6 | 0 | not applicable (C) |
| Rust binding | 150 | 9 | 2 | forbidden |
| der-parser | 154 | 8 | 19 | absent |

Adapter code lines exclude tests, comments and blank lines. Each adapter also normalizes into the
shared schema, so these counts compare effort, not library quality.

| Dimension | Core C API | Published Rust 0.2.2 | der-parser 10.0.0 |
| --- | --- | --- | --- |
| Setup | CMake 3.24+ and a C99 compiler; static link | Exact crate and Rust 1.82. The build script still fetches Core and needs CMake and a C toolchain. | Pure Rust, 19 locked crates, Rust 1.78, no native build |
| Parse flow | Element at a time with manual recursion; a separate strict DER pass and a tag-number call | Same model with `Decoded::layout` ranges. No public tag-number accessor (#50). | One recursive call for SEQUENCE/SET. Other constructed values are opaque, and the caller checks trailing bytes and recomputes header spans. |
| Diagnostics | One result enum with descriptions | Core codes with native offsets. Decode and strict validation return differently shaped errors. | Layered `nom::Err<BerError>` with no offsets; truncated identifiers report `InvalidTag` |
| Lifetimes | Pointers into the caller's buffer, unchecked | Borrowed `Decoded<'d>`, compiler-checked; adapter forbids unsafe code | Borrowed `BerObject<'a>`, compiler-checked |
| API complexity | Positional limits struct | Named limits; no ASN.1 helpers, typed codecs or DER schema (#50–#52) | Three-level error match |

The binding gives the safest borrowed views and the most precise diagnostics. Getting a complete,
validated tree takes the same number of steps as in Core. The reference is the shortest path to a
tree, but its opaque non-universal contents and offset-free errors move work to the caller.

## Execution evidence

Hosted Fast passed with the three-way job on the #31 pull request,
[run 42180528867](https://github.com/OpenTLV/opentlv-testlab/actions/runs/42180528867) at
`25b7fd19832341da1f51d2fc1ec9986d56939763`. It passed again on `main` after the merge,
[run 42180952827](https://github.com/OpenTLV/opentlv-testlab/actions/runs/42180952827) at
`12aaa873e50f40b7ad6ec8ae3065890f9fe720ad`. In both runs, the Rust job ran these steps successfully:

- fresh package setup
- the gap evidence audit
- the report and failure probes
- the exact-divergence regression gate on Ubuntu 24.04 with Rust 1.82.0

Its `rust-differential-reports` artifact keeps the comparison and provenance. These runs came before
this report generator, so the first hosted run of the report step is still to come. Extended does
not run the Rust job, and there is no separate Full workflow.

On 2026-11-06, a local Windows/MSVC run on the existing verified setup used Rust 1.82.0 with
TestLab `12aaa873e50f40b7ad6ec8ae3065890f9fe720ad` plus this change. The regression gate passed with
46 pass, 6 mismatch, 2 unsupported and 9 inconclusive, matching the six recorded divergences
exactly. The generator then confirmed the gated coverage and reran all 7 minimized cases with
unchanged observations. An earlier attempt failed at its seventh fixture when Windows could not
start the Core adapter process (`0xC0000142`); the rerun passed without any change.

## Epic #19 closure evidence

| Epic acceptance criterion | Status | Evidence |
| --- | --- | --- |
| Exact external crate and dependency graph pinned and reviewed | Met | [#29](https://github.com/OpenTLV/opentlv-testlab/issues/29); [reference baseline](rust-reference.md) |
| Deterministic shared corpus and normalized result schema | Met | [#29](https://github.com/OpenTLV/opentlv-testlab/issues/29); [fixture contract](rust-reference.md#fixture-contract) |
| Core and der-parser harness runs locally and in CI with provenance | Met | [#30](https://github.com/OpenTLV/opentlv-testlab/issues/30); hosted Fast runs above |
| Feature matrix and denominator-based coverage report | Met | This report: [coverage](#coverage) and [capability matrix](#capability-matrix) |
| Divergences triaged as defect, limitation or inconclusive | Met | [Bugs](#bugs); [`triage.json`](../differential/rust/triage.json) |
| Rust gap analysis published; confirmed gaps implemented and tested in `opentlv-rust` | **Not met** | Analysis published in [#31](rust-binding.md). [Rust #50](https://github.com/OpenTLV/opentlv-rust/issues/50), [#51](https://github.com/OpenTLV/opentlv-rust/issues/51) and [#52](https://github.com/OpenTLV/opentlv-rust/issues/52) are open with no tested fix. |
| Three-way integration after the confirmed gaps are resolved | **Partly met** | The three-way comparison covers all shared fixtures on published 0.2.2. The rerun after gap resolution is pending. |
| Ergonomics assessment and Bugs section | Met | [Ergonomics](#ergonomics-assessment); [Bugs](#bugs) |
| Disclosure policy followed; CI fails closed | Met | [Disclosure](#disclosure); the runner, gate and generator fail on setup, stale or untriaged evidence |
| No unnecessary tracker, duplicated Core suite or benchmarks | Met | Existing runner, gate and corpus reused; no benchmark |

**Recommendation:** close #32 with this report, and keep epic #19 open. The epic can close after:

1. `opentlv-rust` implements and tests #50, #51 and #52.
2. TestLab pins a later published package after review.
3. `gaps.json` records the tested fixes.
4. The three-way comparison and this report are rerun on that pin.

No Rust 0.3.0 release is required, beyond whatever the Rust repository's normal release gates need.
