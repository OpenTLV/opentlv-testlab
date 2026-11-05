<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 Marek Cingel -->

# Core BER/DER differential against der-parser

The runner for [#30](https://github.com/OpenTLV/opentlv-testlab/issues/30) executes the
[reviewed #29 corpus and observation contract](rust-reference.md) through Core **v0.8.0** and
**der-parser 10.0.0**. Both receive identical octets. Independent X.690 expectations decide the
outcome; agreement between the libraries alone is insufficient. No Rust binding executes here;
that audit and the three-way comparison belong to #31.

## Run locally

Use Python 3.10+, Rust/Cargo 1.78.0 or later, CMake 3.24+, Git and native C/C++ build tools.
Linux/WSL and Windows/MSVC are supported. Start in the TestLab root:

```sh
cargo fetch --locked --manifest-path differential/rust/Cargo.toml
python3 scripts/check_rust_reference.py --verify-cache
python3 scripts/setup_rust_differential.py
python3 scripts/check_rust_differential.py
python3 scripts/run_rust_differential.py
```

On Windows use `python` instead of `python3`. Setup downloads the published Core source archive
and release manifest afresh into a new `build/rust-runs/run-*` directory. It verifies their
pinned SHA-256 digests and manifest version/commit, safely extracts the archive and builds a
static Core plus the C adapter. It separately verifies all 19 Cargo archives and packaged sources,
then tests and builds the Rust adapter offline into that run's own target directory. No Lua or
asn1c setup is involved. Only external Cargo registry data may be cached.

For a machine where downloads must be transferred separately, `--core-assets DIRECTORY` accepts
the exact two release assets named by [the Core pin](../dependencies/opentlv-core.json). It still
verifies and freshly extracts/builds them, but the receipt explicitly records
`supplied-verified-release-assets`, not a fresh download. CI always uses fresh acquisition.
This path does not accept a development checkout, a custom source tree or an arbitrary executable.

`build/rust-provenance.json` selects the last setup attempt. Setup invalidates this selector before
starting, so a failure cannot silently select an older successful build. Receipts preserve exact
package inventories, Core revision, CMake configuration, compiler paths, Rust host/toolchain,
build commands/logs, executable hashes and adapter source hashes. The runner rejects changed
executables, implementation files, pins or setup evidence. Logs include the compiler identification.
Core defaults are enabled, with static linkage and tests/examples/C++ facade targets disabled.
This is release-content verification, not a new producer-attestation or release-gate verification.

Run one reviewed fixture or select an explicit build receipt:

```sh
python3 scripts/run_rust_differential.py --fixture der-sequence
python3 scripts/run_rust_differential.py --fixture ber-high-tag-leading-80 --output build/rust-reports/mismatch.json --report build/rust-reports/mismatch.md
python3 scripts/check_report.py build/rust-reports/mismatch.json
python3 scripts/run_rust_differential.py --provenance build/rust-provenance.json
```

The mismatch example deliberately uses real library behavior and the unchanged standards
expectation. It exits 3. The probe command verifies that example, an agreeing fixture, identical
repeat reports, report-driven reproduction, and a missing setup receipt yielding exit 1.

## Executed intersection

The corpus remains **63 fixtures: 35 BER and 28 DER**, with **52 shared, 2 unsupported and
9 inconclusive**. No shared fixture is reclassified to accommodate a disagreement.

| Participant | Actual path | What an accepted observation establishes |
| --- | --- | --- |
| Core BER | `tlv_format_decode(tlv_format_ber)`, recursive traversal, `tlv_ber_tag_number` | Raw BER framing and complete ordered wire tree; no blanket typed BER validation |
| Core DER | `tlv_der_read_strict`, then `tlv_format_decode(tlv_format_der)` traversal | Recursive DER framing and implemented universal primitive content checks; no schema validation |
| Reference BER | `parse_ber_recursive` with recursion fuel 32 | Generic BER object parse and complete SEQUENCE/SET child observations |
| Reference DER | `parse_der_recursive` with recursion fuel 32 | Generic DER root checks; SEQUENCE/SET children use BER recursion, not strict nested DER validation |

Adapters return library-derived class, tag number, P/C bit, content lengths, ranges and tree
structure. The shared Python normalizer projects those ranges onto the original wire bytes;
it never invokes X.690 to repair a participant's observation. It validates complete consumption,
child ordering, parent bounds and range consistency. Indefinite nodes exclude their own EOC but
preserve an encoded child's EOC in their raw contents. Wide INTEGERs stay raw; no int64 conversion
is required. The separate typed expectation validates the fixture's standards context and is not
an extra library comparison.

Generic reference objects with opaque constructed contents are `unsupported`, not complete trees.
Constructed strings, schema-dependent DEFAULT/order rules, nested canonicality, noncanonical BER
TRUE, EOC policy and architecture-dependent wide lengths retain their declared nonshared outcomes.
CER, encoding and Rust binding exposure remain outside this runner.

Errors retain their native text, source and stage; offsets are `null` because these adapter paths
do not supply an unambiguous native location. Native truncation inside an already delimited parent
is `invalid`, while exhaustion of the root input is `truncated`. Reference `InvalidTag` stays
`invalid` even on an incomplete identifier: the report preserves that category disagreement.
No unrelated integer error values are equated. Unknown mappings are inconclusive evidence.

## Reports and gate behavior

Default reports are `build/rust-reports/comparison.json` and `comparison.md`. JSON retains all
input bytes, fixture origins, X.690 rules, independent expectations, both normalized observations,
native errors, classifications, differences, reproduction commands and the complete setup receipt.
Reports identify the TestLab commit and whether the checkout was modified. A modified checkout
needs the recorded local files as well as that commit to reproduce the same implementation.

| Outcome | Meaning |
| --- | --- |
| `pass` | Both participants meet the independent shared expectation |
| `mismatch` | A shared result, category or tree disagrees, or a declared shared capability is missing |
| `unsupported` | Fixture explicitly excludes a missing operation; never a pass |
| `inconclusive` | Fixture excludes an undecidable rule, or native evidence has no justified mapping |

Coverage reports separate BER, DER and combined totals. The shared pass percentage divides shared
passes by the number of executed shared fixtures; unsupported/inconclusive fixtures never inflate
it. This is fixture execution coverage, not a percentage of X.690 or Core API coverage. Both Core
and reference observations are retained separately; Rust binding coverage remains not tested.

Exit **0** requires every selected shared fixture to pass. Exit **3** means a shared mismatch.
Exit **1** means setup/process/protocol failure or inconclusive evidence on a shared fixture.
Crashes, timeouts, memory exhaustion and malformed output never become input rejections or passes.
A failed run replaces the output report and records the active fixture and completed observations.

The reviewed corpus currently exposes reference differences; the complete gate is expected to
remain nonzero until those differences are resolved through a reviewed dependency or contract
change. There is no allowlist, expectation rewriting or `continue-on-error` to turn them green.
The adapter audit characterizes the observed reference behavior without changing the oracle.
Mismatches are observations requiring triage, not confirmed defect claims; follow-up reporting
and cross-repository actions remain in #32 and require the normal review/disclosure process.

### Local execution evidence

On 2026-11-05, a fresh published Core source acquisition and Windows/MSVC Release build, with
Rust 1.98.1, produced **46 pass, 6 mismatch, 2 unsupported, 9 inconclusive**. Both complete reports
were identical on repeat, and all six mismatch reports reproduced from their recorded commands.
Core met all 52 shared expectations. The reference disagreed on these unchanged reviewed cases:

| Fixtures | Independent expectation | Reference observation |
| --- | --- | --- |
| `ber-high-tag-leading-80` | Reject: invalid identifier | Accept |
| `der-length-long-form-for-1`, `der-length-leading-zero` | Reject: nonminimal DER length | Accept |
| `der-high-tag-form-for-30` | Reject: nonminimal identifier | Accept |
| `ber-high-tag-unterminated`, `der-truncated-identifier` | Reject: truncated | Reject: native `Error(InvalidTag)`, normalized `invalid` |

The final two are diagnostic-category differences, not acceptance of malformed input. Combined
shared agreement was 46/52 (88.46%); BER was 26/28 (92.86%) and DER 20/24 (83.33%). These are
fixture-scoped results, with the limitations above. The minimum Rust 1.78.0 build and all 12
reference capability tests also passed. Hosted Fast CI and Linux execution have not been run
for these local changes; no Rust binding, upstream defect confirmation or publication is claimed.

## Bounds and CI

Each request has at most 4,096 bytes, 256 reported nodes and 16 constructed ancestors, and its
process has five seconds and 256 MiB. Reference recursion fuel 32 is a separate parser budget,
not an assertion that its limit errors equal Core depth limits. Linux uses `RLIMIT_AS`, CPU and
output-file limits. Windows uses a Job Object process-commit limit and a five-second child timeout;
the supervising runner allows two additional seconds for wrapper startup/cleanup. These memory
metrics differ; no cross-platform threshold equivalence is claimed. A platform unable to apply
its memory limit fails rather than running unbounded.

The internal process wrapper can also run a single adapter directly when diagnosing a local build:

```sh
python3 scripts/rust_adapter_process.py /absolute/path/to/testlab-core ber 0500
```

Use the runner for comparison reports and provenance checks. Unit tests exercise malformed trees,
changed binaries/receipts, checksum and extraction failures, process errors, shared capability
loss, independent expectations, coverage denominators and a real over-budget allocation:

```sh
python3 -m unittest discover -s tests -p 'test_rust*.py' -v
```

Fast has a dedicated Ubuntu 24.04 x86-64 job using Rust 1.78.0. The external cache key includes OS,
target, toolchain, manifest, lockfile and dependency inventory with no fallback keys. A cache hit
is verified before compilation or acquisition. Core, native binaries and Cargo build targets are
never cached. The job runs policy tests, fresh setup, failure/repeat probes and the complete corpus;
reports, receipts and build logs upload even on failure. A real shared mismatch fails the job.
Extended's existing Lua suite is unchanged; there is no separate Full workflow in this repository.

Public CI can select only the committed reviewed corpus; the runner has no arbitrary-input or
alternate-corpus option. Exploratory fuzzing and untriaged fuzz findings remain private under the
[disclosure policy](differential-fuzzing.md#disclosure-policy). Uploaded artifacts contain no
external source trees or reference executables. Retained third-party notices stay in Cargo's
verified source cache and the freshly extracted Core archive.
