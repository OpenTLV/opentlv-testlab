<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 Marek Cingel -->

# Rust BER/DER reference baseline

This is the dependency and fixture contract for [#29](https://github.com/OpenTLV/opentlv-testlab/issues/29),
part of [epic #19](https://github.com/OpenTLV/opentlv-testlab/issues/19). It provides a locked external
dependency, an external-only capability audit, standards-based fixtures and a normalized observation
schema. The [Core comparison runner and its CI integration](rust-differential.md) implement #30;
the Rust binding audit and three-way comparison belong to #31. This page describes the baseline
contract; execution results and limitations are documented in the runner guide.

## Dependency identity and provenance

The only direct Rust dependency is **der-parser =10.0.0**, from crates.io, with default features
disabled and only `std` selected. Serialization, bigint, bitvec and unstable features are disabled.
`asn1-rs` is a transitive dependency, not a second reference integration. No dependencies are added to
Core or a binding. The unpublished TestLab package lives in
[`differential/rust`](../differential/rust/Cargo.toml).

[`dependencies/der-parser.json`](../dependencies/der-parser.json) records the published archive,
its registry metadata checked on 2026-11-05, the packaged VCS revision, and the complete 19-package
registry inventory. [`Cargo.lock`](../differential/rust/Cargo.lock) pins all versions, dependency
edges and registry SHA-256 checksums. The inventory also records resolved features, declared Rust
requirements, SPDX license expressions and hashes of the license notices actually packaged.

| Property | Verified value |
| --- | --- |
| Registry release | [der-parser 10.0.0](https://crates.io/crates/der-parser/10.0.0), published 2025-01-21, not yanked at review |
| Upstream | [rusticata/der-parser](https://github.com/rusticata/der-parser) |
| Packaged VCS revision | `79ec2d0cfe1e3ba2deb49ee1f68f984f4ef3a971`, from `.cargo_vcs_info.json` |
| Archive size | 66,186 bytes |
| Archive SHA-256 | `07da5016415d5a3c4dd39b11ed26f915f52fc4e0dc197d87908bc916e51bc1a6` |
| License | MIT OR Apache-2.0; both packaged license files are hashed in the inventory |
| Upstream declared MSRV | Rust 1.63, edition 2018, from the published Cargo.toml |
| TestLab baseline | Rust/Cargo 1.78.0 or later, edition 2021; tested on 1.78.0 |

The upstream MSRV does not describe this resolved graph. `asn1-rs` 0.7.2 declares Rust 1.68,
several macro dependencies require 1.71, and `thiserror` 2.0.21 requires 1.77. This baseline uses
lockfile format 4, supported by Cargo 1.78 and later; see the
[Cargo changelog](https://doc.rust-lang.org/stable/cargo/CHANGELOG.html#cargo-183-2024-11-28).
Packages with no declared `rust-version` have `null` in the inventory; the 1.78.0 build tests the
complete graph rather than inferring compatibility from those declarations.

All 19 crates declare an MIT option. `unicode-ident` additionally requires Unicode-3.0; preserve
its Unicode notice as well as the selected MIT/Apache notice. `asn1-rs-impl` 0.2.0 declares
`MIT/Apache-2.0` but packages no standalone license file: its inventory deliberately records an
empty `notices` object, not an invented file hash. Retain the published sources and metadata in
Cargo's cache. No third-party source or binary is redistributed by this change. Reassess notices
before distributing a reference executable. The archive digest establishes content identity;
the packaged VCS field is upstream metadata, not a signature or an attestation verification.

## Reproduce and verify

Use Python 3.10+ for policy checks, and a Rust toolchain with a native linker for the external
audit. From the TestLab root:

```sh
python3 scripts/check_rust_reference.py
cargo fetch --locked --manifest-path differential/rust/Cargo.toml
python3 scripts/check_rust_reference.py --verify-cache
cargo test --locked --offline --manifest-path differential/rust/Cargo.toml
```

To verify the minimum toolchain explicitly:

```sh
rustup toolchain install 1.78.0 --profile minimal
cargo +1.78.0 test --locked --manifest-path differential/rust/Cargo.toml
cargo +1.78.0 test --locked --offline --manifest-path differential/rust/Cargo.toml
```

The first command checks the committed pin, lockfile, capability declarations, fixture origins,
wire trees and independent X.690 expectations. `--verify-cache` additionally runs offline Cargo
metadata, verifies the entire resolved inventory and features, checks all 19 cached archive digests,
and compares every packaged source file and license notice with the verified archive. Missing or
changed archives or source files fail; this command neither repairs nor downloads them.

Cargo's registry cache may be reused for this external dependency. The runner's CI cache uses an
exact key including OS, target, toolchain, manifest and lockfile, and revalidates on a hit. Do not
cache an OpenTLV package under test: #30 freshly acquires Core release sources; #31 must follow the existing
[consumer policy](dependencies.md#fresh-opentlv-package-from-luarocks), adapted to its actual source
or registry, and record the exact Core revision, configuration and binding features. A sibling
development checkout is not a substitute for a released consumer baseline.

Pin changes require review: verify registry/archive identity and notices, update the exact direct
requirement and Cargo lockfile deliberately, regenerate the inventory from `cargo metadata --locked`,
and inspect every changed package, feature, checksum and license. The lockfile digest uses UTF-8
text with LF newlines. Rerun the minimum-toolchain audit and corpus validation, and revisit the
capability matrix. Never patch the reference or update the lockfile merely to hide a disagreement.

## Capability intersection

The [machine-readable matrix](../differential/rust/capabilities.json) separates Core, the Rust
binding, reference BER and reference DER. Its statuses are `supported`, `unsupported`,
`not-comparable` and `not-tested`. They describe availability for a named subset, not measured
conformance or a pass rate. Core evidence is a source/API review of v0.8.0, commit
`345c77acb29266036df5f27d04ce315bb61853cc`, matching the existing TestLab Core baseline. The runner
records the actual build and observations separately. All Rust binding rows remain `not-tested`; published 0.2.2 is the
epic's intended starting point, not execution evidence or an assumed API equivalence.

| Scenario | Core API requirement | Reference capability and initial decision |
| --- | --- | --- |
| Four classes, high tags, definite short/long lengths | BER/DER formats and tag-number accessor | Shared framing, tag numbers through 2^32-1; preserve identifier and length octets |
| BER constructed indefinite lengths and EOC | BER format and tree traversal | SEQUENCE/SET supported; DER must reject indefinite lengths |
| Primitive raw contents, including large INTEGER | Raw value bytes | Shared; raw INTEGER comparison has no int64 conversion requirement |
| Root canonical BOOLEAN/INTEGER and selected primitive values | Explicit ASN.1 codecs in addition to framing | Selected content rules supported by `parse_der`; BER acceptance alone proves no DER rule |
| Nested DER canonical contents | DER traversal plus per-node codecs | Generic `parse_der` uses BER recursion for SEQUENCE/SET children; inconclusive without explicit per-node DER validation |
| Non-universal constructed children | Generic tree traversal | Generic reference returns opaque `Unknown` contents; unsupported until an adapter explicitly traverses them |
| Constructed BER strings | Framing and separately specified reassembly | Reference OCTET STRING exposes segment encodings without reassembly; logical-value comparison is inconclusive |
| BER TRUE `01` | Raw BER accepts it; canonical BOOLEAN codec is stricter | Typed BER comparison is inconclusive; do not conflate codecs and framing |
| SET/SET OF order, DEFAULT omission, component presence | `der_schema.h` with a schema | Generic reference parsing has no equivalent schema check; inconclusive |
| Empty input and trailing bytes | Single-root adapter policy | Parsers may return end-of-input or a remainder; adapter must enforce exactly one complete root |
| Truncation, malformed headers and parent bounds | Format/traversal API | Shared scenarios; retain native errors and only compare justified broad categories |
| Depth, input, element and memory limits | Distinct Core processing budgets | Reference recursion fuel has different semantics; no equivalent error or threshold assumed |
| Encoding and CER | Core has separate APIs | Excluded from this reference baseline |

The audit in [`src/lib.rs`](../differential/rust/src/lib.rs) records 12 reproducible observations.
It tests BER/DER selection, indefinite lengths, root contents checks, nested validation limitations,
opaque children, tag classes, remainder handling, schema-order limitations, constructed-string
representation and explicit recursion budgets. These are library observations, not standards
expectations. The published source, especially `src/der/parser.rs` and `src/ber/wrap_any.rs`, explains
why a successful generic DER parse cannot establish full DER canonicality. The runner records the
exact API and rules exercised and does not label BER fallback as strict DER validation. Two #30
probes additionally preserve observed acceptance of nonminimal headers and native `InvalidTag`
errors for incomplete identifiers; these remain shared differential mismatches.

## Fixture contract

[`rust-ber-der.json`](../differential/fixtures/rust-ber-der.json) uses contract `rust-ber-der-1` and
contains **63 fixtures: 35 BER and 28 DER**, classified as **52 shared, 2 unsupported and 9 inconclusive**.
Those are declared comparison denominators, not pass counts. Sixty-two reuse bytes, typed
expectations and stable source IDs from the existing reviewed BER/CER and DER corpora. `origin`
names the original corpus and ID. DER IDs gain a `der-` prefix to avoid collisions.

One reviewed mutation, `der-nested-boolean-true-01`, changes the TRUE content octet of the existing
DER `sequence` fixture from `ff` to `01`. The committed offset, old/new octet and X.690 11.1 rule
make it reproducible. Its rejection expectation comes from X.690, while its `inconclusive`
classification records the generic reference's nested-validation limitation.

Each fixture retains `id`, `encoding`, `category`, `description`, `rule`, `type`, `wire`, `expected`
and adds a matrix `feature`, `classification`, reason and review provenance. An accept expectation
has the existing typed oracle `value` and the normalized wire `tree`. The typed value supplies
independent standards context; it is not automatically a shared library check. Large integers,
schema-derived fields and implicit types must not be inferred from a raw tag. A reject expectation
has `result: reject` and an error category. Unknown fields are not a license to widen the comparison.

[`scripts/x690.py`](../scripts/x690.py) independently checks every expectation. It never takes
either participant's output as truth. The validator additionally checks origin bytes, the declared
mutation, unique IDs, tags, length forms, raw contents and child order. New fixtures need a cited
X.690 rule, a reviewable expectation and an explicit support decision. Preserve IDs once published;
do not change a `shared` case to `unsupported` just to make a run pass.

## Normalized observations

[`observation.schema.json`](../differential/rust/observation.schema.json) defines the version-1 JSON
observation produced by the runner. It names the fixture, encoding, participant, exact API and
`checks` actually performed. `result` is `accept`, `reject`, `unsupported` or `inconclusive`.
Infrastructure failures are outside this schema and invalidate the run.

An accepted observation has `consumed` and a complete `tree`; an opaque or partially traversed tree
cannot masquerade as complete. Every node contains:

| Field | Normalization |
| --- | --- |
| `class` | `universal`, `application`, `context` or `private`, independent of library enums |
| `number` | Unsigned decimal string; never a float or a lossy JSON integer |
| `constructed` | The wire's P/C bit, not a guessed ASN.1 schema type |
| `identifier_hex` | Exact identifier octets, lowercase hex without spaces |
| `length.form` | `short`, `long` or `indefinite`; do not canonicalize a BER length |
| `length.value` | Decimal content length for definite values; `null` for indefinite values |
| `length.encoded_hex` | Exact length octets, including `80` for indefinite |
| `value_hex` | Exact contents, including encoded children of constructed values; exclude that node's terminating EOC |
| `children` | Complete ordered wire children; primitive values have `[]`; EOC is a delimiter, not a child |

Keep nested EOC octets in their parent's raw contents when they belong to a child's encoding.
Do not sort SET children, flatten constructed strings, trim INTEGER sign octets or normalize TRUE
before wire comparison. Logical typed values use the existing
[typed-value contract](asn1c-reference.md#typed-values) only when that check is explicitly shared.

An accepted observation does not assert canonicality: `checks` lists the actual rules validated.
For DER, generic `parse_der` and explicit per-node strict validation are distinct API paths. The
adapter may recover wire slices for a successfully parsed value, but must not replace a library's
rejection or unsupported operation with an independently parsed success.

### Errors and outcomes

Rejected observations retain `error.category`, `source` (`library`, `adapter` or `policy`), `stage`,
`native_code` and `offset`. Unavailable native codes/offsets are `null`; never invent positions or
map unrelated errors solely because their integer values match. Error stages distinguish framing,
contents, canonicality, schema, policy and unknown. Category meanings reuse TestLab conventions:

| Category | Meaning |
| --- | --- |
| `empty` | Single-root policy received no octets; Core's end-of-input is not a native parse failure |
| `truncated` | More input is needed outside a definite parent's boundary |
| `trailing` | A successful parse left octets after the one allowed root; attributed to the adapter |
| `invalid` | Malformed or noncanonical input for the explicitly checked rule; overrun of a definite parent belongs here |
| `limit` | A documented resource/policy budget was exceeded, separately from encoding validity |
| `unknown` | The native error cannot justify a more precise mapping; keep the check inconclusive |

`nom::Err::Incomplete` alone does not prove equivalent truncation semantics: inspect whether a
definite parent bounds the failure. Never report a crash, timeout, missing dependency or malformed
adapter output as an invalid BER/DER input. Those are run failures.

The runner uses existing outcomes: `pass` when both shared checks meet the independent
expectation, `mismatch` when a shared check disagrees, `unsupported` for a missing operation, and
`inconclusive` when available evidence cannot decide the rule. The latter two require reasons and
are excluded from pass-rate denominators. A mismatch is an observation needing triage, not a
confirmed defect. The #29 contract validator emits no coverage percentage or differential verdict;
the separate runner reports scoped fixture denominators and fails on shared mismatches.

## Bounds, disclosure and validation status

The corpus declares an execution envelope of 4,096 input bytes, root depth zero with at most
16 constructed ancestors, 256 elements, five seconds per process request and 256 MiB process
memory. The fixture validator checks input/tree dimensions; it does not run participant processes.
The runner enforces time and memory bounds on Linux/WSL and Windows and rejects unsupported platforms.
Do not compare Core depth directly with `parse_ber_recursive`/`parse_der_recursive` recursion fuel.
Tag/length overflow and architecture-specific limits require separate policy cases, never huge
allocations derived from an untrusted length.

Follow the existing [disclosure policy](differential-fuzzing.md#disclosure-policy) and the
[organization security policy](https://github.com/OpenTLV/.github/blob/main/SECURITY.md). Public CI
runs only committed, reviewed fixtures. Exploratory inputs, untriaged observations and suspected
vulnerabilities stay local/private. Confirmed non-security defects go to the owning repository;
security findings go through its verified private reporting channel. Do not assume a private
channel is enabled for this repository or upstream merely because it is mentioned here.

The original #29 local verification on Windows/MSVC included the minimum Rust 1.78.0 external audit,
offline archive/source verification and Python contract tests. The #30 runner adds Core execution,
differential reports and a dedicated Fast job; see its [guide](rust-differential.md). Rust binding
execution, hosted qualification and release/publication evidence are separate.
