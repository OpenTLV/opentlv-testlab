<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 Marek Cingel -->

# Published Rust binding audit

[TestLab #31](https://github.com/OpenTLV/opentlv-testlab/issues/31) adds the published safe Rust
facade to the [BER/DER runner](rust-differential.md). The baseline is crates.io **opentlv 0.2.2**
and **opentlv-sys 0.2.2**, packaged revision `1b860286e342fb8872b591029a4efca19eb1895c`.
Both the direct Core participant and the binding pin Core **v0.8.0**,
`345c77acb29266036df5f27d04ce315bb61853cc`. The binding runs with default Cargo features disabled;
document, NFC and LLDP are outside this ASN.1 comparison. This is not qualification of those
features or of every platform supported by the binding.

## Provenance and reproduction

[`opentlv-rust.json`](../dependencies/opentlv-rust.json) records exact crate checksums, sizes,
licenses, publication metadata, VCS revision, the packaged Core lock, and manifest/lockfile hashes.
The separate [consumer manifest](../differential/rust-binding/Cargo.toml) has only an exact registry
dependency on `opentlv`; the adapter forbids unsafe code and does not call `opentlv-sys` directly.

Every setup downloads both crate archives afresh. After checking checksums and safely extracting
them, it preserves all upstream files and licenses and generates Cargo's directory-source checksum
manifest. A fresh private Cargo home resolves the **registry** packages from those verified files
offline. This is Cargo source replacement, not a binding checkout, path dependency or package patch.
Cargo metadata must match the pinned sources, versions, features and source directories.
No installed OpenTLV crate, native library or binding build output is reused.

The published `opentlv-sys` build script then runs its own normal release resolver. Cargo's
`--offline` does not make that resolver offline: it downloads and verifies the pinned Core release.
Setup rejects development/prebuilt overrides and requires a clean, verified source/binary selection
whose version and commit match the direct Core participant. The receipt retains that selection,
archive/source hashes, build log, configuration, commands and executable hash. Producer attestation,
hosted CI and a new package release are separate evidence; this run does not establish them.

```sh
python3 scripts/setup_rust_binding.py
cargo fetch --locked --manifest-path differential/rust/Cargo.toml
python3 scripts/setup_rust_differential.py
python3 scripts/check_rust_binding.py
python3 scripts/check_rust_differential.py
python3 scripts/check_rust_regressions.py
```

Rust/Cargo 1.82.0 or later is required for the binding. The external der-parser audit retains its
independent 1.78 minimum. On Windows, use `python` and a short build parent with `--runs-dir` if
MSVC reports a path-length error. Retain the entire selected run directory when using its receipt.

## Capability and gap matrix

The [machine-readable matrix](../differential/rust/capabilities.json) separates Core support,
published Rust exposure and the external BER/DER reference. The
[gap inventory](../differential/rust-binding/gaps.json) identifies exact source evidence and owning
issues. These are scoped ASN.1 observations, not a second full API-disposition system: the binding's
[API/ABI coverage epic #46](https://github.com/OpenTLV/opentlv-rust/issues/46) owns that gate.

| Capability | Core v0.8.0 | Published safe Rust 0.2.2 | der-parser 10.0.0 / comparison |
| --- | --- | --- | --- |
| BER/DER framing, high tags, classes, original length/value ranges | Supported | `FormatRef::decode`, `Decoded::layout/encoded/raw_length`, `Tag::as_bytes` | Shared wire trees for the declared subset |
| Constructed indefinite BER, nested SEQUENCE/SET | Supported | Same public decoder; adapter traverses library-delimited children | Shared where reference exposes complete children |
| Private/context constructed children and constructed strings | Supported framing | Same public decoder exposes children | Reference opaque/unsupported forms remain excluded |
| Strict root and nested DER primitive-content validation | `tlv_der_read_strict` | `Format::Der.read(..., Strictness::Strict)` | Generic reference validates selected root rules; nested DER checks are incomplete |
| Errors, consumed bytes and bounded strict validation | Supported | `Error`, `FormatError`, `ValidationError`, `Limits` | Native evidence retained; empty/trailing policy belongs to adapters |
| Definite BER and canonical DER writing | Supported | `FormatRef::encode`, `Format::Der.write` | Public-facade round-trip probe only; no reference encoder verdict |
| Standalone ASN.1 identifiers, BER length codecs and explicit indefinite writing | Supported | **Missing public operations**; raw accepted tag bytes are available | [Rust #50](https://github.com/OpenTLV/opentlv-rust/issues/50), open |
| Typed ASN.1 value codecs | Supported, with explicit canonical/representation limits | **Missing typed ASN.1 facade**; strict validation still works | [Rust #51](https://github.com/OpenTLV/opentlv-rust/issues/51), open |
| Schema-aware DER ordering, DEFAULT omission, tagged/choice composition | Supported by dedicated DER schema engine | **Missing DER schema facade**; generic `StructureSchema` is separate | [Rust #52](https://github.com/OpenTLV/opentlv-rust/issues/52), open; generic reference has no equivalent schema verdict |
| Full ASN.1 semantics from raw BER framing, arbitrary-size typed integers, universal canonicality from generic DER parsing | No such blanket contract | No such guarantee inferred | Not comparable; not a binding implementation claim |
| Huge values / architecture-wide limits | Core has native buffer and logical size limits | Not exercised beyond the 4096-byte execution envelope | Not tested; never a pass |

`Tag::as_bytes` exposes the exact accepted identifier. TestLab projects its numeric tag, class and
P/C bit for presentation, just as it projects length octets from public source ranges. This does
**not** implement or claim a public ASN.1 helper API; #50 remains open. Parsing/rejection and child
boundaries always come from the participant library. No X.690 oracle output feeds an observation.

The public-facade probes in [the adapter](../differential/rust-binding/src/main.rs) exercise
indefinite/private children, preserved source layout, strict root/nested content rejection,
truncation and single-root policy, resource limits, encoding and round trips. The full corpus
additionally compares all three participants against the independent expectations. Reference
limitations do not suppress the Rust observations, and agreement on shared fixtures does not
resolve the missing API rows.

## Gap disposition

Issues #50, #51 and #52 are linked to TestLab #31 and Rust #46 and remain **open**. No tested fix
or later published package is claimed. Do not mark these gaps resolved until the owning Rust
implementation and public-facade/ABI tests provide evidence. A local fix would still not change
what the pinned published 0.2.2 packages expose. TestLab #31's gap-closure acceptance therefore
remains pending even when the three-way regression gate passes. No Rust 0.3.0 release is required.
