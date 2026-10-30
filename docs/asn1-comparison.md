<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 Marek Cingel -->

# ASN.1 Lua comparison scope

## Identity and reproducible pin

This document resolves the shorthand **asn1-lua** in
[issue #2](https://github.com/OpenTLV/opentlv-testlab/issues/2) to the original
[`kunkku/lua-asn1`](https://github.com/kunkku/lua-asn1) project, imported as
`require("asn1")`. It does not select one of its forks, a ComputerCraft-specific
implementation, or a similarly named ASN.1 package.

| Property | Selected value |
| --- | --- |
| Upstream version | `2.2.1`, tag `v2.2.1` |
| Immutable source | `ac0c68c796143d1698ec88790bfd8b405a9d3f64` |
| License | MIT; Copyright (c) 2015-2025 Kaarle Ritvanen |
| Core module | `asn1/init.lua`; pure Lua, requires `bit32` and `table.unpack` |
| Initial runtime | Stock PUC Lua 5.2; local audit uses 5.2.4 |
| Integrity | SHA-256 for all five upstream files in `dependencies/lua-asn1.json` |
| Verification date | 2026-10-30 |

Primary evidence: the [tagged source][source], [license][license], and
[upstream Makefile][makefile]. The Makefile installs the three modules under
`$(ROOT_DIR)/usr/share/lua/common/asn1`; `ROOT_DIR` permits staging. No rockspec
or runtime support matrix is present at this revision. LuaRocks searches for
`asn1` and `asn1-lua`, including non-root modules, returned no package on the
verification date. Therefore there is no verified `luarocks install asn1-lua`
command or rock revision to pin. The [dependency setup](dependencies.md) uses
the upstream Makefile for a staged source installation.

The audit fetches commit-addressed files and verifies their bytes without
installing anything globally. It preserves `LICENSE` and every source notice.
It never patches upstream behavior. `asn1.rfc3779` additionally requires
`stringy`; that module and the RFC-specific schemas are outside this comparison,
so no `stringy` dependency is needed for `require("asn1")`.

## Runtime compatibility

These are requirements inferred from the pinned source, not a claim that
upstream publishes a tested compatibility matrix.

| Runtime | Unmodified source requirements | Initial TestLab status |
| --- | --- | --- |
| Lua 5.1 | No standard `bit32` or `table.unpack` | Excluded; would need dependencies/shims |
| Lua 5.2 | Both facilities are standard | Selected; capability audit executed on 5.2.4 |
| Lua 5.3 | `table.unpack` present; `bit32` depends on compatibility build/external module | Deferred until dependency/runtime setup is pinned |
| Lua 5.4 | `table.unpack` present; external `bit32` required | Deferred until dependency/runtime setup is pinned |
| LuaJIT | Its `bit` API is not `require("bit32")`; `table.unpack` is build-dependent | Excluded from initial scope |

OpenTLV Lua targets Lua 5.1-5.4 and LuaJIT. Lua 5.2 is the initial common runtime;
its selection does not reduce OpenTLV's own supported matrix. See the
[Lua 5.2 manual](https://www.lua.org/manual/5.2/manual.html#6.7) for `bit32` and
the [Lua 5.3 compatibility notes](https://www.lua.org/manual/5.3/manual.html#8.2).

## Comparison contract

The external API is a typed, schema-driven **DER-oriented** encoder/decoder,
not a generic BER reader. DER-compatible definite-length encodings provide the
initial BER intersection; this audit does not establish full DER conformance
of the external implementation. OpenTLV's BER reader returns raw Tag, Length
and Value bytes and does not automatically validate ASN.1 primitive semantics.

OpenTLV API inspection is tied to Lua commit
`adabdbe9b85187ff5db877142b26d33d20a5917e` and its Core v0.8.0 pin
`345c77acb29266036df5f27d04ce315bb61853cc`; see its [API guide][lua-api].
This is a source reference for the matrix, not a published-package acquisition
result. The [dependency setup](dependencies.md#fresh-opentlv-release-package)
separately pins and freshly acquires the OpenTLV package under test.

Each comparable fixture must carry its ASN.1 schema. Initially require one
complete root, short-form definite length **0-127 at every level**, low tag
numbers **0-30**, universal or context-specific class, and canonical primitive
value bytes. Bound nesting (initially at most four levels) and input size in the
future corpus. Do not infer a schema from the same library output being tested.

Use `syntax.decode(wire)` / `syntax.encode(value)` (dot calls, not colon calls)
for external types. Use `opentlv.read_source(wire, opentlv.formats.ber)` and check
its encoded size against `#wire`; descend into constructed `element.value` with
Reader `next_source()`. A Source is needed for the original length bytes: the
v0.3.0 API guide lists `raw_length` on elements, but the installed elements have no
such field. Encoding uses `opentlv.formats.ber:encode(tag, value)` or Writer/Tree
Writer with fixture-specified raw values.

Preserve identifier bytes, original length bytes, numeric value length, raw
primitive values, ordered children and consumed size. An external typed result
alone does **not** expose all those fields. Its adapter must map the result
through the explicit fixture schema, compare typed values against the expected
raw payload, and retain the original wire separately. Never use re-encoding as
proof that a decoder preserved noncanonical bytes. For encoding, compare exact
output bytes only for fixtures with one agreed canonical representation.

## Concrete comparison matrix

`Shared` means eligible for the differential corpus, not evidence that both
libraries have run on every listed fixture; the
[runner guide](differential-runner.md) identifies what currently runs. Probe IDs
refer to `tests/asn1_capabilities.lua`; those checks characterize the external pin only.

| Operation / fixture | External operation | OpenTLV Lua operation | Decision / comparison |
| --- | --- | --- | --- |
| Empty and binary OCTET STRING (`04 00`, `04 03 00 ff 41`) | `asn1.octet_string.decode/encode` | BER read / encode tag `04` | Shared; exact payload and wire (`octets-*`) |
| Short length 127 | `octet_string.decode/encode` | BER read / encode | Shared at every nesting level (`short-length-127`) |
| BOOLEAN `00` / `ff` | `asn1.boolean.decode/encode` | BER framing plus fixture raw value | Shared for canonical false/true only (`boolean-*`) |
| Positive INTEGER 1 through 2^31-1 | `asn1.integer.decode/encode` | BER framing plus explicit minimal positive bytes | Shared bounded range; sign padding required, e.g. 128 = `02 02 00 80` (`integer-positive`) |
| BIT STRING | `asn1.bit_string.decode/encode` | BER framing with unused-bit count and raw payload | Shared with valid padding; map bit text through schema (`bit-string`) |
| IA5String | `asn1.ia5string.decode/encode` | BER framing, tag `16` | Shared ASCII fixtures only (`ia5-string`); no Unicode validation claim |
| SEQUENCE, SEQUENCE OF, nesting | `asn1.sequence{...}`, `asn1.sequence_of(type)` | BER read + recursive descent / Tree Writer | Shared schema-fixed ordered children; all nested lengths <=127 (`nested-sequence`, `empty-sequence-of`) |
| Context implicit / explicit tags | `type{tag=n}`, `asn1.explicit(n, type)` | BER read / encode raw identifier and child bytes | Shared tags 0-30 (`implicit-context-30`, `explicit-context`) |
| Truncated tag/length/value, truncated child | Typed decode under `pcall` | Final-input BER read and recursive descent | Shared rejection only; empty input must be classified as missing required root by adapter (`truncated-*`, `empty-input`) |
| Extra complete root / trailing bytes | Typed decode rejects full-input length mismatch | Reader accepts streams; `read` consumes first only | Shared rejection only after explicit one-root consumption policy (`trailing-element`) |
| Length boundary 127/128 and 255/256 | Long-length code exists but has reversed shift arguments | BER supports long definite lengths | Known external difference; exclude all long-form lengths from initial pass/mismatch gate (`known-difference-long-length-*`) |
| Truncated long-form header, reserved length `ff` | `04 81` and `04 ff` decode as empty; `04 82 01` is rejected | Rejected as truncated or invalid length | Excluded with the other long forms; no malformed-input verdict from disagreement (`truncated-long-header`, `ambiguous-truncated-long-header`, `ambiguous-reserved-length`) |
| High-tag-number form, tag >=31 | Explicit assertions reject it | BER supports high tags | Unsupported external capability (`high-tag`, `high-tag-encode`) |
| Application / private class | Tag builder maps only universal/context | BER accepts all classes | Unsupported (`application-private-classes`) |
| Indefinite length / EOC | `split` rejects length `80` | BER supports constructed indefinite framing | Unsupported; no differential malformed-input verdict from disagreement (`indefinite-length`, `indefinite-constructed`) |
| Constructed OCTET/BIT STRING | Primitive tag expected; no fragment concatenation | BER tree framing supported | Unsupported external typed operation (`constructed-octets`) |
| Negative INTEGER / large arbitrary precision | Negative values explicitly rejected; Lua number accumulation | Raw BER bytes, optional number codecs | Unsupported negative values; large-number semantic comparison deferred (`negative-integer`) |
| INTEGER zero encoding | Decoder accepts `02 01 00`; encoder calls `bit32.band(nil, ...)` | Can encode the raw value `00` | Decoding `02 01 00` is shared; known external difference, so exclude zero encoding (`known-difference-integer-zero`) |
| NULL, OID, REAL, SET / SET OF, ASN.1 time types | No corresponding core type constructors | Can frame their raw tags/values | Unsupported typed comparison; generic framing is not equivalent semantic support |
| Nonminimal lengths/integers, noncanonical BOOLEAN, BIT padding, invalid IA5 | No reliable general validity contract; typed information can be lost | BER framing often accepts opaque values | Inconclusive for initial differential verdict; preserve bytes and explain ambiguity |
| Invalid BOOLEAN value length | `01 00` returns true; `01 02 00 ff` returns false | Raw TLV framing succeeds | No shared ASN.1 semantic validation oracle (`semantic-boolean-validation`) |
| CHOICE, optional/default fields, constraints, RFC schemas | `choice` loses false values; other semantics are schema-specific | Different schema/codec API | Deferred; false CHOICE characterized by `choice-false-limitation` |
| Incremental input, streaming, source preservation | No equivalent external API | Reader / Tree Reader / Source | Outside shared scope |

The long-length defect is visible in `split` as `bit32.lshift(8, meta.len)`
and in the encoder as `bit32.rshift(8, len)`, with the operands reversed for
base-256 accumulation. The audit records observable examples: canonical length
128 is rejected on decode; length 256 encodes as `04 81 00` plus 256 payload
bytes. It also records acceptance of `04 81 00` plus eight bytes, so this
implementation must not be treated as a malformed-BER oracle. These are known
differences of this exact pin, not failures attributed to OpenTLV.

## Outcomes and error boundaries

The [differential runner](differential-runner.md) applies these rules. Eligibility
is declared by the fixture **before** any comparison runs:

- **Pass**: both operations satisfy a shared fixture's explicit expectations.
- **Mismatch**: a supported, unambiguous fixture differs in bytes/tree/value or
  accept/reject result. Preserve both outputs; do not immediately assign blame.
- **Unsupported**: a missing external operation or an excluded known limitation;
  attach the matrix reason. Do not count it as a successful comparison.
- **Inconclusive**: the fixture's semantics, canonical form or validation
  contract do not support a fair verdict. Retain bytes and the reason.

External errors are Lua assertions/strings, sometimes incidental type errors.
Only normalize them to `rejected` for the narrow malformed framing cases;
do not equate error text, offsets or detailed categories with `opentlv.Error`.
A crash, timeout, missing dependency or wrong source hash is an audit/run failure,
never an `unsupported` result that turns CI green. The runner distinguishes
resource-limit failures from BER rejection.

## Verification and follow-up ownership

Run the [README commands](../README.md#run-the-capability-audit) to verify the
pin and execute the characterization checks, including expected upstream
limitations. The audit intentionally fails if those observations change:
updating the pin requires revisiting the matrix, not silently accepting a fork
or local fixes. Python tests verify that changed/missing source is rejected.

Fast now runs that audit on the cached installed external library, alongside
fresh OpenTLV package setup, the differential seed fixtures and the BER corpus. Hosted CI evidence
must be checked on the PR; local execution alone does not fulfill the hosted Fast
gate. The standalone scope audit does not acquire OpenTLV or execute the runner.

Local evidence on 2026-10-30: all 35 capability checks passed under WSL with
stock Lua 5.2.4; all four Python source-integrity tests passed on Windows and
WSL. Fresh source acquisition and the offline verification path both succeeded.
Workflow YAML and local documentation file links were also checked. Hosted Fast
remained unverified at that point.

- [#3](https://github.com/OpenTLV/opentlv-testlab/issues/3): installation, versioned
  cache and fresh OpenTLV package acquisition; consume the committed source pin.
- [#4](https://github.com/OpenTLV/opentlv-testlab/issues/4): adapters and runner;
  schema projection and the complete-root policy above are implemented.
- [#5](https://github.com/OpenTLV/opentlv-testlab/issues/5): deterministic
  [BER corpus](differential-runner.md#ber-corpus) with shared, unsupported,
  known-difference and inconclusive cases declared explicitly.
- [#6](https://github.com/OpenTLV/opentlv-testlab/issues/6): reproducible
  [mismatch reports](differential-runner.md#mismatch-reports) and CI artifacts.
- [#7](https://github.com/OpenTLV/opentlv-testlab/issues/7): the
  [Fast gate and manual extended suite](ci.md).
- [#8](https://github.com/OpenTLV/opentlv-testlab/issues/8): end-to-end workflow docs.

[source]: https://github.com/kunkku/lua-asn1/blob/ac0c68c796143d1698ec88790bfd8b405a9d3f64/asn1/init.lua
[license]: https://github.com/kunkku/lua-asn1/blob/ac0c68c796143d1698ec88790bfd8b405a9d3f64/LICENSE
[makefile]: https://github.com/kunkku/lua-asn1/blob/ac0c68c796143d1698ec88790bfd8b405a9d3f64/Makefile
[lua-api]: https://github.com/OpenTLV/opentlv-lua/blob/adabdbe9b85187ff5db877142b26d33d20a5917e/docs/api.md
