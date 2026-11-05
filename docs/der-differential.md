<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 Marek Cingel -->

# DER differential against asn1c

`scripts/run_der_differential.py` decodes and encodes the same DER fixtures with OpenTLV Lua
v0.3.0 and the [asn1c reference adapter](asn1c-reference.md), then judges each library against an
expectation written by hand from ITU-T X.690. Neither library defines what is correct: a
fixture's expected value, bytes or error come from the rule it names, and a library that differs
from them fails that check. This is [#21](https://github.com/OpenTLV/opentlv-testlab/issues/21).

The comparison is TestLab infrastructure. It adds nothing to OpenTLV Core or any binding,
acquires OpenTLV Lua from luarocks.org as the [dependency policy](dependencies.md#fresh-opentlv-package-from-luarocks)
requires, and uses asn1c only through its adapter under `build/`.

## What each library can decide

OpenTLV is a TLV library, not an ASN.1 compiler, so the comparison uses only what OpenTLV Lua
offers for DER:

- `opentlv.formats.der` and `opentlv.visit_tree()`, which runs Core's strict `tlv_der_visit()`
  over every nested element: identifier and length rules of X.690 8.1, 10.1 and 10.2;
- the `opentlv.codecs.asn1.*` value codecs, which apply the canonical contents rules of
  X.690 section 11 to BOOLEAN, INTEGER, BIT STRING, NULL, OBJECT IDENTIFIER and IA5String;
- the DER Tree Writer, which writes minimal definite lengths.

OpenTLV Lua binds no DER schema layer. Core's `der_schema.h` checks SET and SET OF order,
DEFAULT omission and component presence, but no Lua function reaches it. The TestLab adapter
therefore matches tags to the schema's components itself, and a rejection it makes is marked
`source: adapter` and never counts as an OpenTLV verdict.

asn1c decodes DER with its BER decoder, so it checks no DER restriction
([DER decoding](asn1c-reference.md#der-decoding)). Its DER encoder canonicalizes what it decoded
([DER encoding](asn1c-reference.md#der-encoding)). TestLab therefore derives asn1c's DER verdict:
an input is DER for asn1c when it decodes and its DER re-encoding equals the input. A different
re-encoding is reported as `noncanonical` and normalized to `invalid`. This verdict also covers
padded tags and constructed strings, which asn1c accepts as BER.

| X.690 rule | OpenTLV Lua | asn1c |
| --- | --- | --- |
| Minimal definite lengths (10.1) | Strict traversal | Re-encoding |
| Minimal tag numbers, primitive strings and constructed SEQUENCE and SET (8.1.2, 10.2) | Strict traversal | Re-encoding or decoder |
| Canonical BOOLEAN, INTEGER, BIT STRING and OBJECT IDENTIFIER contents (8, 11) | Codecs | Re-encoding, except an empty INTEGER and a padded subidentifier |
| INTEGER beyond int64 | Not representable | Any size |
| DEFAULT omission (11.5), SET order (10.3) and SET OF order (11.6) | Not bound in Lua | Re-encoding |
| Schema conformance: tags, required and repeated components | TestLab adapter only | Decoder |
| Empty, truncated and trailing input | Framing | Decoder |

## Run the comparison

Set up both libraries, then run the corpus:

```sh
python3 scripts/setup_lua.py --lua lua5.2
python3 scripts/setup_asn1c.py
python3 scripts/run_der_differential.py
```

The run prints one line per fixture, the summary and each check's judged count. It ends with:

```text
98 pass, 0 mismatch of 98 fixtures
```

To reproduce one fixture and keep every observation:

```sh
python3 scripts/run_der_differential.py --fixture length-128 --output build/der-one.json --report build/der-one.md
```

`--lua-provenance` and `--asn1c-provenance` select setup receipts; otherwise the newest complete
receipt in `--lua-runs-dir` (default `build/dependency-runs`) and `--asn1c-runs-dir` (default
`build/asn1c-runs`) are used. Both are revalidated as the [BER runner](differential-runner.md#how-a-run-works)
and [`check_asn1c.py`](asn1c-reference.md#capability-audit) do, and the asn1c receipt must have
audited the committed capability probes.

| Exit code | Meaning |
| --- | --- |
| 0 | Every judged check passed |
| 1 | Run failure, including a declared limitation that did not occur; no verdict can be trusted |
| 2 | Invalid command-line usage |
| 3 | At least one judged check failed |

## Checks

Each fixture names a schema type of [`TestLabReference-1`](../differential/asn1c/TestLabReference-1.asn1)
and expects either a canonical value or a rejection.

A **canonical** fixture gives the typed value and its DER bytes. Seven checks apply:

| Check | Passes when |
| --- | --- |
| `opentlv.decode` | OpenTLV decodes the bytes to the expected value |
| `opentlv.round-trip` | OpenTLV re-encodes its decoded value to the same bytes |
| `opentlv.encode` | OpenTLV encodes the expected value to the bytes |
| `asn1c.decode` | asn1c decodes the bytes to the expected value |
| `asn1c.encode` | asn1c re-encodes its decoded value to the bytes; asn1c encodes only values it decoded |
| `interop.opentlv-to-asn1c` | asn1c decodes OpenTLV's encoding to the expected value |
| `interop.asn1c-to-opentlv` | OpenTLV decodes asn1c's re-encoding to the expected value |

Encoders are compared byte for byte only through these checks, so always for one schema type and
one logical value. A **rejection** fixture gives the bytes and one normalized error; only
`opentlv.decode` and `asn1c.decode` apply.

| Error | OpenTLV | asn1c |
| --- | --- | --- |
| `empty` | No input | `empty` |
| `truncated` | `TRUNCATED` while reading the root | `truncated` (`RC_WMORE`) |
| `trailing` | Bytes after the first root | `trailing` |
| `invalid` | Any other `TRUNCATED`, `INVALID_LENGTH`, `INVALID_TAG`, `INVALID_TAG_SIZE` or `INVALID_VALUE` | `malformed`, `constraint` or `noncanonical` |

Every observation keeps the native result: OpenTLV's error text and code, asn1c's `asn_dec_rval_t`
code and its canonical re-encoding. Any other OpenTLV error, a crash, a timeout or a malformed
adapter response is a run failure.

### Limitations

A fixture declares what a library cannot decide, with the reason and the documentation or
capability probe behind it:

```json
"limitations": {"asn1c.decode": "asn1c accepts an INTEGER without contents ... (capability probe ber-integer-empty)"}
```

`opentlv.decode`, `opentlv.encode`, `asn1c.decode` and `asn1c.encode` can be limited. Every check
that uses a limited operation becomes `limited`: it keeps its observation, never counts as a pass
and never decides the run. A round trip uses OpenTLV's decoder and encoder, and a cross check uses
both libraries. A limitation that does not show in its own check fails the run, so a corpus cannot
keep a claim about a library that is no longer true. A fixture must leave at least one library
judged.

## DER corpus

[`differential/fixtures/der-canonical.json`](../differential/fixtures/der-canonical.json) holds 98
fixtures: 55 canonical and 43 rejections. 13 declare a limitation.

| Category | Fixtures | What they cover |
| --- | --- | --- |
| `primitive` | 22 | BOOLEAN, INTEGER from -2^64 to 2^63 including sign octets and int64 limits, BIT STRING padding, OCTET STRING, IA5String, NULL and OBJECT IDENTIFIER with multi-octet, joint and 32-bit arcs |
| `zero-length` | 8 | Empty strings, BIT STRING, SEQUENCE OF, SET OF, absent OPTIONAL components and empty high-tag values |
| `tag-boundary` | 6 | Tag 30, the last low-tag number; tags 31 and 200 in high-tag form; application and private classes; an explicit tag |
| `length-boundary` | 5 | Lengths 127, 128, 255 and 256, and long-form lengths at two nesting levels |
| `constructed` | 12 | SEQUENCE, OPTIONAL and DEFAULT components, SEQUENCE OF, canonically ordered SET and SET OF, and CHOICE |
| `nested` | 2 | Three levels of SEQUENCE, and empty nested components |
| `truncated` | 8 | Empty input, truncated identifier, length, value and component, and trailing octets or elements |
| `noncanonical` | 16 | Long-form and nonminimal lengths, indefinite lengths, padded and high-form tag numbers, a constructed string, TRUE as `01`, nonminimal INTEGER, set BIT STRING padding, a padded subidentifier, an encoded DEFAULT, and unsorted SET and SET OF |
| `malformed` | 19 | Reserved and primitive indefinite lengths, wrong forms, end-of-contents, a component past its parent, invalid BOOLEAN, INTEGER, BIT STRING, NULL, OBJECT IDENTIFIER and IA5String contents, and schema violations |

[`TestLabReference-1.json`](../differential/der/TestLabReference-1.json) describes each schema type
for the OpenTLV adapter: its kind, its identifier octets and its components. The runner requires the
same types in the same order as the `.asn1` module. A wrong description cannot pass unnoticed,
because asn1c decodes from the module itself.

The runner validates every fixture before running anything. A canonical fixture's bytes must equal
the DER encoding of its value as computed by a small independent encoder in the runner, which
applies X.690 minimal lengths and integers, DEFAULT omission and SET and SET OF ordering. A
rejection's declared `empty`, `truncated` or `trailing` error must match the framing of its bytes.
Neither library output can define an expectation. Wire size is limited to 4096 bytes.

### Coverage

Judged counts are fixed by the corpus: a check is judged on every fixture it applies to, except
where a limitation removes it.

| Check | Applies to | Judged |
| --- | --- | --- |
| `asn1c.decode` | 98 | 95 |
| `asn1c.encode` | 55 | 55 |
| `interop.asn1c-to-opentlv` | 55 | 53 |
| `interop.opentlv-to-asn1c` | 55 | 52 |
| `opentlv.decode` | 98 | 89 |
| `opentlv.encode` | 55 | 52 |
| `opentlv.round-trip` | 55 | 52 |

### Add a fixture

Write the bytes and the expected value or error from the X.690 rule, add the fixture to the corpus
and run the checks:

```json
{
  "id": "octet-string-two",
  "category": "primitive",
  "description": "Two-octet OCTET STRING",
  "rule": "X.690 10.2: primitive form",
  "type": "Octets",
  "wire": "04 02 aa bb",
  "expected": {"result": "canonical", "value": {"kind": "octet_string", "value": "aabb"}}
}
```

```sh
python3 -m unittest discover -s tests
python3 scripts/run_der_differential.py --fixtures differential/fixtures/der-canonical.json
```

A rejection expects `{"result": "reject", "error": "invalid"}` or another error from the table
above. Values use the [typed value](asn1c-reference.md#typed-values) form of the asn1c adapter,
including a DEFAULT component with its default value, as asn1c fills it in. When a judged check
fails, investigate before declaring a limitation. Declare one only when documentation or a
capability probe explains the difference, and cite it in the reason.

## Results

Local verification on 2026-11-04, in WSL on Ubuntu 24.04 x86-64 with Lua 5.2.4 and GCC 13.3.0 from a
clean clone, passed every judged check on all 98 fixtures in under a second. A repeated run gave a
byte-identical JSON report. No OpenTLV defect was found within this intersection, and no asn1c result
contradicted its capability audit.

| Finding | Library | Fixtures |
| --- | --- | --- |
| Strict traversal and the codecs reject every noncanonical length, tag, form and primitive contents in the corpus, each with a library error, not an adapter one | OpenTLV | 28 rejections |
| INTEGER beyond int64 is rejected with `INVALID_VALUE`, which Core's `asn1_codec.h` documents, so it cannot be told apart from noncanonical contents; the encoder rejects the argument | OpenTLV (limitation) | `integer-above-int64`, `integer-below-int64` |
| An encoded DEFAULT value and unsorted SET and SET OF are accepted, and a DEFAULT value is written when given | OpenTLV Lua (limitation, no DER schema layer) | `default-omitted`, `default-encoded`, `set-unsorted`, `set-of-unsorted` |
| Missing, repeated and wrongly tagged components are rejected only by the TestLab adapter | OpenTLV Lua (limitation) | 4 rejections |
| The re-encoding verdict rejects what the BER decoder accepts: nonminimal and indefinite lengths, padded and high-form tag numbers, a constructed string, invalid BOOLEAN, INTEGER and BIT STRING contents, an encoded DEFAULT and unsorted SET and SET OF | asn1c | 18 rejections |
| `04 80 00 00` reports trailing input, and `02 00` and `06 03 2a 80 03` re-encode unchanged | asn1c (limitation) | `length-indefinite-primitive`, `integer-empty`, `oid-leading-80` |
| Both libraries normalize to the same error on every rejection that both judge, and each decodes the other's encodings | Both | 33 rejections, 105 cross checks |

The run's reports hold the complete outcome matrix and every observation. In the Markdown report:

- **Mismatches: possible defects** lists each failed check with its difference, the input and
  commands that reproduce only that fixture.
- **Coverage** counts the outcomes of each check and category.
- **Outcome matrix** gives every check of every fixture.
- **Declared limitations: not defects** shows what each limitation looked like in this run.

The JSON report adds each library's complete observation, the runtime, platform, compiler,
package commits, both setup receipts, the corpus SHA-256 and the TestLab commit. Neither report has
timestamps.

A mismatch is a possible defect, not a finding. Check the fixture against its rule first, then the
library's documentation and the capability audit. Report a confirmed defect that is not a security
issue to the repository that owns the library. `scripts/check_report.py FILE` reruns each mismatch
in a JSON report from either runner and requires the same result.

## Security and triage

Public CI runs only the committed, reviewed corpus. Inputs from [differential fuzzing](differential-fuzzing.md)
stay local until triage, under its [disclosure policy](differential-fuzzing.md#disclosure-policy). A suspected
vulnerability in OpenTLV goes to its private security reporting, and one in asn1c to upstream's
private channel in its `SECURITY.md`, never to a public issue, CI artifact or fixture. A crash or
timeout is a run failure, not a result.

## Fast CI

The `DER differential against asn1c` job in [Fast](ci.md#fast-gate) sets up both libraries from
exact-key caches, runs the corpus, and requires the deliberate probe in
[`tests/fixtures/der_mismatch.json`](../tests/fixtures/der_mismatch.json) to exit with code 3 and
reproduce its report. The probe omits the `opentlv.encode` limitation of `default-omitted`. It
uploads the reports as the `der-differential-reports` artifact, even after a failure.

## Limits

- Only the 21 types of `TestLabReference-1` are covered, in the typed-value forms both adapters
  share. OBJECT IDENTIFIER arcs above 2^32-1 are excluded, because asn1c reduces them modulo 2^32
  (capability probe `ber-oid-arc-above-32-bits`).
- The verdict is X.690 DER for these types and values, not a complete DER conformance claim for
  either library. Constraints beyond the schema, REAL, time and other string types are not covered.
- OpenTLV is exercised through its Lua binding only; Core's `der_schema.h` and other bindings are
  not compared.
- Only Linux and WSL with GCC were verified, and the Extended suite does not run this comparison.
