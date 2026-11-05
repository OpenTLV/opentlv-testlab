<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 Marek Cingel -->

# BER and CER differential against asn1c

`scripts/run_ber_cer_differential.py` decodes and encodes the same BER and CER fixtures with
OpenTLV Lua v0.3.0 and the [asn1c reference adapter](asn1c-reference.md), then judges each library
against an expectation written by hand from ITU-T X.690. Neither library defines what is correct.
This is [#22](https://github.com/OpenTLV/opentlv-testlab/issues/22), which follows the
[DER differential](der-differential.md) of #21 and uses the same receipts, schema and adapter
conventions.

The comparison is TestLab infrastructure. It adds nothing to OpenTLV Core or any binding,
acquires OpenTLV Lua from luarocks.org as the [dependency policy](dependencies.md#fresh-opentlv-package-from-luarocks)
requires, and uses asn1c only through its adapter under `build/`.

## What each library can decide

BER allows many encodings of one value, so a BER encoder is never compared byte for byte. CER is
canonical, so its encoders are compared byte for byte, always for one schema type and one value.

OpenTLV is a TLV library, not an ASN.1 compiler. The comparison uses only what OpenTLV Lua offers:

- `opentlv.formats.ber`, which reads definite and indefinite lengths, end-of-contents octets and
  high tag numbers, and `opentlv.formats.cer`, which also requires the indefinite form for
  constructed values and the fewest length octets for primitive ones (Core's `ber.h` and `cer.h`);
- `opentlv.visit_tree()` over every nested element with the same Format;
- the `opentlv.codecs.asn1.*` value codecs, which apply the canonical contents rules of X.690
  section 11 to BER as well, as Core's `asn1_codec.h` documents;
- the Tree Writer, which writes definite lengths for BER and indefinite ones for CER.

OpenTLV Lua binds neither an ASN.1 schema layer nor Core's `cer_validation.h`, which checks string
segmentation and writes segmented strings. The TestLab adapter therefore matches tags to components,
rejects a constructed form of a type that has none and joins the segments of a constructed string
itself. A rejection it makes is marked `source: adapter` and never counts as an OpenTLV verdict.

asn1c decodes BER and also reads CER with its BER decoder, which accepts every BER form, so it
cannot judge a CER restriction ([capability probe](asn1c-reference.md#cer) `cer-form-as-ber`). It
has no CER encoder (`cer-encode`). Its BER re-encoding is DER, which is valid BER.

| X.690 rule | OpenTLV Lua | asn1c |
| --- | --- | --- |
| Identifier, length and end-of-contents framing (8.1) | BER and CER Format | BER decoder |
| Primitive contents (8.2 to 8.23) | Codecs, with the canonical rules of section 11 | BER decoder, with the exceptions its probes record |
| Constructed strings (8.6.4, 8.7.3) | Framing; the adapter joins segments | Only segments that repeat the type's own tag |
| CER indefinite constructed and minimal primitive lengths (9.1) | CER Format | Not comparable |
| CER segmentation of strings over 1000 octets (9.2) | Not bound in Lua | Not comparable |
| DEFAULT omission (11.5), SET (9.3) and SET OF (11.6) order | Not bound in Lua | Not comparable for CER |
| Schema conformance | TestLab adapter only | Decoder |
| Empty, truncated and trailing input | Framing | Decoder |

## Independent X.690 reference

[`scripts/x690.py`](../scripts/x690.py) decodes BER or CER into the [typed values](asn1c-reference.md#typed-values)
of the asn1c adapter, and writes CER. It shares no code with either library. The runner uses it to:

- validate every fixture before running anything: an expected value must be what the reference
  decodes, a CER fixture's bytes must equal its CER encoding of the value, and a rejection must be
  rejected with the declared error;
- judge BER encoders by value: an encoding passes when the reference reads it back as the
  expected value, whatever its length forms;
- tell CER rejections that are still valid BER, which asn1c cannot decide, from those that are not.

Values are compared as logical values. A SET OF is unordered, so its items compare in any order;
padding bits of a BER BIT STRING are not part of the value and read as zero.

## Run the comparison

Set up both libraries, then run the corpus:

```sh
python3 scripts/setup_lua.py --lua lua5.2
python3 scripts/setup_asn1c.py
python3 scripts/run_ber_cer_differential.py
```

The run prints one line per fixture, then the summary and the judged share of all checks. It ends
with:

```text
154 pass, 0 mismatch, 0 confirmed of 154 fixtures
```

To reproduce one fixture and keep every observation:

```sh
python3 scripts/run_ber_cer_differential.py --fixture ber-indefinite-nested --output build/ber-cer-one.json --report build/ber-cer-one.md
```

`--lua-provenance`, `--asn1c-provenance`, `--lua-runs-dir` and `--asn1c-runs-dir` select setup receipts
as for the [DER differential](der-differential.md#run-the-comparison), and the asn1c receipt must
have audited the committed capability probes.

| Exit code | Meaning |
| --- | --- |
| 0 | No judged check is a mismatch; confirmed mismatches do not fail the run |
| 1 | Run failure, including a declaration that no longer holds; no verdict can be trusted |
| 2 | Invalid command-line usage |
| 3 | At least one judged check is a mismatch |

## Checks

Each fixture names its encoding, a schema type of [`TestLabReference-1`](../differential/asn1c/TestLabReference-1.asn1)
and either a value or a rejection.

A BER **accept** fixture gives the value of one valid BER encoding, often not the shortest one:

| Check | Passes when |
| --- | --- |
| `opentlv.decode` | OpenTLV decodes the bytes to the value |
| `opentlv.encode` | The X.690 reference reads OpenTLV's encoding of the value as the value |
| `asn1c.decode` | asn1c decodes the bytes to the value |
| `asn1c.encode` | The X.690 reference reads asn1c's re-encoding as the value |
| `interop.opentlv-to-asn1c` | asn1c decodes OpenTLV's encoding to the value |
| `interop.asn1c-to-opentlv` | OpenTLV decodes asn1c's re-encoding to the value |

A CER **canonical** fixture gives the value and its CER bytes, and has the seven checks of a
[DER canonical fixture](der-differential.md#checks), with CER in place of DER: decoding, the round
trip and encoding by OpenTLV, decoding and encoding by asn1c, and both cross checks. asn1c's
encoding and the cross check from asn1c are always a `limitation`, because asn1c writes no CER.

A **rejection** gives the bytes and one normalized error, and only `opentlv.decode` and
`asn1c.decode` apply. Errors are normalized as in the [DER differential](der-differential.md#checks):
`empty`, `truncated` while reading the root, `trailing` and `invalid`. A missing octet truncates the
input only where no definite length bounds the element, so an indefinite root that ends early is
`truncated`, while a component that overruns a definite parent is `invalid`.

### Outcomes

| Outcome | Meaning | Judged |
| --- | --- | --- |
| `pass` | The check met the X.690 expectation | Yes |
| `mismatch` | The check differs from the expectation: a possible defect, not yet triaged | Yes |
| `confirmed` | A triaged defect, declared with the issue that tracks it | Yes |
| `limitation` | The library lacks the operation or documents that it excludes the case | No |
| `not-comparable` | The library's behavior cannot decide the rule, as a capability probe records | No |
| `inconclusive` | The check had no input, because the producing encoder gave no encoding | No |

Only judged checks count towards the pass rate, so missing functionality is never a defect.

### Declarations

A fixture declares what a library cannot decide, with the reason and the documentation or
capability probe behind it:

```json
"limitations": {"opentlv.decode": "asn1.boolean applies the CER and DER rule of X.690 11.1 ... (asn1_codec.h)"},
"not_comparable": {"asn1c.decode": "asn1c accepts redundant leading INTEGER octets (capability probe ber-integer-nonminimal)"}
```

`limitations` and `not_comparable` name one of `opentlv.decode`, `opentlv.encode`, `asn1c.decode` and
`asn1c.encode`, and every check that uses that operation takes the outcome. `confirmed` names a check
and must link the OpenTLV issue that tracks the defect. The runner itself declares the CER cases of
asn1c: its missing CER encoder, and its BER reading of a CER rejection that is still valid BER, which
asn1c must then accept.

A declaration that does not show in its own check fails the run, and so does a runner-declared one,
so the corpus cannot keep a claim about a library that is no longer true. A fixture must leave at
least one library judged.

## BER and CER corpus

[`differential/fixtures/ber-cer-interop.json`](../differential/fixtures/ber-cer-interop.json) holds 154
fixtures: 99 BER (53 accept and 46 rejections) and 55 CER (32 canonical and 23 rejections).
30 declare a limitation and 11 a not-comparable library.

| Category | Fixtures | What they cover |
| --- | --- | --- |
| `primitive` | 15 | Negative, 2^31, 2^53 and 2^63 INTEGER, NULL, OBJECT IDENTIFIER with multi-octet arcs, BIT STRING and IA5String |
| `constructed` | 13 | SEQUENCE, OPTIONAL and DEFAULT components, SEQUENCE OF, SET, SET OF in CER order, CHOICE and an explicit tag |
| `nested` | 4 | Mixed definite and indefinite levels and a constructed component |
| `tag-boundary` | 12 | Tag 30, tags 31 and 200 in high-tag form, constructed high tags, application and private classes |
| `length-boundary` | 8 | Lengths 127, 128, 255 and 256, and the 1000-octet limit of primitive CER strings |
| `indefinite-length` | 7 | Indefinite SEQUENCE, SEQUENCE OF, SET and nesting, inside and around definite values |
| `end-of-contents` | 7 | End-of-contents as the root, in a definite value, with a length, constructed, repeated and too early |
| `alternate-form` | 12 | Valid BER that DER forbids: long and padded lengths, TRUE as `01`, set padding bits, an encoded DEFAULT, unsorted SET and SET OF |
| `segmented` | 15 | Constructed and nested strings, BIT STRING and IA5String segments, and CER segmentation of 1001 and 2000 octets |
| `truncated` | 23 | Empty input, truncated tags, lengths, values, segments and end-of-contents, and trailing octets |
| `malformed` | 24 | Reserved and primitive indefinite lengths, invalid tags, constructed primitive types, invalid contents and schema violations |
| `noncanonical` | 14 | Valid BER that CER forbids: definite constructed lengths, long-form lengths, short constructed and long primitive strings, wrong segment sizes, an encoded DEFAULT and unsorted SET and SET OF |

Fixtures reuse earlier evidence instead of new bytes. 45 name an `origin` in the
[BER corpus](differential-runner.md#ber-corpus) of #1: 40 of its 67 `unsupported` or `inconclusive`
fixtures, which lua-asn1 could not compare, now have a verdict here. 17 reuse rejections of the
[DER corpus](der-differential.md#der-corpus), most of them valid BER. The runner requires the same
bytes as the origin. The Rust `der-parser` integration of [#19](https://github.com/OpenTLV/opentlv-testlab/issues/19)
has no committed evidence yet.

### Coverage

Judged counts are fixed by the corpus: a check is judged on every fixture it applies to, except
where a declaration removes it.

| Encoding | Check | Applies to | Judged |
| --- | --- | --- | --- |
| BER | `asn1c.decode` | 99 | 85 |
| BER | `asn1c.encode` | 53 | 48 |
| BER | `interop.asn1c-to-opentlv` | 53 | 44 |
| BER | `interop.opentlv-to-asn1c` | 53 | 47 |
| BER | `opentlv.decode` | 99 | 88 |
| BER | `opentlv.encode` | 53 | 52 |
| CER | `asn1c.decode` | 55 | 36 |
| CER | `asn1c.encode` | 32 | 0 |
| CER | `interop.asn1c-to-opentlv` | 32 | 0 |
| CER | `interop.opentlv-to-asn1c` | 32 | 25 |
| CER | `opentlv.decode` | 55 | 48 |
| CER | `opentlv.encode` | 32 | 26 |
| CER | `opentlv.round-trip` | 32 | 26 |

Of 680 checks, 525 (77.2%) are judged.

### Add a fixture

Write the bytes and the expected value or error from the X.690 rule. To see how the independent
reference reads them, which every fixture must match, decode them by hand; `--encoding cer`
applies CER, and a rejection exits with code 1:

```sh
python3 scripts/x690.py Octets "24 80 04 01 aa 04 01 bb 04 01 cc 00 00"
```

Then add the fixture to the corpus and run the checks:

```json
{
  "id": "ber-octets-indefinite-three",
  "encoding": "ber",
  "category": "segmented",
  "description": "Indefinite constructed OCTET STRING with three segments",
  "rule": "X.690 8.7.3, 8.1.3.6",
  "type": "Octets",
  "wire": "24 80 04 01 aa 04 01 bb 04 01 cc 00 00",
  "expected": {"result": "accept", "value": {"kind": "octet_string", "value": "aabbcc"}}
}
```

```sh
python3 -m unittest discover -s tests
python3 scripts/run_ber_cer_differential.py --fixtures differential/fixtures/ber-cer-interop.json
```

A CER fixture uses `canonical` in place of `accept`, and its bytes must be the CER encoding of the
value. A rejection expects `{"result": "reject", "error": "invalid"}` or another normalized error.
Name an `origin` such as `asn1-ber:indefinite-empty` when the bytes come from an earlier corpus. When
a judged check fails, investigate before declaring anything; declare only what documentation or a
capability probe explains, and cite it in the reason.

## Results

Local verification on 2026-11-04, in WSL on Ubuntu 24.04 x86-64 with Lua 5.2.4 and GCC 13.3.0 from a
clean clone, passed every judged check on all 154 fixtures in under half a second. A repeated run
gave byte-identical JSON and Markdown reports.

### Bugs

No OpenTLV defect was found within this intersection, so the corpus declares no confirmed mismatch.
asn1c disagreed with X.690 on valid and invalid BER. Its behavior is reproducible with the pinned
release, so six new [capability probes](asn1c-reference.md#ber-decoding) record it, and the
fixtures that depend on it cite them. asn1c is a test oracle here, and these findings have not been
reported upstream.

| Finding | Library | Classification | Fixtures |
| --- | --- | --- | --- |
| Rejects constructed strings whose segments are OCTET STRINGs when the type is IA5String or implicitly tagged, and accepts segments that repeat the type's tag instead | asn1c | Limitation (`ber-constructed-ia5-octet-segments`, `ber-constructed-implicit-octet-segments`) | 6 |
| Rejects an indefinite length on an explicit tag around INTEGER | asn1c | Limitation (`ber-explicit-indefinite-primitive`) | 2 |
| Accepts an unterminated last OBJECT IDENTIFIER subidentifier | asn1c | Not comparable (`ber-oid-incomplete-subidentifier`) | 1 |
| Accepts invalid BOOLEAN, INTEGER, BIT STRING and OBJECT IDENTIFIER contents and nonminimal tags, as its earlier probes record | asn1c | Not comparable | 10 |

### Limitations

| Finding | Library | Fixtures |
| --- | --- | --- |
| BER TRUE other than `ff` and set BIT STRING padding are rejected, because the codecs apply the canonical rules of section 11 | OpenTLV | 3 |
| INTEGER beyond int64 is rejected on decoding and encoding | OpenTLV | 1 |
| CER string segmentation is not checked, and long strings are written in primitive form, because `cer_validation.h` is not bound | OpenTLV Lua | 9 |
| An encoded DEFAULT and unsorted SET and SET OF are accepted in CER, and a DEFAULT value is written when given | OpenTLV Lua | 4 |
| Constructed primitive types, wrong segment tags and schema violations are rejected only by the TestLab adapter | OpenTLV Lua | 7 |
| No CER encoder, and no CER restriction decided for valid BER | asn1c | 32 canonical, 14 rejections |

OpenTLV's BER and CER Formats rejected every malformed framing in the corpus with a library error:
reserved and primitive indefinite lengths, misplaced or malformed end-of-contents octets, padded tag
numbers, the high-tag form for a low number in CER, definite constructed and nonminimal lengths in
CER and truncation at every level. Each library decodes the other's encodings wherever both are
judged.

The run's reports hold the complete outcome matrix and every observation. In the Markdown report:

- **Mismatches: possible defects** lists each mismatched check with its difference, the input and
  commands that reproduce only that fixture.
- **Bugs: confirmed mismatches** lists declared, tracked defects.
- **Coverage** counts each outcome per encoding and check, with the judged share, and per category.
- **Outcome matrix** gives every check of every fixture, per encoding.
- **Limitations and not-comparable cases: not defects** shows what each declaration looked like in
  this run.

The JSON report adds each library's complete observation, the runtime, platform, compiler, package
commits, both setup receipts, the corpus SHA-256 and the TestLab commit. Neither report has
timestamps. `scripts/check_report.py FILE` reruns each mismatch in a JSON report and requires the
same result.

## Security and triage

Public CI runs only the committed, reviewed corpus. Inputs from [differential fuzzing](differential-fuzzing.md)
stay local until triage, under its [disclosure policy](differential-fuzzing.md#disclosure-policy). A suspected
vulnerability in OpenTLV goes to its private security reporting, and one in asn1c to upstream's
private channel in its `SECURITY.md`, never to a public issue, CI artifact or fixture. Only a
confirmed non-security defect goes to the repository that owns the library. A crash or timeout is a
run failure, not a result.

## Fast CI

The `BER and CER differential against asn1c` job in [Fast](ci.md#fast-gate) sets up both libraries
from exact-key caches, runs the corpus, and requires the deliberate probe in
[`tests/fixtures/ber_cer_mismatch.json`](../tests/fixtures/ber_cer_mismatch.json) to exit with code 3
and reproduce its report. The probe omits the `opentlv.decode` limitation of `ber-boolean-true-01`. It
uploads the reports as the `ber-cer-differential-reports` artifact, even after a failure.

## Limits

- Only the 21 types of `TestLabReference-1` are covered, in the typed-value forms both adapters share.
- The verdicts are X.690 BER and CER for these types and values, not a complete conformance claim
  for either library. REAL, time types, other string types and constraints beyond the schema are not
  covered.
- OpenTLV is exercised through its Lua binding only; Core's `cer_validation.h`, its BER
  indefinite-length writer and other bindings are not compared.
- Only Linux and WSL with GCC were verified, and the Extended suite does not run this comparison.
