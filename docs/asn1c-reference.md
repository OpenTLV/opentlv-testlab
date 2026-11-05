<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 Marek Cingel -->

# asn1c reference adapter

TestLab can build [`vlm/asn1c`](https://github.com/vlm/asn1c), generate C code from a
small TestLab ASN.1 schema and query it through one adapter process. The adapter is an
independent C reference for comparisons with OpenTLV: the
[DER differential](der-differential.md) ([#21](https://github.com/OpenTLV/opentlv-testlab/issues/21))
and the [BER and CER differential](ber-cer-differential.md)
([#22](https://github.com/OpenTLV/opentlv-testlab/issues/22)) use it. This page records which asn1c
was selected, how it is built, what the adapter returns and what asn1c can and cannot decide.

asn1c is a TestLab test tool. It is not a runtime, build or test dependency of OpenTLV Core
or any binding, and it adds no Core build option. Generated code and the asn1c runtime are
compiled only into the adapter, under `build/`. Nothing in this setup acquires or links
OpenTLV; a comparison that does, such as the DER differential, acquires OpenTLV as the
[dependency policy](dependencies.md#fresh-opentlv-package-from-luarocks) requires.

## Why a second reference

lua-asn1 can only compare short definite lengths, low tag numbers, two tag classes and a
few types; the [comparison matrix](asn1-comparison.md#concrete-comparison-matrix) declares
the rest `unsupported`. asn1c decodes what those fixtures need: long and indefinite lengths,
high tag numbers, application and private classes, constructed strings, arbitrary-precision
and negative INTEGER, NULL, OBJECT IDENTIFIER, SET, SET OF and CHOICE. It also has a DER
encoder, which gives a canonical re-encoding of each decoded value.

The Rust `der-parser` reference from [#19](https://github.com/OpenTLV/opentlv-testlab/issues/19)
is not integrated yet. When it is, it will be a schema-less parser in another language, while
asn1c is schema-driven C code with an encoder, so the two references stay distinct. The
adapter reuses the TestLab conventions instead of a new framework: commit-pinned sources,
exact-key caches, setup receipts, hand-written expectations and run failures that never pass
as results.

## Identity and pin

| Property | Selected value |
| --- | --- |
| Upstream | [`vlm/asn1c`](https://github.com/vlm/asn1c), the original project by Lev Walkin |
| Release | `0.9.29`, tag `v0.9.29`, released 2026-06-22 |
| Immutable source | `c7bd85d1574a994e9cb439a6b34ecbbc8106fefe` |
| Acquisition | Release asset `asn1c-0.9.29.tar.gz`, 1899204 bytes |
| Integrity | SHA-256 `a8b7b60475357285ac7250f0f3452d0c7555abffa50e1226a0a671df715cc9ff`, equal to the digest GitHub shows for the asset |
| License | BSD-2-Clause; Copyright (c) 2003-2017 Lev Walkin and contributors; `LICENSE` SHA-256 pinned |
| Runtime version | `ASN1C_ENVIRONMENT_VERSION` 929, reported by the adapter |
| Verification date | 2026-11-04 |

[`dependencies/asn1c.json`](../dependencies/asn1c.json) holds these values. Setup downloads the
asset only from its release URL and rejects any other size or digest before writing it.

The release archive was compared with the tagged commit on 2026-11-04. All 929 files they share
are byte-identical. The archive adds only Autotools output (`configure`, `aclocal.m4`,
`config.h.in`, `config/*`, Libtool macros), `Makefile.in` files and one test data file. It omits
13 repository files, among them the parser grammar sources, `SECURITY.md` and CI settings, but
ships the parser generated from them, which is also committed at the tag. The archive holds only
regular files and directories.

### Dependencies

The release archive builds with a C99 compiler and GNU Make only. It ships `configure` and the
generated parser, so the Autotools, Bison and Flex listed in upstream `REQUIREMENTS.md` are not
needed. The built `asn1c` links only libc. Generated code needs a C90 compiler and libc. No
package manager, network service or other library is involved.

### Alternatives considered

| Candidate | Decision |
| --- | --- |
| Ubuntu 24.04 package `asn1c 0.9.28+dfsg-5` | Rejected: the 2017 release lacks the 0.9.29 decoder fixes, including the BER CHOICE infinite loop |
| `vlm/asn1c` `master` | Rejected as a pin: not a release. Its fixes after the tag are a compiler check (CVE-2025-32893, `asn1p_expr_compare`) and open-type decoders; the compiler only reads the trusted TestLab schema, which has no information object sets or open types |
| [`mouse07410/asn1c`](https://github.com/mouse07410/asn1c) v1.5.3 | Deferred: an actively maintained fork, but a different implementation lineage whose tag ships no generated parser, so it needs Bison, Flex and Autotools. Evaluate it as a separate reference if asn1c's limits matter |

Upstream `SECURITY.md` supports only `master` and 0.9.28 for security fixes. The pin is a test
oracle run on committed probes, not a production decoder, so a reproducible release outweighs
fixes outside the schema's reach. Revisit the pin when upstream tags a new release.

## Set up the reference

The supported setup is Linux or WSL with Python 3.10+, a C compiler and GNU Make. Ubuntu's
`build-essential` is enough. It needs no Lua, and the [Lua setup](dependencies.md) does not need it.

```sh
python3 scripts/setup_asn1c.py
```

`--cc` and `--make` select other tools. Setup:

1. downloads and verifies the release archive, extracts it after rejecting any unsafe path, link
   or special file, and runs `./configure`, `make` and `make install` into a temporary prefix;
2. publishes the verified source archive, `LICENSE` and installed prefix as one cache entry;
3. generates the [schema](#schema-and-generated-code) twice and requires identical output;
4. compiles the generated code and the [adapter](#adapter-contract) into a new run directory;
5. runs the [capability audit](#capability-audit) and fails on any changed observation.

The cache defaults to `build/dependency-cache/<key>`, beside the lua-asn1 entry. The key is a
SHA-256 of the full pin, the compiler's version, target and executable digest, the Make version
and digest, the platform and `INSTALL_SCHEMA`. Print it with:

```sh
python3 scripts/setup_asn1c.py --print-cache-key
```

A warm run downloads and builds nothing. It rechecks the archive, the license and every
installed file against the digests recorded when the entry was built, and rejects symlinks,
missing and extra files. The compiler and runtime are native build output, so those digests
come from the build, not from upstream; they detect corruption, not a different build. A
corrupt entry fails instead of being rebuilt; remove that entry or choose a new `--cache-dir`.
`--offline` requires an existing entry and never downloads:

```sh
python3 scripts/setup_asn1c.py --offline
```

Runs default to `build/asn1c-runs/<uuid>`; set `--runs-dir` to change it. Each run keeps:

- `provenance.json`: status, timestamps, configuration, the cache key and hit or miss, the pin,
  the `asn1c -version` line, the schema identity and digests of every generated file, compiler
  flags, the adapter source and binary digests and the audit totals;
- `generated/`, `build/` and the `asn1c-adapter` binary;
- `asn1c-build.log` on a cache miss, `generate.log`, `build.log` and `capabilities.log`;
- `failure.json` when setup fails after creating the run directory.

Only `status: "passed"` is a usable setup. Nothing removes old runs. Local verification on
2026-11-04 took 34 seconds for a cold setup and under 2 seconds for a warm one.

### Sanitized build

For [differential fuzzing](differential-fuzzing.md), `--sanitize` compiles the generated code,
the asn1c runtime and the adapter with AddressSanitizer and UndefinedBehaviorSanitizer, and with
`-fno-sanitize-recover=all`, so any report stops the adapter:

```sh
python3 scripts/setup_asn1c.py --sanitize
```

It uses the same cache entry, since only the adapter is compiled differently, and runs the same
audit. Its runs default to `build/asn1c-sanitized-runs`, so the corpus runners, which take the
newest receipt from `build/asn1c-runs`, keep the plain adapter. The receipt records
`"sanitizers": ["address", "undefined"]` and the flags.

UBSan's `nonnull-attribute` check is off. asn1c 0.9.29's `dynamic_encoder_cb()` in
`asn_application.c` passes a null pointer to `memcpy()` with a length of zero whenever it
re-encodes an empty string read in constructed form, such as `24 80 04 00 00 00`. That is undefined
behavior, but it accesses no memory, so it is not a vulnerability and is not reported upstream.
Fuzzing found it ([#23](https://github.com/OpenTLV/opentlv-testlab/issues/23)).

## Schema and generated code

[`differential/asn1c/TestLabReference-1.asn1`](../differential/asn1c/TestLabReference-1.asn1)
is version 1 of the schema: 21 types, each a target for one behavior the probes characterize.
A definition never changes in place. A new behavior that needs a changed type gets a new file and
module, `TestLabReference-2`, and the probes move to it in the same change. Setup requires the
module name to equal the file name, and the probes name the module they were verified against.
Type names avoid asn1c's runtime file names, which differ only in case, such as `BOOLEAN.c`.

asn1c runs with `-fwide-types -fcompound-names -fincludes-quoted -no-gen-OER -no-gen-PER
-no-gen-example`, so INTEGER stays arbitrary-precision and only the BER, DER and XER codecs are
generated. Setup generates the schema twice, from identical relative paths, and fails unless
every file is byte-identical. Generated comments name the absolute schema and runtime paths, so
output differs between checkouts but not between runs from the same one.

The source list and the `-DASN_DISABLE_OER_SUPPORT -DASN_DISABLE_PER_SUPPORT` flags come from
asn1c's own `Makefile.am.libasncodec`, and setup requires both. Every generated module must name
`asn1c-0.9.29` and this module, and the generated types must equal the schema's. Generated code
is compiled with `-std=gnu99 -O2`, the adapter additionally with `-Wall -Wextra -Werror`. The
binary itself is not claimed to be reproducible; its digest is recorded and rechecked.

## Adapter contract

[`asn1c_adapter.c`](../differential/asn1c/asn1c_adapter.c) is the only code that includes
asn1c headers. It reads one request per line on standard input:

```text
ID TYPE DECODE ENCODE HEX
```

`TYPE` is a schema type, `DECODE` is `ber`, `der` or `cer`, `ENCODE` is one of those or `none`,
and `HEX` is lowercase hex of at most 4096 bytes, or `-` for empty input. The adapter writes JSON
lines: an identity first, then one result per request.

```json
{"adapter": "asn1c", "version": "0.9.29", "environment_version": 929,
 "schema": "TestLabReference-1", "schema_sha256": "...", "types": ["Flag", "..."]}
{"id": "ber-sequence", "type": "Pair",
 "decode": {"syntax": "ber", "status": "accepted", "code": "RC_OK", "consumed": 8,
            "value": {"kind": "sequence", "fields": [
              {"name": "flag", "value": {"kind": "boolean", "value": true}},
              {"name": "count", "value": {"kind": "integer", "value": "5"}}]}},
 "encode": {"syntax": "der", "status": "encoded", "wire": "30060101ff020105"}}
```

The identity must equal the pin, schema and type list exactly. A request the adapter cannot
represent exits with code 2, so it is a run failure, never a result.

### Decode results

`decode.status` is `accepted`, `rejected` or `unsupported`, and `code` is asn1c's own
`asn_dec_rval_t` code. The adapter applies two policies of its own: the input holds exactly one
complete value, and a decoded value must pass asn1c's constraint check.

| `error` | asn1c code | Meaning |
| --- | --- | --- |
| `empty` | `RC_WMORE` | No input bytes |
| `truncated` | `RC_WMORE` | asn1c needs more bytes |
| `malformed` | `RC_FAIL` | asn1c rejected the bytes; it reports no finer category |
| `trailing` | `RC_OK` | A complete value was decoded before the end of the input |
| `constraint` | `RC_OK` | Decoded, but `asn_check_constraints()` failed; its text is in `detail` |

`consumed` is what asn1c reports; on a rejection it is diagnostic. `unsupported` means
`asn_decode()` failed with `ENOENT` because asn1c has no decoder for that syntax.

### Typed values

`value` is the typed value asn1c decoded, never the input bytes. Constructed values nest:

| `kind` | Fields |
| --- | --- |
| `boolean` | `value`: `true` or `false` |
| `integer` | `value`: signed decimal string of any size, or `null` without contents octets |
| `bit_string` | `unused_bits` and `value` in hex, as asn1c stores them |
| `octet_string`, `ia5string` | `value` in hex |
| `null` | none |
| `object_identifier` | `value`: dotted arcs, or `null` for malformed arcs; an arc above 2^32-1 is reduced modulo 2^32 (`ber-oid-arc-above-32-bits`) |
| `sequence`, `set` | `fields`: present components in definition order, `{"name", "value"}` |
| `sequence_of`, `set_of` | `items`: values in decoded order |
| `choice` | `alternative` and `value` |

An absent OPTIONAL component is omitted, and an absent DEFAULT component has its default value,
as asn1c fills it in. The value cannot show length forms, segment boundaries, nonminimal octets
or cleared padding bits. Compare such properties with the DER re-encoding or with an adapter that
reads the wire, not with this value.

### Encode results

`encode` is present when a value was accepted and `ENCODE` is not `none`. `status` is `encoded`
with `wire` in hex, `unsupported` when `asn_encode()` fails with `ENOENT`, or `failed` with the
failing type in `detail`. asn1c's BER encoder emits DER. The 0.9.29 header promises a NULL buffer
from `asn_encode_to_new_buffer()` on failure, but the function returns its scratch buffer; the
adapter checks the encoded size instead.

## Capability audit

[`differential/asn1c/capabilities.json`](../differential/asn1c/capabilities.json) holds 80 probes: 50 supported, 6 unsupported and 24 not comparable.
Each probe names its area, classification, the X.690 or X.680 rule it checks, the request and
the exact expected result, without `syntax` and `detail`. Expectations were written from the
rules, then confirmed against the pinned build; classification depends on the rule, not on
whether asn1c happened to match.

| Classification | Meaning for later comparisons |
| --- | --- |
| `supported` | asn1c behaves as the rule requires; it can be an oracle for this case |
| `unsupported` | asn1c has no such operation or rejects a valid form; a reference limitation, never an OpenTLV defect |
| `not-comparable` | asn1c accepts or emits what the rule forbids, so it cannot judge that rule |

Setup runs the audit and fails on any difference. To rerun it on the newest passed setup without
building, select probes and keep every observation:

```sh
python3 scripts/check_asn1c.py
python3 scripts/check_asn1c.py --probe cer-decode --output build/asn1c-probe.json
```

`--runs-dir` and `--provenance` select the setup. The check fails, rather than reporting stale
results, if the schema, adapter source, generated files, adapter binary or cache changed after
setup. A changed observation after a pin change means revisiting the classification and this
page, not only editing the expectation.

### BER decoding

| Probe | Classification | Finding |
| --- | --- | --- |
| `ber-boolean-true` | supported | `01 01 ff` decodes as TRUE |
| `ber-integer-sign-padding`, `ber-integer-negative`, `ber-integer-large-negative` | supported | Two's complement of any size, including a 9-octet negative value |
| `ber-long-length-128` | supported | Long-form length |
| `ber-indefinite-constructed-octets`, `ber-indefinite-nested` | supported | Indefinite lengths, constructed strings and nesting |
| `ber-high-tag-31`, `ber-high-tag-200` | supported | High-tag-number form with one and two subsequent octets |
| `ber-application-class`, `ber-private-class`, `ber-explicit-context`, `ber-implicit-context-30` | supported | Every tag class, explicit and implicit tags |
| `ber-null`, `ber-object-identifier`, `ber-bit-string`, `ber-bit-string-empty` | supported | NULL, OBJECT IDENTIFIER and BIT STRING |
| `ber-bit-string-padding` | supported | Set unused bits are cleared in the value; BER gives them no meaning |
| `ber-sequence`, `ber-optional-absent`, `ber-optional-present`, `ber-default-absent`, `ber-sequence-of-empty` | supported | SEQUENCE, OPTIONAL, DEFAULT and SEQUENCE OF |
| `ber-choice-number`, `ber-choice-text` | supported | CHOICE |
| `ber-empty-input`, `ber-truncated-value`, `ber-truncated-long-length`, `ber-truncated-indefinite`, `ber-truncated-segment` | supported | Empty and truncated input, including a missing end-of-contents |
| `ber-trailing-byte`, `ber-trailing-after-sequence` | supported | Bytes after one complete value |
| `ber-wrong-tag`, `ber-reserved-length`, `ber-null-with-contents`, `ber-bit-string-unused-8`, `ber-bit-string-empty-unused`, `ber-constructed-integer`, `ber-set-missing-component`, `ber-choice-no-alternative` | supported | Rejected as `malformed` |
| `ber-ia5-out-of-range`, `ber-oid-empty` | supported | Accepted by the decoder, rejected by the constraint check |
| `ber-integer-nonminimal` | not comparable | Accepts redundant leading octets |
| `ber-integer-empty` | not comparable | Accepts an INTEGER without contents, and re-encodes it |
| `ber-boolean-empty`, `ber-boolean-two-octets` | not comparable | Accepts zero or two BOOLEAN contents octets as FALSE |
| `ber-bit-string-no-initial-octet` | not comparable | Accepts a BIT STRING without its initial octet |
| `ber-primitive-indefinite` | not comparable | Reads `04 80` as a complete empty value, so the error surfaces as trailing input |
| `ber-high-tag-leading-zero`, `ber-high-tag-form-for-low-number` | not comparable | Accepts nonminimal tag numbers |
| `ber-oid-leading-80` | not comparable | Accepts a padded subidentifier, and re-encodes it |
| `ber-oid-incomplete-subidentifier` | not comparable | Accepts an unterminated last subidentifier, reports no arcs and re-encodes it |
| `ber-bit-string-segment-unused` | not comparable | Ignores the unused bits of a segment other than the last and keeps them as data |
| `ber-constructed-segment-own-tag` | not comparable | Accepts segments of a constructed IA5String tagged IA5String |
| `ber-constructed-ia5-octet-segments`, `ber-constructed-implicit-octet-segments` | unsupported | Rejects the OCTET STRING segments that X.690 8.23.5 and 8.7.3.2 prescribe for a character string or an implicitly tagged string, because it requires each segment to repeat the type's own tag |
| `ber-explicit-indefinite-primitive` | unsupported | Rejects an indefinite length on an explicit tag around INTEGER; the definite form decodes |
| `ber-oid-arc-above-32-bits` | not comparable | Reduces an arc above 2^32-1 modulo 2^32 without an error: `1.2.4294967296` reads as `1.2.0`, while the DER encoder emits the original octets |
| `ber-bit-string-segment-no-initial-octet` | not comparable | Accepts and ignores a BIT STRING segment without its initial octet |
| `ber-bit-string-constructed-empty` | unsupported | Rejects a constructed BIT STRING with no segments, the empty bit string, in its constraint check |

The [BER and CER differential](ber-cer-differential.md#bugs) found the six probes from
`ber-oid-incomplete-subidentifier` to `ber-explicit-indefinite-primitive`, and
[differential fuzzing](differential-fuzzing.md#results) found the last three. The others were
characterized for the DER differential.

### DER decoding

asn1c decodes DER with its BER decoder. Apart from the baseline `der-decode-canonical`, which is
supported, it checks no DER restriction, so it cannot decide whether an input is valid DER:

| Probe | DER rule asn1c does not check |
| --- | --- |
| `der-decode-long-form-length`, `der-decode-indefinite` | Minimal definite lengths |
| `der-decode-constructed-string` | Primitive strings |
| `der-decode-boolean-nonzero` | TRUE is `ff` |
| `der-decode-integer-nonminimal` | Minimal INTEGER |
| `der-decode-bit-string-padding` | Zero unused bits; asn1c clears them silently |
| `der-decode-default-present` | DEFAULT values omitted |
| `der-decode-set-of-unsorted`, `der-decode-set-unsorted` | SET OF and SET order |

### DER encoding

The DER encoder canonicalizes what it decoded, so a canonical re-encoding that differs from the
input is evidence that the input was not DER. All of these are supported: `der-encode-boolean-true`,
`der-encode-minimal-length`, `der-encode-primitive-string`, `der-encode-set-order`,
`der-encode-set-of-order`, `der-encode-default-omitted` and `der-encode-ber-syntax`. Two decoded
values re-encode noncanonically, so their DER output is no oracle either: the empty INTEGER of
`ber-integer-empty` and the padded subidentifier of `ber-oid-leading-80`.

### CER

| Probe | Classification | Finding |
| --- | --- | --- |
| `cer-decode` | unsupported | `asn_decode()` has no CER case and fails with `ENOENT`, although `asn_application.h` says CER decoding is supported |
| `cer-encode` | unsupported | `asn_encode()` fails with `ENOENT` for CER on every type |
| `cer-form-as-ber` | not comparable | The BER decoder accepts CER forms, but every non-CER form too |

asn1c is therefore no CER reference in either direction. The
[BER and CER differential](ber-cer-differential.md) judges CER against an independent X.690
reference and declares these limitations for every CER fixture.

## Security and triage

Public CI runs only the committed, reviewed probes, with input limited to 4096 bytes, a
60-second adapter timeout and asn1c's default 30000-byte stack bound. Exploratory or fuzzed
inputs stay local and private until triage, as the [disclosure policy](differential-fuzzing.md#disclosure-policy)
of the fuzzer requires. A suspected vulnerability in generated code or the asn1c runtime goes to
upstream's private reporting channel in its `SECURITY.md`, never to a public issue, CI artifact or
fixture. A crash or timeout is a run failure, not a probe result.

## Fast CI

The `asn1c reference adapter` job in [Fast](ci.md#fast-gate) restores only the exact cache key,
runs setup with the audit, checks the cache offline, reruns the audit with `check_asn1c.py` and
uploads receipts, logs and the audit report as the `asn1c-reference` artifact. The Lua job does
not depend on it.

## Limits

- Only the 21 schema types are covered; a new type needs a new schema version, probes and an
  adapter representation.
- Typed values cannot show encoding details; see [typed values](#typed-values).
- Only Linux and WSL with GCC were verified; the Extended suite does not run asn1c yet.
- The probes characterize asn1c only. The [DER differential](der-differential.md) and the
  [BER and CER differential](ber-cer-differential.md) compare it with OpenTLV and cite the probes
  that limit their verdicts.

## Verification

Local verification on 2026-11-04 used WSL on Ubuntu 24.04 x86-64 with GCC 13.3.0 and GNU Make
4.3, from a clean clone with these changes applied. A cold setup built asn1c 0.9.29 from the
verified archive, generated identical sources twice, compiled the adapter with no warnings and
passed all 71 probes of #20; the six BER probes added for #22 passed in a new cold setup. A warm setup hit the cache without downloading or building, `--offline`
hit it again, an empty cache with `--offline` failed with an offline cache miss, and
`check_asn1c.py` reran selected probes on the built adapter. The Python tests in
`tests/test_asn1c.py` cover the pin, schema, probes, cache, generation, adapter protocol and
receipts with stand-ins, so they also run on Windows.
