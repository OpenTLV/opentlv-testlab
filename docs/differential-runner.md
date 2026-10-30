<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 Marek Cingel -->

# Lua differential runner

`scripts/run_differential.py` decodes the same fixture bytes with OpenTLV Lua and
`kunkku/lua-asn1`, then classifies each fixture as `pass`, `mismatch`, `unsupported`
or `inconclusive`. The [comparison scope](asn1-comparison.md) defines what those
libraries can fairly be compared on; this page describes how the runner applies it.

## Run it

Complete the [dependency setup](dependencies.md), then run from this repository:

```sh
python3 scripts/setup_lua.py --lua lua5.2
python3 scripts/run_differential.py
```

The runner uses the newest complete passed setup in `build/dependency-runs`.
`--runs-dir DIR` searches elsewhere and `--provenance FILE` selects one receipt.
`--fixtures FILE` selects a corpus, and `--output FILE` also writes every adapter
observation as JSON. Each line of the output shows a fixture's outcome:

```text
pass         nested-sequence
unsupported  high-tag: lua-asn1 rejects high-tag-number form (high-tag)
22 pass, 0 mismatch, 7 unsupported, 5 inconclusive
```

To see a real mismatch, run the deliberate probe. It claims two lossy encodings
as shared, so the libraries must disagree. It exits with code 3:

```sh
python3 scripts/run_differential.py --fixtures tests/fixtures/differential_mismatch.json
```

```text
mismatch     boolean-noncanonical-as-shared
             lua-asn1 root.value: expected '01', observed 'ff'
```

## Outcomes and exit codes

| Outcome | Meaning |
| --- | --- |
| `pass` | A `shared` fixture, and both libraries met its explicit expectation |
| `mismatch` | A `shared` fixture, and a library differed in bytes, tree or accept/reject result |
| `unsupported` | Declared by the fixture: a missing operation or known limitation; never a pass |
| `inconclusive` | Declared by the fixture: no fair verdict is possible; never a pass |

A mismatch names the library that differs from the fixture. That is not a finding
that the library is wrong: lossy typed results and fixture errors look the same here.
Both libraries still run on declared fixtures, so their observations are retained
and a crash on one still fails the run.

| Exit code | Meaning |
| --- | --- |
| 0 | Every `shared` fixture passed; `unsupported` and `inconclusive` may also be present |
| 1 | Run failure; no verdict can be trusted |
| 2 | Invalid command-line usage |
| 3 | At least one mismatch |

A run failure is never reported as a comparison outcome. It covers an invalid
corpus, an unusable receipt, a crash, a timeout, a resource limit, a malformed
adapter response, a `shared` fixture an adapter reports as unsupported, and a corpus
that compared no `shared` fixture. Mismatch has its own code so that no
infrastructure failure, including an uncaught Python error, can look like one.

## How a run works

Python validates the corpus and receipt, spawns the adapters and compares their
results; the libraries and their adapters run only under Lua.

1. **Verify the setup.** The receipt must be a complete passed setup using the
   committed pins. The Lua executable digest, the cached external library and the
   installed OpenTLV file inventory and digests are all rechecked. A changed
   file or a shadow module fails the run.
2. **Run one adapter per process.** [`adapter_host.lua`](../differential/lua/adapter_host.lua)
   loads a single adapter. Inherited `LUA_*` and `LUAROCKS_*` variables are removed,
   and each process gets a search path holding only its own library. Each process
   reports the module it loaded, which must be the one from the receipt.
3. **Send the same bytes.** Both adapters get the fixture id and wire bytes. Only
   the lua-asn1 adapter gets the schema. Neither gets the classification or
   expectation, so neither can adapt to the expected answer.
4. **Compare with the fixture.** Each result is compared with the fixture's
   expectation, which also shows how two libraries differ from each other.

## Normalized representation

```json
{"identifier": "30", "length": 3, "length_bytes": "03",
 "children": [{"identifier": "04", "length": 1, "length_bytes": "01", "value": "41"}]}
```

A node holds `value` when primitive and `children` when constructed. Bytes are
lowercase hex. A result also has `status` (`accepted`, `rejected` or `unsupported`)
and, where known, `consumed` and `detail`.

The two adapters observe different things, and the result says so:

- **OpenTLV** reports what it read from the wire, without a schema. It descends
  into every element with the constructed bit set. Its element tables have no raw
  length field, so the length bytes come from the [Source API][source]. It applies
  the complete-root policy itself: empty input and bytes after the first root are
  rejected. Only `TRUNCATED`, `INVALID_LENGTH` and `INVALID_TAG` count as malformed
  input; any other error is a run failure.
- **lua-asn1** returns typed values, so its tree is **projected** through the
  fixture schema. It has no `length_bytes`, because the API cannot observe them,
  and that field is compared only when reported. The result marks `projected: true`
  and retains the `typed` value. Projection never calls the library's encoder.

Errors are compared only as accepted or rejected. Error text is retained in `detail`
but never compared, because lua-asn1 reports some malformed input through incidental
type errors. Its failures therefore count as agreement only where a fixture declares
a framing rejection; anywhere else, a rejection is a mismatch.

## Fixture format

A corpus is a JSON object with `"schema": 1` and a `fixtures` array:

```json
{
  "id": "octets-binary",
  "operation": "decode",
  "wire": "04 03 00 ff 41",
  "schema": {"type": "octet_string"},
  "classification": "shared",
  "expected": {
    "result": "accept",
    "tree": {"identifier": "04", "length": 3, "length_bytes": "03", "value": "00ff41"}
  }
}
```

An expected rejection is `{"result": "reject", "framing": "truncated"}`; `framing`
is `empty`, `truncated` or `trailing`. An `unsupported` or `inconclusive` fixture
has a required `reason`, citing its capability probe where one exists, and no `expected`.

A `shared` schema uses `boolean`, `integer`, `bit_string`, `octet_string`, `ia5string`,
`sequence` (`fields`: `{"name", "schema"}` objects), `sequence_of` (`item`) or `explicit`
(`tag`, `inner`). All but `explicit` accept an optional implicit context `tag`.

The runner checks each `shared` fixture with a small independent parser. It must have one
root, short-form lengths, tags 0-30, universal or context class and at most four
levels, and its expected tree or declared framing error must describe the wire.
No library output can define an expectation. Wire size is limited to 4096 bytes.
The parser does not judge ASN.1 semantics, so authors must still give `shared`
fixtures canonical primitive values. The mismatch probe breaks that rule on purpose.

[`differential/fixtures/seed.json`](../differential/fixtures/seed.json) exercises each
adapter path. It is not the coverage corpus planned in
[issue #5](https://github.com/OpenTLV/opentlv-testlab/issues/5).

## Limits

- Only decoding is compared; encoding is not implemented.
- Lua 5.2 on Linux/WSL is the only supported configuration, as for dependency setup.
- A `pass` shows the libraries agree on the bytes in the corpus, not that either is
  correct in general or that lua-asn1 is a validating decoder.
- Reproduction commands and CI report artifacts are planned in
  [issue #6](https://github.com/OpenTLV/opentlv-testlab/issues/6). `--output` retains
  observations, but is not that report.

## Verification

Fast runs the seed fixtures and requires the mismatch probe to exit with code 3.
Python tests cover eligibility, classification, process failures and receipt checks
using stand-in adapter processes, so they also run on Windows without Lua. Only
the Fast steps and the commands above exercise the Lua adapters and real libraries.

Local verification on 2026-10-30 used WSL with Lua 5.2.4, a fresh OpenTLV Lua v0.3.0
installation and the cached lua-asn1 v2.2.1. The seed fixtures gave 22 pass,
7 unsupported and 5 inconclusive, and the mismatch probe gave 2 mismatches and exit
code 3. Real-library runs also confirmed that inherited Lua settings are ignored,
that neither adapter's path can load the other library, and that two runs produce
identical reports. Hosted Fast remains to be verified on the PR.

[source]: https://github.com/OpenTLV/opentlv-lua/blob/v0.3.0/docs/api.md#source-preservation
