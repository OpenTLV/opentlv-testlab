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
`--fixtures FILE` selects a corpus and `--fixture ID` runs only that fixture; repeat it
for more. `--output FILE` also writes every adapter observation as JSON, and
`--report FILE` writes a [Markdown report](#mismatch-reports). Each line of the output
shows a fixture's outcome:

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

The [mismatch report](#mismatch-reports) follows those lines.

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
that compared no `shared` fixture, unless `--fixture` asked for specific ones. Mismatch
has its own code so that no infrastructure failure, including an uncaught Python error,
can look like one.

## Mismatch reports

A mismatch prints a report after the summary. `--report FILE` saves the same details as
Markdown and `--output FILE` as JSON, whatever the outcome. Each mismatch records:

- the fixture id, description, operation, input bytes, schema and expectation;
- the differences, and which library differs from the fixture;
- each library's complete observation, including its error text;
- commands that reproduce only this fixture, and the exit code to expect.

The report also names the Lua runtime, platform, setup receipt, both packages with their
commits and acquisition, the corpus and its SHA-256, and the TestLab commit. It warns
when the checkout had uncommitted changes, because the commit alone may not reproduce
those. It has no timestamps, so two runs with the same inputs give identical reports.

Fixtures from a corpus outside this repository keep their absolute path, so its command
only works where that file exists. Its fixture definition is still in the report. A pull
request's Fast run records the merge commit GitHub created for it, so fetch it first with
`git fetch origin COMMIT` if `git checkout` cannot find it.

The report keeps three kinds of result apart, because only the first asks for a fix:

| Report section | Applies to | What to do |
| --- | --- | --- |
| Mismatches: possible defects | A `shared` fixture that a library did not meet | Investigate; the exit code is 3 |
| Declared by the fixture: not defects | `unsupported` and `inconclusive` fixtures | Nothing; each lists its reason and both library statuses |
| Run failure: no verdict | Anything that stopped the run | Fix or investigate; the exit code is 1 |

A mismatch is a possible defect, not a finding. If only one library differs, read its
observation first. If every library differs, check the fixture first. If the library's
documentation or the capability audit explains the difference, declare the fixture
`unsupported` with that reason; otherwise report it to the library. The deliberate probe
ends at this step on purpose: it shows lossy lua-asn1 typed values, not a lua-asn1 defect.

A run failure also writes both files, with the error and the failing fixture's input
when one is known. This covers a crash, a timeout and a `shared` fixture that an adapter
reports as unsupported. Other adapter output is lost in a crash, so it only records
the error, and a crash or timeout can still be a real library defect.

`scripts/check_report.py FILE` checks a JSON mismatch report: it needs the fields above,
reruns each mismatch's final command with the same receipt, and requires exit code 3 and
an identical result. It does not rerun the checkout or setup steps.

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
adapter path and stays the default corpus.

A corpus can add reproduction metadata, as the BER corpus does:

```json
"reproduction": {
  "command": "python3 scripts/run_differential.py --fixtures differential/fixtures/asn1-ber.json",
  "runtime": "Lua 5.2",
  "packages": {"opentlv": "0.3.0", "lua-asn1": "2.2.1"}
}
```

The versions must equal the committed pins and the runtime must equal the one each
adapter reports, or the run fails. Changing a pin therefore requires verifying the
corpus again. Every fixture in such a corpus also needs a `category` and a `description`,
and the `--output` report retains all of them.

## BER corpus

[`differential/fixtures/asn1-ber.json`](../differential/fixtures/asn1-ber.json) is the
coverage corpus. Its bytes are committed, so nothing about it depends on a seed, a clock
or a library:

```sh
python3 scripts/run_differential.py --fixtures differential/fixtures/asn1-ber.json
```

| Category | Compared as `shared` | Declared `unsupported` or `inconclusive` |
| --- | --- | --- |
| `primitive` | Each shared type, INTEGER octet-size boundaries, BIT STRING unused-bit counts | Negative and large INTEGER, types lua-asn1 lacks, invalid IA5 |
| `constructed` | SEQUENCE, SEQUENCE OF, explicit and implicit tags, false values | Constructed strings, SET and SET OF |
| `nested` | Siblings and every constructed kind up to four levels | Five levels |
| `tag-boundary` | Context tags 0-30 at both ends and around universal numbers | High-tag form, application and private classes |
| `length-boundary` | Lengths 0, 1, 126 and 127, on primitives and on a parent at the limit | Long form, indefinite length, nonminimal length |
| `truncated` | Each missing part, down to the depth bound, as `empty` or `truncated` | Truncated long-form headers and values |
| `malformed` | Trailing bytes, and children that overrun their parent | Reserved length, invalid primitive contents, schema conformance, end-of-contents octets |

Classification rests on the [comparison scope](asn1-comparison.md) and the capability
audit, not on which fixtures happened to agree. Where a reason ends in a name in
parentheses, that name is the audit check that demonstrates it, and a test requires the
check to exist. A disagreement on a declared fixture is retained in the `--output` report
but never decides the run: `length-reserved-ff`, for example, is accepted by lua-asn1 and
rejected by OpenTLV.

## Add a fixture

Add coverage to the BER corpus. The seed corpus only exercises each adapter path, and the
mismatch probe must keep failing. Write the bytes and expectation by hand, independently
of either library, and never copy an expectation from a library's output.

1. Append an entry to the `fixtures` array. This one is a `shared` fixture:

   ```json
   {
     "id": "sequence-boolean-integer",
     "category": "constructed",
     "description": "SEQUENCE of a BOOLEAN and an INTEGER",
     "operation": "decode",
     "wire": "30 06 01 01 ff 02 01 05",
     "schema": {"type": "sequence", "fields": [
       {"name": "flag", "schema": {"type": "boolean"}},
       {"name": "count", "schema": {"type": "integer"}}
     ]},
     "classification": "shared",
     "expected": {"result": "accept", "tree": {
       "identifier": "30", "length": 6, "length_bytes": "06", "children": [
         {"identifier": "01", "length": 1, "length_bytes": "01", "value": "ff"},
         {"identifier": "02", "length": 1, "length_bytes": "01", "value": "05"}
       ]
     }}
   }
   ```

2. Choose its classification before running it, not from which libraries agree:

   | Classification | Use it when | The entry needs |
   | --- | --- | --- |
   | `shared` | The wire fits the [limits below](#fixture-format), both libraries document the operation and a verdict is fair | `expected` |
   | `unsupported` | A library lacks the operation or has a known limitation | `reason`, without `expected` |
   | `inconclusive` | Semantics, canonical form or a validation contract leave no fair verdict | `reason`, without `expected` |

   End a `reason` with the audit check that demonstrates it in parentheses, where one exists,
   and add a check to `tests/asn1_capabilities.lua` if a new limitation needs one.

3. Validate the corpus, then run the new fixture and read both observations:

   ```sh
   python3 -m unittest discover -s tests
   python3 scripts/run_differential.py --fixtures differential/fixtures/asn1-ber.json --fixture sequence-boolean-integer --output build/new.json
   ```

   A run failure at this step usually means the fixture is wrong. For example, a wrong length
   gives `Expected tree does not describe the wire` and exit code 1. The tests also reject a
   duplicate id, a duplicate wire and schema pair, and a cited check that does not exist.

4. Run the whole corpus and update the [category table](#ber-corpus) if the fixture adds
   a new kind of case. Add a changelog entry to the pull request; Fast then runs the fixture
   through both real libraries.

If the libraries differ on a `shared` fixture, follow the [mismatch steps](#mismatch-reports);
do not reclassify the fixture just to pass the run. Only a documented limitation or
missing contract justifies declaring it instead.

A new corpus file also needs `"schema": 1`, a `.license` file like its neighbors and its own
Fast step. Add `reproduction` metadata to require a `category` and `description` on each
fixture and to tie the corpus to the pins.

## Limits

- Only decoding is compared; encoding is not implemented.
- Lua 5.2 on Linux/WSL is the only supported configuration, as for dependency setup.
- A `pass` shows the libraries agree on the bytes in the corpus, not that either is
  correct in general or that lua-asn1 is a validating decoder.
- A report classifies a mismatch for investigation; it cannot decide which library is
  wrong.

## Verification

Fast runs the seed fixtures and the BER corpus, requires the mismatch probe to exit with
code 3 and checks that the probe's report reproduces itself. It uploads all three reports
as the `differential-reports` artifact, even after a failure, and the setup receipts as
`dependency-provenance`. Python tests check the corpus's coverage and metadata. They also
cover eligibility, classification, reports, process failures and receipt checks using
stand-in adapter processes, so they run on Windows without Lua. Only the Fast steps, the
[extended suite](ci.md#extended-suite) and the commands above exercise the Lua adapters and
real libraries.

Local verification on 2026-10-30 used WSL with Lua 5.2.4, a fresh OpenTLV Lua v0.3.0
installation from luarocks.org and the cached lua-asn1 v2.2.1. The seed fixtures gave 22 pass,
7 unsupported and 5 inconclusive, and the mismatch probe gave 2 mismatches and exit
code 3. Real-library runs also confirmed that inherited Lua settings are ignored,
that neither adapter's path can load the other library, and that two runs produce
identical reports.

Local verification of the BER corpus on 2026-10-30 used the same configuration and
freshly installed OpenTLV Lua v0.3.0. It gave 102 pass, 0 mismatch, 43 unsupported and
24 inconclusive with exit code 0, and two runs produced identical reports.

Local verification of the reports on 2026-10-30 used the same configuration. The mismatch
probe's report gave exit code 3, named lua-asn1 for both mismatches, and `check_report.py`
reproduced both with identical results. Two BER runs produced byte-identical JSON and
Markdown reports. A failure injected at adapter startup wrote a failure report. A crash at
a specific fixture was exercised only with stand-in processes. A checkout shared with
Windows shows as modified under WSL because of line endings, so those local reports carry
the uncommitted-changes warning.

The [Add a fixture](#add-a-fixture) example was run on 2026-10-30 from a clean clone. It
passed alone, took the BER corpus to 103 pass, and a wrong length gave exit code 1. It was
not committed, so the corpus counts above stand.

Hosted [Fast and Extended](ci.md#verification) passed on the same corpora on 2026-10-30.

[source]: https://github.com/OpenTLV/opentlv-lua/blob/v0.3.0/docs/api.md#source-preservation
