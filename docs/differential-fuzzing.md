<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 Marek Cingel -->

# Differential fuzzing of BER, DER and CER

`scripts/run_fuzz.py` generates values and encodings, feeds the same input to OpenTLV Lua v0.3.0
and the [asn1c reference adapter](asn1c-reference.md), and judges both against the independent
X.690 reference in [`scripts/x690.py`](../scripts/x690.py). It looks for semantic differences
beyond crashes and sanitizer reports. This is [#23](https://github.com/OpenTLV/opentlv-testlab/issues/23),
migrated from [Core #296](https://github.com/OpenTLV/opentlv/issues/296). It builds on the asn1c
adapter of #20 and on the comparison rules of the [DER differential](der-differential.md) (#21)
and the [BER and CER differential](ber-cer-differential.md) (#22).

The fuzzer is exploratory. It is not a publication gate: neither Fast nor Extended runs it, and
its inputs and findings stay local until triage (see the [disclosure policy](#disclosure-policy)).
It adds nothing to OpenTLV Core or any binding, and no Core build option.

## Strategies

Every case derives from a seed, a strategy and an index, through a SplitMix64 generator that
gives the same case on every Python version and platform. Any case can be rerun alone.

| Strategy | Each case |
| --- | --- |
| `value` | Generates a typed value of a random schema type. OpenTLV encodes it as BER, DER and CER. The reference writes its DER and CER encodings and one random BER encoding, and both libraries decode all three with each encoding: 12 cases per value |
| `mutation` | Takes a committed DER, BER or CER fixture or a generated encoding, and mutates it one to three times. A seed that is valid BER is usually edited as a tree: one element's contents, tag, length form or children change and every length around it is recomputed, so most inputs keep valid framing. Other seeds get byte edits: bit flips, interesting octets, insertions, deletions, truncation, splices and header edits. The bytes are sometimes read with another encoding or type |

The random BER encodings use what BER allows and DER forbids: long and padded lengths, indefinite
lengths, constructed and nested string segments, TRUE other than `ff`, set padding bits, an encoded
DEFAULT and any SET or SET OF order. The reference must read each back as the value, or the run
fails.

## Checks

Each check compares one library with the X.690 reference, never with the other library.

| Check | Applies to | Passes when |
| --- | --- | --- |
| `opentlv.decode` | Every decoded input | OpenTLV accepts what X.690 accepts, with the same logical value, and rejects what it rejects |
| `opentlv.round-trip` | Inputs both accept | OpenTLV's re-encoding is the input for DER and CER, and is read as the value for BER |
| `opentlv.encode` | Generated values | OpenTLV's DER and CER are the canonical bytes; its BER is read as the value |
| `asn1c.decode` | Every decoded input | As for OpenTLV. For DER, asn1c's verdict also requires its canonical re-encoding, as in the [DER differential](der-differential.md#checks) |
| `asn1c.round-trip` | BER and CER inputs both accept | asn1c's DER re-encoding is the DER of the value |

Values compare as logical values: SET OF items in any order, and BER padding bits read as zero.
asn1c re-encodes as DER and writes no CER, so its CER encoding is not checked.

## Feature intersection

The comparison covers what both libraries implement for the 21 types of
[`TestLabReference-1`](../differential/asn1c/TestLabReference-1.asn1), in the typed values both
adapters share.

| Area | Covered |
| --- | --- |
| Encodings | BER, DER and CER decoding by both libraries; BER, DER and CER encoding by OpenTLV; DER re-encoding by asn1c |
| Types | BOOLEAN, INTEGER, BIT STRING, OCTET STRING, IA5String, NULL, OBJECT IDENTIFIER, SEQUENCE with OPTIONAL and DEFAULT components, SEQUENCE OF, SET, SET OF, CHOICE, an explicit tag, implicit context, application and private tags, and tags 30, 31 and 200 |
| Generated values | INTEGER within int64; OBJECT IDENTIFIER with up to 9 arcs, each at most 2^32-1; strings of up to 2005 octets, around the 127, 128, 255, 256 and 1000-octet boundaries; up to 20 items |
| Input size | At most 4096 octets, the asn1c adapter's limit |
| Mutated inputs | Anything within that size, including values outside the generated ranges |

Generated values stay inside both libraries' representations. Mutated inputs do not, and the
explanations below classify what falls outside.

OpenTLV Lua implements only part of X.690. Its Formats check framing, and its codecs apply the
canonical contents rules to every encoding, but it binds no schema layer and no `cer_validation.h`.
The fuzzer therefore asks the reference a second question with an X.690 `Rules` profile that
leaves out exactly the missing rule groups:

| Encoding | Full X.690 profile | OpenTLV Lua profile |
| --- | --- | --- |
| BER | Framing | Framing and canonical contents (11.1, 11.2.1) |
| CER | Framing (9.1), contents, segmentation (9.2), SET, SET OF and DEFAULT rules | Framing (9.1) and contents |
| DER | Framing (10.1), contents, primitive strings (10.2), SET, SET OF and DEFAULT rules | Framing (10.1) and contents |

An OpenTLV verdict that differs from the full profile but matches its own profile is a
limitation, never a defect. Any other difference is a finding, as is a difference from both.

## Outcomes

| Outcome | Meaning | Finding |
| --- | --- | --- |
| `pass` | The check met the X.690 expectation | No |
| `semantic-mismatch` | The library disagrees on whether the input is valid BER, or on its value | Yes |
| `canonical-mismatch` | A decoder accepts as DER or CER what is only valid BER, or an encoder writes valid BER that is not the canonical encoding | Yes |
| `crash` | The adapter process died, hung or raised an unexpected error | Yes |
| `sanitizer` | AddressSanitizer, LeakSanitizer or UndefinedBehaviorSanitizer reported an error in the asn1c adapter | Yes |
| `limitation` | A documented limitation of the library explains the difference | No |
| `not-comparable` | A capability probe records that the library cannot decide this rule | No |
| `inconclusive` | Both reject but with another normalized error, or asn1c could not re-encode | No |

Error categories are not compared as findings. An input with several defects can be rejected for
any of them, and decoders meet them in different orders.

### Explanations

Only these explain a difference. Each cites a documented limitation or an
[asn1c capability probe](asn1c-reference.md#capability-audit), and the tests require every cited
probe to exist with a matching classification.

| Rule | Outcome | Source |
| --- | --- | --- |
| `opentlv-contents` | limitation | The `asn1.*` codecs apply X.690 11.1 and 11.2.1 to BER as well (`asn1_codec.h`) |
| `opentlv-strings` | limitation | CER string segmentation, X.690 9.2, is not checked: `cer_validation.h` is not bound |
| `opentlv-schema` | limitation | SET and SET OF order and DEFAULT omission are not checked: no schema layer is bound |
| `opentlv-writer` | limitation | The Tree Writer writes the value as given: it omits no DEFAULT and segments no CER string |
| `opentlv-adapter` | limitation | Only the TestLab adapter rejected a schema violation, so it is not an OpenTLV verdict |
| `opentlv-int64` | limitation | `asn1.integer` represents int64 only |
| `opentlv-oid` | limitation | `asn1.oid` holds at most `TLV_ASN1_OID_MAX_ARCS` (32) arcs, each within `uint64_t` |
| `opentlv-depth` | limitation | The adapters traverse at most 32 levels |
| `asn1c-cer` | not-comparable | asn1c reads CER with its BER decoder (`cer-form-as-ber`) |
| `asn1c:ber-integer-empty` | not-comparable | Probe `ber-integer-empty` |
| `asn1c:ber-integer-nonminimal` | not-comparable | Probe `ber-integer-nonminimal` |
| `asn1c:ber-boolean-empty` | not-comparable | Probes `ber-boolean-empty` and `ber-boolean-two-octets` |
| `asn1c:ber-bit-string-no-initial-octet` | not-comparable | Probe `ber-bit-string-no-initial-octet` |
| `asn1c:ber-oid-leading-80` | not-comparable | Probe `ber-oid-leading-80` |
| `asn1c:ber-oid-incomplete-subidentifier` | not-comparable | Probe `ber-oid-incomplete-subidentifier` |
| `asn1c:ber-oid-arc-above-32-bits` | not-comparable | Probe `ber-oid-arc-above-32-bits` |
| `asn1c:ber-high-tag-leading-zero` | not-comparable | Probe `ber-high-tag-leading-zero` |
| `asn1c:ber-high-tag-form-for-low-number` | not-comparable | Probe `ber-high-tag-form-for-low-number` |
| `asn1c:ber-bit-string-segment-unused` | not-comparable | Probe `ber-bit-string-segment-unused` |
| `asn1c:ber-bit-string-segment-no-initial-octet` | not-comparable | Probe `ber-bit-string-segment-no-initial-octet` |
| `asn1c:ber-bit-string-constructed-empty` | limitation | Probe `ber-bit-string-constructed-empty` |
| `asn1c:ber-primitive-indefinite` | not-comparable | Probe `ber-primitive-indefinite` |
| `asn1c:ber-constructed-segment-own-tag` | not-comparable | Probe `ber-constructed-segment-own-tag` |
| `asn1c:ber-constructed-ia5-octet-segments` | limitation | Probes `ber-constructed-ia5-octet-segments` and `ber-constructed-implicit-octet-segments` |
| `asn1c:ber-explicit-indefinite-primitive` | limitation | Probe `ber-explicit-indefinite-primitive` |
| `error-category` | inconclusive | Both reject, with another normalized error |
| `asn1c-reencoding` | inconclusive | asn1c decoded the input but could not re-encode it |

An asn1c probe explains a difference only when the reference's own reason for rejecting matches
the probed rule, or when the input has the probed shape. asn1c accepting an input that has a
probed defect and an unknown one is therefore explained by the first defect the reference finds.

## Run it

Set up OpenTLV Lua and the sanitized asn1c adapter on Linux or WSL, then run both strategies:

```sh
python3 scripts/setup_lua.py --lua lua5.2
python3 scripts/setup_asn1c.py --sanitize
python3 scripts/run_fuzz.py --seed 1 --iterations 5000
```

The [sanitized build](asn1c-reference.md#sanitized-build) keeps its receipts in
`build/asn1c-sanitized-runs`, which is the fuzzer's default. To fuzz the plain adapter instead,
pass `--asn1c-runs-dir build/asn1c-runs`; the summary then lists no sanitizers.

| Option | Default | Use |
| --- | --- | --- |
| `--seed` | 1 | The seed every case derives from |
| `--strategy` | both | `value` or `mutation`; repeat for both |
| `--iterations` | 500 | Cases per strategy, from `--start` |
| `--start` | 0 | First case index, to rerun one case |
| `--batch-size` | 200 | Cases per adapter process |
| `--timeout` | 120 | Seconds per adapter process |
| `--max-findings` | 50 | Findings to minimize; later ones are kept as found |
| `--minimize-rounds` | 48 | Evaluation rounds per minimization |
| `--output-dir` | `build/fuzz/seed-SEED` | New or empty; must be under `build/` or outside the repository |

`--lua-runs-dir`, `--lua-provenance`, `--asn1c-runs-dir` and `--asn1c-provenance` select setup
receipts as for the [DER differential](der-differential.md#run-the-comparison). Both receipts are
revalidated, so a run uses only the pinned OpenTLV Lua release, the pinned asn1c and the
committed capability probes.

| Exit code | Meaning |
| --- | --- |
| 0 | No finding; every difference is explained |
| 1 | Run failure, such as a missing setup, an output directory in use or a reference that contradicts itself |
| 2 | Invalid command-line usage |
| 3 | At least one finding |

### Output

| Path | Content |
| --- | --- |
| `summary.json`, `summary.md` | Seed, cases, package versions and commits, runtime, compiler, sanitizers, the TestLab commit and the seed corpora digests; counts per check, encoding and outcome; every explained difference with its rule, count and first case; the findings; input coverage per encoding, type and mutation |
| `findings/ID.json` | One finding with everything needed to reproduce and triage it |

The summary has no timestamps: the same seed, setup and TestLab commit give byte-identical
summaries.

## Findings

Findings that likely share a cause share a bucket: the check, encoding, outcome, reference verdict
and reason, and the type, or the normalized crash or sanitizer report. Only the first case of a
bucket is minimized; the count of all its cases is kept.

Each finding file holds:

- `first`: the original case, seed, strategy, index, mutations, both libraries' observations, the
  reference verdicts and the commands that rerun that one case;
- `minimized`: the minimized case, rechecked with both libraries and the X.690 reference, whether
  it is still in the same bucket (`stable`), and a command that confirms it by hand;
- `fixture_draft`: the minimized case as an entry of the committed corpus for its encoding,
  already validated by that corpus's runner, or the reason it does not validate;
- the packages, runtime, platform, compiler, sanitizers, receipts and TestLab commit.

Minimization drops chunks of bytes, or simplifies the value of an encoding finding, while the
finding stays in its bucket. It never moves a finding to an explanation or another outcome. It does
not rewrite length octets, so a minimized input can keep bytes that a length counts.

Rerun a finding's minimized case, which exits with code 3 while it still reproduces and 0 once it
no longer does, or rerun its original case:

```sh
python3 scripts/run_fuzz.py --replay build/fuzz/seed-1/findings/ID.json
python3 scripts/run_fuzz.py --seed 1 --strategy mutation --start 902 --iterations 1 --output-dir build/fuzz/case-902
```

Confirm the minimized input against X.690 by hand with the reference's own command:

```sh
python3 scripts/x690.py Identifier 06072a8fffffff9f7f --encoding der
```

### Triage

1. Confirm the minimized input against X.690 by reading the rule the reference cites. The
   reference is code too: a reference error is fixed in `x690.py` with a test.
2. Decide which library is wrong, or whether the TestLab adapter or harness is.
3. An explained limitation needs documentation or a capability probe; add a probe to
   `capabilities.json` and an explanation here, never an explanation without a source.
4. A defect goes to the repository that owns the library, or to its private security process.
   A confirmed non-security OpenTLV defect can become a fixture with a `confirmed` declaration
   in the [BER and CER corpus](ber-cer-differential.md#declarations).
5. Only a reviewed, triaged input enters a committed corpus. Start from `fixture_draft`, write
   its description and rule, and run the corpus's runner and the tests.

## Disclosure policy

Exploratory inputs and untriaged findings are local and private:

- Fuzz output stays under `build/`, which Git ignores, or outside the repository. The fuzzer
  refuses any other output directory in the repository.
- The fuzzer refuses to run in GitHub Actions. TestLab is public, so its workflow logs and
  artifacts are public, and they would publish untriaged inputs. `--private-ci` overrides this
  only for a CI whose logs and artifacts are private.
- A suspected vulnerability in OpenTLV goes to its private security reporting, and one in asn1c to
  upstream's private channel in its `SECURITY.md`. It never goes to a public issue, pull request,
  CI artifact or fixture.
- Only a confirmed non-security defect goes to a public issue in the owning repository, and only a
  reviewed regression fixture enters a committed corpus and public CI.

## CI

Exploratory runs stay out of [Fast and Extended](ci.md). Fast runs the fuzzer's unit tests,
which drive every strategy, check, explanation, minimization and report with stand-in libraries
and need no Lua or C compiler. A bounded scheduled or manual fuzz run needs a runner whose logs
and artifacts are private, which this public repository does not have. Add one only with such a
runner, a fixed time budget, and output that publishes counts but no inputs.

## Sanitizers

The asn1c adapter, the generated code and the asn1c runtime run under AddressSanitizer,
LeakSanitizer and UndefinedBehaviorSanitizer, and any report stops the adapter at the input that
caused it. The fuzzer reruns that input alone, and attributes a report that only appears at exit,
such as a leak, by splitting the batch.

OpenTLV Lua runs as released: the [dependency policy](dependencies.md#fresh-opentlv-package-from-luarocks)
installs it from luarocks.org as a user would, so it is not rebuilt with sanitizers. A crash still
shows as a dead or hung process. OpenTLV Core's own C API fuzzing already runs its libFuzzer targets
under AddressSanitizer and UndefinedBehaviorSanitizer in Core's `fuzz.yml` workflow.

## Results

Local verification on 2026-11-05 ran in WSL on Ubuntu 24.04 x86-64, with Python 3.12.3, Lua 5.2.4,
GCC 13.3.0 and the sanitized asn1c adapter, from a clean clone with these changes applied. Seeds 1,
2 and 3 each ran 20000 cases of each strategy: 260000 cases and about 700000 checks per seed, in
two to three minutes. None gave a finding:

| Seed | Checks | Pass | Limitation | Not comparable | Inconclusive | Findings |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 700839 | 662482 | 16543 | 18622 | 3192 | 0 |
| 2 | 700244 | 661878 | 16411 | 18609 | 3346 | 0 |
| 3 | 701068 | 663193 | 16165 | 18388 | 3322 | 0 |

With seed 1, the reference accepted 61466 and rejected 5633 BER inputs, accepted 41282 and rejected
24388 CER inputs, and accepted 41132 and rejected 26099 DER inputs. Every cited explanation occurred
at least once. Repeating seed 1 gave byte-identical summaries, and a single case reran alone. A
deliberate model error, which pretended that OpenTLV Lua checks every DER rule, gave a minimized,
stable finding, with a valid draft fixture, whose replay exited with code 3.

### Triaged findings

Earlier runs during development found the following, now triaged and resolved. None is an
OpenTLV defect, and none is a security issue.

| Finding | Owner | Resolution |
| --- | --- | --- |
| DER values longer than 1024 bytes failed to encode with a buffer error | TestLab | The OpenTLV DER adapter now sets the Tree Writer capacity, as the BER and CER adapter already did |
| OpenTLV rejects an OBJECT IDENTIFIER of about 1000 arcs | OpenTLV, documented | Explained by `opentlv-oid`: `TLV_ASN1_OID_MAX_ARCS` is 32 |
| asn1c reduces arcs above 2^32-1 modulo 2^32 | asn1c | New probe `ber-oid-arc-above-32-bits`; the DER guide said such arcs read as `null` |
| asn1c ignores a BIT STRING segment without its initial octet | asn1c | New probe `ber-bit-string-segment-no-initial-octet` |
| asn1c rejects an empty constructed BIT STRING | asn1c | New probe `ber-bit-string-constructed-empty` |
| UBSan reports a zero-length `memcpy()` from a null pointer in asn1c's `dynamic_encoder_cb()` | asn1c | Benign; the [sanitized build](asn1c-reference.md#sanitized-build) leaves out UBSan's `nonnull-attribute` check |

The asn1c findings characterize the reference only and are not reported upstream.

## Limits

- Only the 21 types of `TestLabReference-1` and the value ranges above are covered. REAL, time
  types, other string types and constraints beyond the schema are not.
- OpenTLV is exercised through its Lua binding and TestLab's adapters only. Core's schema layer,
  `cer_validation.h`, other bindings and the C API are not compared; Core's fuzzing covers its C API.
- The X.690 reference is the oracle. A defect shared by the reference and a library is not found;
  the committed corpora, written by hand from X.690, check the reference.
- Error categories, length forms and segment boundaries are not compared on findings, only
  acceptance and logical values, and DER and CER bytes.
- An asn1c difference behind a probed one is reported as the probed one.
- Only Linux and WSL with GCC were verified.
