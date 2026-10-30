# opentlv-testlab

Independent testing and validation laboratory for OpenTLV, including differential
testing against external libraries, cross-language binding verification, and
compatibility testing of released packages.

## ASN.1 Lua comparison

The first integration decodes the same BER bytes with OpenTLV Lua v0.3.0 and
[`kunkku/lua-asn1`](https://github.com/kunkku/lua-asn1) v2.2.1 under Lua 5.2, then
compares both results with an expectation written by hand.

External comparison dependencies belong only in TestLab. Do not add them to Core or to a
binding repository.

| Guide | What it covers |
| --- | --- |
| [Comparison scope](docs/asn1-comparison.md) | Upstream identity, license, runtimes and the full operation matrix |
| [Dependency setup](docs/dependencies.md) | Installation, cache keys, provenance and pin changes |
| [Differential runner](docs/differential-runner.md) | Outcomes, reports, the fixture format and the BER corpus |
| [Fast gate and extended suite](docs/ci.md) | What each workflow checks and how to read the result |

## Reproduce a comparison locally

### Set up both Lua dependencies

The supported setup is Linux or WSL with Python 3.10+, Lua 5.2 and its development
headers, LuaRocks, GNU Make, a C compiler, CMake 3.24+, Git, zip and unzip. On Ubuntu 24.04:

```sh
sudo apt-get install lua5.2 liblua5.2-dev luarocks cmake build-essential git zip unzip
git clone https://github.com/OpenTLV/opentlv-testlab.git
cd opentlv-testlab
python3 -m unittest discover -s tests
python3 scripts/setup_lua.py --lua lua5.2
```

On WSL, clone inside the Linux file system. A checkout shared with Windows shows as
modified because of line endings, so its reports warn about uncommitted changes.

Setup stages the pinned lua-asn1 using its upstream Makefile and caches it. It then
**freshly installs OpenTLV Lua v0.3.0 from luarocks.org with `luarocks`** into a new run
directory, verifies both libraries and records paths, versions, hashes and provenance.
`--lua`, `--luarocks`, `--make` and `--lua-prefix` select private tool installations.

### Run the comparison

```sh
python3 scripts/run_differential.py
python3 scripts/run_differential.py --fixtures differential/fixtures/asn1-ber.json
```

The first command runs the small seed fixtures and the second the BER corpus. Each prints
one line per fixture and ends with a summary. Both exit with code 0, and the BER corpus
ends with:

```text
102 pass, 0 mismatch, 43 unsupported, 24 inconclusive
```

To reproduce one fixture and keep what both libraries observed, select it by id:

```sh
python3 scripts/run_differential.py --fixtures differential/fixtures/asn1-ber.json --fixture length-reserved-ff --output build/one.json --report build/one.md
```

To see a mismatch and its report, run the deliberate probe, which exits with code 3:

```sh
python3 scripts/run_differential.py --fixtures tests/fixtures/differential_mismatch.json --output build/probe.json
python3 scripts/check_report.py build/probe.json
```

### Run the capability audit

The audit characterizes lua-asn1 alone, without installing it or OpenTLV. It needs Python
3.10+ and stock Lua 5.2 (tested locally with 5.2.4):

```sh
python3 scripts/check_asn1.py --download --lua lua5.2
```

On Windows, `python` can replace `python3`; `--lua` also accepts an executable
path. WSL can run the Linux commands directly. The initial command downloads
the five pinned upstream files into `build/asn1-source`, preserving their license
and verifying SHA-256 before writing. Subsequent offline audits omit `--download`;
they recheck every file before running Lua. Use `--source-dir PATH` to audit an
existing copy. A missing or changed file, failed capability assertion, wrong Lua
runtime or timeout fails the command.

### Commands

| Command | Use it to |
| --- | --- |
| `python3 -m unittest discover -s tests` | Check policies, corpora, reports and documentation; needs no Lua and also runs on Windows |
| `python3 scripts/setup_lua.py` | Install both libraries; see [dependency setup](docs/dependencies.md) |
| `python3 scripts/run_differential.py` | Compare the libraries; see the [runner guide](docs/differential-runner.md) |
| `python3 scripts/check_report.py FILE` | Rerun each mismatch in a JSON report and require the same result |
| `python3 scripts/check_asn1.py` | Verify the lua-asn1 pin and run the capability audit |
| `python3 scripts/run_extended.py` | Run the [extended suite](docs/ci.md#extended-suite) locally |

## Supported BER subset

The two libraries overlap only partly: lua-asn1 is a typed, schema-driven decoder, and
OpenTLV reads raw BER framing. A fixture can therefore be compared, or `shared`, only
if it has one complete root, short-form lengths 0-127 at every level, tags 0-30 in the
universal or context class, at most four levels and canonical primitive values.

| Fixture classification | What it covers |
| --- | --- |
| `shared` | BOOLEAN, INTEGER 0 to 2^31-1, BIT STRING, OCTET STRING, ASCII IA5String, SEQUENCE, SEQUENCE OF, explicit and implicit context tags, and rejecting empty, truncated or trailing input |
| `unsupported` | Long-form and indefinite lengths, high tags, application and private classes, constructed strings, negative and larger INTEGER, and types lua-asn1 lacks, such as NULL, OBJECT IDENTIFIER, REAL, SET and UTCTime |
| `inconclusive` | Nonminimal encodings, invalid BOOLEAN, INTEGER, BIT STRING or IA5 contents, schema conformance, end-of-contents octets and five levels of nesting |

Only decoding is compared. The [comparison matrix](docs/asn1-comparison.md#concrete-comparison-matrix)
gives each operation's decision and the [BER corpus](docs/differential-runner.md#ber-corpus)
lists what runs.

## Add a fixture

Write the bytes and expectation by hand, independently of both libraries, and add them
to [`differential/fixtures/asn1-ber.json`](differential/fixtures/asn1-ber.json). Then run:

```sh
python3 -m unittest discover -s tests
python3 scripts/run_differential.py --fixtures differential/fixtures/asn1-ber.json
```

If the libraries differ on a `shared` fixture, investigate. Do not reclassify it just to
pass the run. [Add a fixture](docs/differential-runner.md#add-a-fixture) has a complete
example and the rules for choosing a classification.

## Read the results

| Outcome | Meaning | What to do |
| --- | --- | --- |
| `pass` | A `shared` fixture, and both libraries met its expectation | Nothing |
| `mismatch` | A `shared` fixture, and a library did not meet its expectation | [Investigate](docs/differential-runner.md#mismatch-reports) |
| `unsupported` | Declared by the fixture: a missing operation or known limitation | Nothing; never a pass |
| `inconclusive` | Declared by the fixture: no fair verdict is possible | Nothing; never a pass |

The runner exits with code 0 when every `shared` fixture passes, 3 on a mismatch and 1
when the run itself fails, so that no verdict can be trusted.

A mismatch is a possible defect, not proof that either library is wrong. A report names
which library differs from the fixture. If only one differs, read its observation first.
If both differ, check the fixture first. If documentation or the capability audit
explains the difference, declare the fixture `unsupported` with that reason; otherwise
report it to the library. `--output` and `--report` save everything needed, including
the bytes, both results, versions and reproduction commands.

## Versions and cache

[`dependencies/lua-asn1.json`](dependencies/lua-asn1.json) and
[`dependencies/opentlv-lua.json`](dependencies/opentlv-lua.json) pin exact versions,
commits and SHA-256 digests. The two libraries are treated differently:

| | lua-asn1 | OpenTLV Lua |
| --- | --- | --- |
| Role | External library | Package under test |
| Source | Commit-addressed upstream files | luarocks.org, as a user installs it |
| Cache | `build/dependency-cache`, keyed by pin, Lua, platform and Make | Never cached; every setup installs it anew |

A changed cached file fails the run rather than being replaced. Print the current key
with `python3 scripts/setup_lua.py --lua lua5.2 --print-cache-key`. A pin changes only
through a reviewed update, as described in [Change a pin](docs/dependencies.md#change-a-pin);
never patch lua-asn1 or switch to a fork to make a comparison pass.

## CI

The `Fast` workflow gates every pull request and every push to `main`. It runs the Python
tests and full setup with an exact-key lua-asn1 cache, verifies an offline cache hit, runs
the seed fixtures and the BER corpus, requires the deliberate mismatch probe to exit with
code 3 and reproduce its report, and uploads reports, provenance and logs.

The `Extended` workflow is started by hand from the **Actions** tab and is not required
for a pull request. On x86-64 and arm64 Ubuntu, it starts without a cache, sets up twice,
checks that repeated runs and a second install give the same results, and uploads a
summary, reports, provenance and logs. Run the same suite locally with:

```sh
python3 scripts/run_extended.py --lua lua5.2
```

See [Fast gate and extended suite](docs/ci.md) for what each one checks and how to read
the result.

## Limits

- A `pass` shows that the libraries agree on the committed bytes, not that either is
  correct in general or that lua-asn1 is a validating decoder.
- `unsupported` and `inconclusive` fixtures are not evidence about OpenTLV. They keep
  observations for reading, and a disagreement on one never decides a run.
- Setup and the runner support only Lua 5.2 on Linux or WSL; OpenTLV's own Lua support is
  wider. Other Lua versions, native Windows and macOS are not yet supported here.
- Setup checks what the registry serves and what was installed. It does not repeat
  OpenTLV's release gate or verify Sigstore attestations.

## License

TestLab is MIT-licensed; see [LICENSE](LICENSE).
The downloaded external sources retain Kaarle Ritvanen's MIT notice and are
ignored by Git. No upstream source is vendored into the tracked tree.
