<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 Marek Cingel -->

# Fast gate and extended suite

TestLab has two workflows. `Fast` gates every pull request, and `Extended` is a deeper
suite that a person starts when they want more evidence.

| | `Fast` | `Extended` |
| --- | --- | --- |
| Runs on | Every pull request, pushes to `main`, manual start | Manual start; pull requests that change the suite itself |
| Before merging | Must pass | Not expected |
| Runners | Ubuntu 24.04 x86-64 | Ubuntu 24.04 x86-64 and arm64 |
| External cache | Restored by exact key | None, so setup starts cold |
| Differential runs | Each corpus once | Each corpus three times, across two installs |

## Fast gate

[`fast.yml`](../.github/workflows/fast.yml) runs, in order:

1. the Python tests;
2. full [dependency setup](dependencies.md), which installs OpenTLV Lua fresh from
   luarocks.org and restores lua-asn1 from an exact-key cache;
3. the capability audit against the cached library, without network acquisition;
4. the seed fixtures and the [BER corpus](differential-runner.md#ber-corpus);
5. the deliberate mismatch probe, which must exit with code 3 and reproduce its own report.

It uploads the `differential-reports` and `dependency-provenance` artifacts, even after
a failure. `main` has no branch protection yet, so passing `Fast` before merging is a
project rule that GitHub does not enforce.

Both corpora stay in this gate. They are committed bytes with no clock, seed or network,
and on the last hosted runs each finished within about a second. Moving the BER corpus out
would save almost nothing and leave fixture changes untested until someone started the
manual suite.

## Extended suite

[`extended.yml`](../.github/workflows/extended.yml) runs the Python tests and
[`scripts/run_extended.py`](../scripts/run_extended.py) on both runners. It restores no
cache. The suite adds what `Fast` cannot show:

| Check | What it adds to `Fast` |
| --- | --- |
| `cold-setup` | Upstream lua-asn1 can still be downloaded, verified and installed with no cache; a hit fails |
| `repeat-setup` | A second setup hits that cache and still installs OpenTLV fresh; a miss fails |
| `offline-cache` | The entry those setups share passes the capability audit without network acquisition |
| `standalone-audit` | The [documented audit](../README.md#run-the-capability-audit) works from a new download |
| `compare-seed`, `compare-asn1-ber` | Repeating a run gives byte-identical reports, and a second install gives identical fixture results |
| `mismatch-probe` | The probe exits with code 3 and reproduces its report |

The arm64 runner also builds OpenTLV Lua and Core there, which no other OpenTLV workflow
does yet, and lua-asn1 under a new cache key.

### Start it

In GitHub, open **Actions**, select **Extended**, choose **Run workflow** and pick a branch.
It takes no inputs.

A pull request that changes `extended.yml` or `run_extended.py` also runs the suite,
because GitHub cannot start a workflow by hand before it reaches the default branch. Do not
make `Extended` a required status check: on a pull request that its path filter skips, the
check would never report and the pull request could not merge.

To run the same suite locally on Linux or WSL, with the [setup tools](../README.md#set-up-both-lua-dependencies)
installed:

```sh
python3 scripts/run_extended.py --lua lua5.2
```

`--luarocks`, `--make` and `--lua-prefix` select private tools, as for setup. `--output-dir`
defaults to `build/extended`. It must be new or empty, so that an earlier cache cannot pass
as a cold setup; the suite never deletes it for you.

### Read the result

Each hosted run shows the summary table on its run page and uploads an `extended-RUNNER`
artifact:

| Path | Content |
| --- | --- |
| `summary.md`, `summary.json` | Overall status, TestLab commit, platform and one result per check |
| `reports/` | [Differential reports](differential-runner.md#mismatch-reports), JSON and Markdown, for every run |
| `logs/` | Output of every script the suite ran |
| `runs/*/` | Setup receipts, install and capability logs, and any `failure.json` |

Installed libraries, the cache and the source download stay out of the artifact, and local
runs keep them in the output directory. A receipt's paths only exist on the machine that
wrote it.

| Exit code | Status | Meaning |
| --- | --- | --- |
| 0 | `passed` | Every check passed |
| 1 | `failed` | A check failed or could not run, so read its log; this outranks a mismatch |
| 2 | | Invalid usage, including an output directory that is not empty |
| 3 | `mismatch` | Only a committed corpus mismatched; [investigate it](differential-runner.md#mismatch-reports) |

A failed `cold-setup` or `repeat-setup` ends the suite, because every later check needs
both installs, so the summary lists only the checks that ran. Any other check can fail and
the rest still run.

## Limits

- `Extended` runs the same committed fixtures as `Fast`. It adds setup paths, an
  architecture and repeat runs, not new inputs.
- It only tests Lua 5.2 on Ubuntu 24.04. Other Lua versions and platforms remain outside
  the [supported setup](dependencies.md#supported-setup-and-selection).
- Second-install comparison covers fixture results. The report headers differ, since they
  name each install's receipt.
- It cannot show that a newer upstream release exists, and it does not repeat a binding's
  own release gate.

## Verification

Local verification on 2026-10-30 used WSL with Lua 5.2.4 and LuaRocks 3.11.1 on x86-64.
`run_extended.py` passed all seven checks with exit code 0, starting from an empty output
directory: the BER corpus gave 102 pass, 0 mismatch, 43 unsupported and 24 inconclusive. A
non-empty output directory gave exit code 2, and a missing interpreter gave exit code 1 with
a summary naming `cold-setup`. Stand-in scripts in the Python tests exercise the mismatch,
unstable-report and install-dependent paths.

Hosted runs on 2026-10-30 passed on the [`Extended` pull request run][extended-run] for both
x86-64 and arm64, each uploading its `extended-RUNNER` artifact, and on the [`Fast` run on
`main`][fast-run], which uploaded `differential-reports` and `dependency-provenance`. Starting
`Extended` by hand from **Actions** has not been exercised yet.

[extended-run]: https://github.com/OpenTLV/opentlv-testlab/actions/runs/41062388886
[fast-run]: https://github.com/OpenTLV/opentlv-testlab/actions/runs/41062607319
