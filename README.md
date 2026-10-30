# opentlv-testlab

Independent testing and validation laboratory for OpenTLV, including differential
testing against external libraries, cross-language binding verification, and
compatibility testing of released packages.

## ASN.1 Lua comparison

The first integration compares OpenTLV Lua with `kunkku/lua-asn1`.
The [comparison scope](docs/asn1-comparison.md) identifies the upstream package,
exact version, license, runtime requirements, shared operations and exclusions.
The machine-readable pin is [dependencies/lua-asn1.json](dependencies/lua-asn1.json).

Issue #2 establishes this scope and an executable upstream capability audit.
Issue #3 adds reproducible dependency setup, an external cache and fresh OpenTLV
release installation. The differential runner, fixture corpus and mismatch
reporting remain follow-up work in [epic #1](https://github.com/OpenTLV/opentlv-testlab/issues/1).
External comparison dependencies belong only in TestLab.

## Set up both Lua dependencies

The initial supported setup is Linux/WSL with Lua 5.2 and its development headers,
LuaRocks, GNU Make, a C compiler, CMake 3.24+, Git, zip and unzip. On Ubuntu 24.04:

```sh
sudo apt-get install lua5.2 liblua5.2-dev luarocks cmake build-essential git zip unzip
python3 -m unittest discover -s tests -v
python3 scripts/setup_lua.py --lua lua5.2
```

This stages the pinned external library using its upstream Makefile. It then
**freshly downloads and installs OpenTLV Lua v0.3.0** from its published source
rock into a unique run directory, verifies both installed libraries and records
paths, versions, hashes and provenance. Only the external library is cached.
See [dependency setup](docs/dependencies.md) for cache keys, offline verification,
custom tool paths, receipts and supported-platform limits.

## Run the capability audit

Use Python 3.10+ and stock Lua 5.2 (tested locally with 5.2.4). For example,
install `lua5.2` with your OS package manager, then run from this repository:

```sh
python3 -m unittest discover -s tests -v
python3 scripts/check_asn1.py --download --lua lua5.2
```

On Windows, `python` can replace `python3`; `--lua` also accepts an executable
path. WSL can run the Linux commands directly. The initial command downloads
the five pinned upstream files into `build/asn1-source`, preserving their license
and verifying SHA-256 before writing. Subsequent offline audits omit `--download`;
they recheck every file before running Lua. Use `--source-dir PATH` to audit an
existing copy. A missing or changed file, failed capability assertion, wrong Lua
runtime or timeout fails the command.

The `Fast` workflow runs the dependency tests and full setup on Ubuntu with Lua
5.2, restores only the exact external cache key, then verifies an offline cache
hit. It uploads provenance and logs. It does not yet run the differential gate
planned in issue #7.

## License

TestLab is MIT-licensed; see [LICENSE](LICENSE).
The downloaded external sources retain Kaarle Ritvanen's MIT notice and are
ignored by Git. No upstream source is vendored into the tracked tree.
