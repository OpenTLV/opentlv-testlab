<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 Marek Cingel -->

# Reproducible Lua dependencies

`python3 scripts/setup_lua.py --lua lua5.2` sets up the two dependencies for the
initial comparison. Python 3.10+ orchestrates supported installation commands;
the comparison and package probes execute under PUC Lua 5.2. No dependencies
are added to Core or the binding repositories, and nothing is installed globally.

## Supported setup and selection

The first setup path supports Linux, including WSL, with GNU Make and the tools
listed in the [README](../README.md#set-up-both-lua-dependencies). Native Windows,
macOS, LuaJIT and other Lua ABIs are not yet supported by this installer. Python
policy tests also run on Windows. The cache key includes platform/runtime identity
so future supported configurations cannot accidentally reuse incompatible entries.

Use `--lua /prefix/bin/lua`, `--luarocks /prefix/bin/luarocks` and optionally
`--make /path/to/make` for private tool installations. `--lua-prefix /prefix`
selects the interpreter and header installation for LuaRocks; by default it is
inferred from the resolved Lua executable's `bin` directory. With system
`lua5.2`, install matching `liblua5.2-dev` headers. LuaRocks receives explicit
`--lua-version=5.2`, `--lua-dir` and a private `--tree`.

The runtime must provide `bit32` and `table.unpack`. Version output and the
interpreter executable digest are recorded, rather than trusting the name `lua`.
The script removes inherited Lua search/startup settings and LuaRocks config
overrides. A private LuaRocks config disables rock servers; the selected source
rock has no non-Lua rock dependencies. The compiler, CMake and Git remain local
build prerequisites. This is a dependency pin and installation contract, not a
bit-for-bit reproducible toolchain or native binary guarantee.

## External library installation and cache

[`dependencies/lua-asn1.json`](../dependencies/lua-asn1.json) pins
`kunkku/lua-asn1` v2.2.1 to its exact source commit and five file digests. As
established by the [scope audit](asn1-comparison.md), this revision has an upstream
Makefile, but no verified LuaRocks package. The installer therefore runs the
unmodified supported command:

```sh
make install ROOT_DIR=../stage
```

The command runs inside the verified source directory; its relative staging
root avoids upstream Makefile quoting limitations when the cache path contains
spaces. The resulting modules live under `stage/usr/share/lua/common/asn1`. The upstream
license is also preserved at `stage/usr/share/doc/lua-asn1/LICENSE`; the verified
original source, including the Makefile and license, remains alongside the stage.
`asn1.rfc3779` is installed as upstream specifies, but its optional `stringy`
dependency and RFC-specific APIs remain outside the comparison. The audited
`asn1` module does not require it.

The cache defaults to `build/dependency-cache/<key>`. The key is a SHA-256 of:

- the full external pin: version, commit, file hashes and declared metadata;
- the actual Lua ABI/version output and interpreter executable SHA-256;
- OS, kernel release, architecture and libc identity;
- GNU Make version/executable SHA-256, installation layout and installer schema.

Changing any of these selects a new entry. Absolute tool paths are not part of
the key; identical tools may be installed at different locations. Increment
`INSTALL_SCHEMA` when changing the installed layout or installation semantics.
Print the same key used by setup with:

```sh
python3 scripts/setup_lua.py --lua lua5.2 --print-cache-key
```

A cold run downloads commit-addressed source files, verifies every hash, installs
into a temporary directory, verifies the installed bytes and license, then
atomically publishes the complete cache entry. Failed downloads/installs never
publish partial entries. A warm run performs no external download or reinstall:
it revalidates the source, installed bytes, exact inventory and configuration,
rejecting corruption, symlinks, missing files and extra shadow modules. A corrupt
entry fails rather than becoming a cache miss or silently changing its identity.
To recover, remove that exact reported cache entry or choose a fresh `--cache-dir`.

An explicit offline check requires an existing valid external entry:

```sh
python3 scripts/setup_lua.py --lua lua5.2 --external-only --offline
```

It reruns all 35 external capability checks against the **installed** modules.
`--offline` is rejected without `--external-only`; it cannot waive fresh OpenTLV
acquisition. `--external-only` without `--offline` permits cold external setup.

## Fresh OpenTLV release package

[`dependencies/opentlv-lua.json`](../dependencies/opentlv-lua.json) selects the
published [OpenTLV Lua v0.3.0 release][release], release ID `427813424`, binding
commit `8fff4a001f34117647a7d59ff9b4602a2b330453`, rock `0.3.0-1`, and Core commit
`345c77acb29266036df5f27d04ce315bb61853cc`. Release identity and asset digests were
checked on 2026-10-30. The source rock supports Lua 5.2; the published precompiled
archives target Lua 5.4 and are not used for this comparison.

Every complete setup creates a new UUID run directory and downloads all three
pinned assets: `release-manifest.json`, `opentlv-0.3.0-1.rockspec` and
`opentlv-0.3.0-1.src.rock`. There is no OpenTLV cache, HTTP conditional request or
fallback to a previous run/local sibling checkout. Downloads request revalidation
and use no credentials, including on redirects. SHA-256 is checked against the
committed pin; a missing, replaced or truncated asset fails setup.

The manifest must match the binding version, tag, binding commit, Core commit
and source-rock/rockspec digests. The installer executes `luarocks unpack` on the
fresh source rock, checks its rockspec against the independently downloaded file,
then runs `luarocks make` in the unpacked source with a new private install tree.
These are the same source-rock installation steps used by the binding's own
package consumer checks; keeping the unpacked tree lets TestLab verify the
actual fetched Core Git commit after compilation. No Core override is passed.

It checks the installed facade, rockspec, Lua/Core license bytes and release
metadata. Source rocks legitimately have an empty `binding_revision`; provenance
comes from the pinned manifest and source-rock digest, not from inventing Git
metadata in an archive. An isolated Lua process checks the loaded native module
path, both public version APIs and a small BER read/encode round trip.

This verifies the selected published bytes and their installed identity. It does
not repeat the publisher's Full release gate or independently reverify Sigstore
attestations. Existing release records are provenance, not newly executed tests.

## Run records and downstream use

Runs default to `build/dependency-runs/<uuid>`; override this with `--runs-dir`.
Keep runs outside the external cache. Each run retains:

- `provenance.json`: status, timestamps, runtime/platform, cache key and hit/miss,
  exact source pins, fresh asset URLs/hashes/sizes, installed-file hashes, verified
  Core commit, version metadata and LuaRocks/CMake tool versions;
- `capabilities.log` and, for complete setup, `install.log`;
- fresh downloads, unpacked source, Core checkout, build and installed `tree`;
- `failure.json` when setup fails after creating the run directory.

Only `status: "passed"` represents successful setup. External-only receipts have
no `opentlv` section. The `environment` object supplies explicit `LUA_PATH` and
`LUA_CPATH` for the two installed libraries without default/fallback path suffixes.
The future runner should clear inherited `LUA_INIT*` and versioned `LUA_PATH*` /
`LUA_CPATH*` overrides before using it. Paths are local to that run; a receipt
copied as a CI artifact does not make its installed files portable or persistent.

## Fast CI and verification

Fast runs the Python policy tests, restores **only an exact external cache key**,
performs a complete fresh OpenTLV installation, and performs an offline external
cache hit check. It never caches the run directory, OpenTLV downloads, Core build
or installed native module. Provenance and logs are uploaded even on failure.
No fuzzy restore keys permit a different configuration to masquerade as a hit.

Tests cover cold/warm behavior, key invalidation, offline misses, corruption,
extra/missing installed files, incomplete downloads/installs, fresh release
acquisition on repeated runs and release integrity/provenance failures. The
setup smoke check is not the differential runner planned in issue #4. Local
success and a committed Fast workflow do not establish hosted CI success.

Local verification on 2026-10-30 passed 21 Python tests on Windows and WSL.
Under WSL, Lua 5.2.4 / LuaRocks 3.11.1 / CMake 3.28.3 completed two full setups:
the first external cache miss became a hit on the second, while each run freshly
downloaded all three OpenTLV assets, built the release rock and passed the native
package smoke check. An offline external cache hit and a separate cold install
with spaces in the cache path also passed all 35 capability checks. Both modules
loaded together using each complete run's recorded environment. Hosted Fast
remains to be verified on the PR.

[release]: https://github.com/OpenTLV/opentlv-lua/releases/tag/v0.3.0
