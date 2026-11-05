#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel

"""Build the two adapters from verified Cargo sources and a fresh Core release archive."""

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

if __package__:
    from . import check_rust_reference as reference
    from .run_differential import testlab_revision
    from .setup_lua import digest, require, run, write_json
else:
    import check_rust_reference as reference
    from run_differential import testlab_revision
    from setup_lua import digest, require, run, write_json

ROOT = reference.ROOT
PIN = ROOT / "dependencies/opentlv-core.json"
RUNS = ROOT / "build/rust-runs"
RECEIPT = ROOT / "build/rust-provenance.json"


def implementation_identity():
    paths = [*sorted((ROOT / "differential/rust").glob("src/*.rs")),
             *sorted((ROOT / "differential/rust/core").glob("*")),
             ROOT / "differential/rust/Cargo.toml", ROOT / "differential/rust/Cargo.lock",
             PIN, reference.PIN, Path(__file__), ROOT / "scripts/check_rust_reference.py",
             ROOT / "scripts/run_rust_differential.py", ROOT / "scripts/rust_adapter_process.py",
             ROOT / "scripts/setup_lua.py",
             ROOT / "differential/rust/observation.schema.json"]
    # Text identity is stable across Git's Windows CRLF and Linux LF checkouts.
    return {p.relative_to(ROOT).as_posix(): reference.digest(p.read_text(encoding="utf-8").encode())
            for p in paths}


def verify_assets(directory, pin):
    for name, expected in pin["assets"].items():
        require(digest(directory / name) == expected, f"Core asset checksum mismatch: {name}")
    manifest = reference.load_json(directory / "release-manifest.json")
    require(manifest["version"] == pin["version"] and manifest["commit"] == pin["commit"],
            "Core manifest identity mismatch")
    sources = [a for a in manifest["artifacts"] if a["kind"] == "source"]
    require(sources == [{"kind": "source", "filename": pin["archive"],
                         "sha256": pin["assets"][pin["archive"]], "version": pin["version"],
                         "commit": pin["commit"]}], "Core manifest source identity mismatch")


def extract_source(archive, destination, prefix):
    """Extract only regular files/directories below the single expected archive root."""
    with tarfile.open(archive, "r:gz") as stream:
        seen = set()
        members = stream.getmembers()
        require(sum(m.size for m in members) <= 128 * 1024 * 1024, "Core archive too large")
        for member in members:
            path = PurePosixPath(member.name)
            require(not path.is_absolute() and path.parts and path.parts[0] == prefix and
                    ".." not in path.parts and "\\" not in member.name and ":" not in member.name and
                    (member.isfile() or member.isdir()), "unsafe Core archive member")
            require(member.name not in seen, "duplicate Core archive member")
            seen.add(member.name)
        # No archive permissions, ownership, links or timestamps are applied.
        for member in members:
            target = destination / member.name
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with stream.extractfile(member) as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output)


def setup(directory, core_assets=None):
    implementation = implementation_identity()
    pin = reference.load_json(PIN)
    external = reference.load_json(reference.PIN)
    reference.verify_pin(external)
    reference.verify_cache(external)
    assets = directory / "assets"
    assets.mkdir()
    for name in pin["assets"]:
        if core_assets:
            shutil.copyfile(core_assets / name, assets / name)
        else:
            with urllib.request.urlopen(pin["base_url"] + name, timeout=60) as response:
                with (assets / name).open("xb") as output:
                    shutil.copyfileobj(response, output)
    verify_assets(assets, pin)
    extract_source(assets / pin["archive"], directory / "source", pin["source_directory"])
    log = directory / "build.log"
    native_build = directory / "core-build"
    commands = [
        ["cmake", "-S", ROOT / "differential/rust/core", "-B", native_build,
         "-DTESTLAB_CORE_SOURCE=" + str(directory / "source" / pin["source_directory"]),
         "-DCMAKE_BUILD_TYPE=Release"],
        ["cmake", "--build", native_build, "--config", "Release", "--target", "testlab-core", "--parallel", "4"],
        ["cargo", "test", "--locked", "--offline", "--manifest-path", ROOT / external["manifest"],
         "--target-dir", directory / "cargo-target"],
        ["cargo", "build", "--locked", "--offline", "--manifest-path", ROOT / external["manifest"],
         "--target-dir", directory / "cargo-target"],
    ]
    for command in commands:
        run(command, cwd=ROOT, log=log, timeout=600)
    require(implementation_identity() == implementation, "implementation changed during build; rerun setup")
    suffix = ".exe" if os.name == "nt" else ""
    candidates = list(native_build.rglob("testlab-core" + suffix))
    require(len(candidates) == 1, "missing or ambiguous Core executable")
    binaries = {"core": candidates[0], "der-parser": directory / "cargo-target/debug" /
                ("testlab-der-reference" + suffix)}
    cache = native_build / "CMakeCache.txt"
    configuration = {line.split("=", 1)[0]: line.split("=", 1)[1]
                     for line in cache.read_text(encoding="utf-8").splitlines()
                     if line.startswith(("OPENTLV_", "CMAKE_C_COMPILER:", "CMAKE_CXX_COMPILER:",
                                         "CMAKE_GENERATOR:", "CMAKE_BUILD_TYPE:")) and "=" in line}
    receipt = {"schema": 1, "status": "passed", "directory": str(directory),
               "packages": {"core": pin, "der-parser": external}, "testlab": testlab_revision(),
               "acquisition": "supplied-verified-release-assets" if core_assets else "fresh-release-download",
               "runtime": {"platform": platform.platform(), "machine": platform.machine(),
                           "rustc": run(["rustc", "-vV"]), "cargo": run(["cargo", "-V"]),
                           "cmake": run(["cmake", "--version"]).splitlines()[0]},
               "configuration": configuration, "commands": [[str(x) for x in c] for c in commands],
               "implementation": implementation,
               "binaries": {name: {"path": str(path), "sha256": digest(path)} for name, path in binaries.items()},
               "files": {str(cache): digest(cache), str(log): digest(log),
                         **{str(assets / name): checksum for name, checksum in pin["assets"].items()}}}
    write_json(directory / "provenance.json", receipt)
    return receipt


def load_receipt(path):
    receipt = reference.load_json(path)
    require(receipt.get("schema") == 1 and receipt.get("status") == "passed", "setup has not passed")
    require(receipt["implementation"] == implementation_identity(), "adapter implementation changed; rerun setup")
    require(receipt["packages"] == {"core": reference.load_json(PIN),
                                    "der-parser": reference.load_json(reference.PIN)}, "setup pins changed")
    require(set(receipt["binaries"]) == {"core", "der-parser"}, "setup participant set changed")
    for binary in receipt["binaries"].values():
        require(digest(Path(binary["path"])) == binary["sha256"], "adapter executable changed")
    for name, checksum in receipt["files"].items():
        require(digest(Path(name)) == checksum, "setup evidence changed: " + name)
    return receipt


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core-assets", type=Path,
                        help="use verified release assets supplied locally; recorded as supplied, not a fresh download")
    parser.add_argument("--output", type=Path, default=RECEIPT)
    args = parser.parse_args(arguments)
    RUNS.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix="run-", dir=RUNS))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    # Replace the selector first: a failed setup must not leave an older success selectable.
    failure = {"schema": 1, "status": "failed", "directory": str(directory), "error": "setup incomplete"}
    write_json(args.output, failure)
    try:
        receipt = setup(directory, args.core_assets)
        write_json(args.output, receipt)
        print(f"Built verified Core and der-parser adapters: {args.output}")
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, tarfile.TarError) as error:
        failure["error"] = str(error)
        write_json(directory / "failure.json", failure)
        write_json(args.output, failure)
        print(f"Rust differential setup failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
