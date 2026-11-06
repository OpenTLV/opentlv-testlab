#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel

"""Fresh published Rust packages for the three-way runner; no binding checkout/cache."""

import json
import os
from pathlib import Path
import re
import sys
import urllib.request

if __package__:
    from . import check_rust_reference as reference
    from .setup_lua import digest, require, run, write_json
else:
    import check_rust_reference as reference
    from setup_lua import digest, require, run, write_json

ROOT = reference.ROOT
PIN = ROOT / "dependencies/opentlv-rust.json"


def verify_pin(pin):
    require(pin["schema"] == 1 and pin["version"] == "0.2.2", "unknown Rust binding baseline")
    for field in ("manifest", "lockfile"):
        require(reference.digest((ROOT / pin[field]).read_text(encoding="utf-8").encode()) == pin[field + "_sha256"],
                "binding " + field + " changed")
    manifest = (ROOT / pin["manifest"]).read_text(encoding="utf-8")
    require('opentlv = { version = "=0.2.2", default-features = false }' in manifest and
            'rust-version = "1.82"' in manifest, "binding version/features changed")
    locked = []
    for block in (ROOT / pin["lockfile"]).read_text(encoding="utf-8").split("[[package]]")[1:]:
        fields = dict(re.findall(r'^(name|version|source|checksum) = "([^"\n]+)"$', block, re.M))
        if "source" in fields:
            locked.append(fields)
        else:
            require(fields == {"name": "testlab-rust-binding", "version": "0.1.0"}, "unexpected local binding dependency")
    require(locked == [{k: p[k] for k in ("name", "version", "source", "checksum")} for p in pin["packages"]],
            "binding package inventory differs")
    require({p["name"] for p in pin["packages"]} == {"opentlv", "opentlv-sys"}, "unexpected binding packages")
    for package in pin["packages"]:
        require(package["source"] == reference.REGISTRY and package["version"] == pin["version"] and
                package["features"] == [] and package["license"] == "MIT" and
                package["url"] == f'https://static.crates.io/crates/{package["name"]}/{package["name"]}-0.2.2.crate',
                "unreviewed binding registry/version/features")
    core = reference.load_json(ROOT / "dependencies/opentlv-core.json")
    require(all(pin["core_lock"][key] == core[key] for key in ("version", "commit", "repository")),
            "binding and direct Core pins differ")


def verify_selection(selection, pin):
    require(selection["mode"] in ("verified-source", "verified-binary") and selection["verified"] is True and
            selection["dirty"] is False, "binding did not use verified Core")
    for key in ("repository", "version", "commit", "release_tag"):
        require(selection[key] == pin["core_lock"][key], "binding selected a different Core: " + key)
    require(selection["locked_commit"] == pin["core_lock"]["commit"] and
            selection["locked_version"] == pin["core_lock"]["version"], "binding Core lock differs")


def build(directory, extract_source):
    pin = reference.load_json(PIN)
    verify_pin(pin)
    for name in ("OPENTLV_CORE_SOURCE", "OPENTLV_LIB_DIR", "OPENTLV_LINK_KIND", "DOCS_RS",
                 "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER"):
        require(not os.environ.get(name), "binding setup forbids override: " + name)
    directory.mkdir()
    assets, vendor, home = (directory / name for name in ("assets", "vendor", "cargo-home"))
    assets.mkdir()
    home.mkdir()
    files = {}
    for package in pin["packages"]:
        name = f'{package["name"]}-{package["version"]}'
        archive = assets / (name + ".crate")
        with urllib.request.urlopen(package["url"], timeout=60) as response:
            archive.write_bytes(response.read())
        require(digest(archive) == package["checksum"] and archive.stat().st_size == package["size"],
                "binding archive checksum/size differs: " + name)
        extract_source(archive, vendor, name)
        source = vendor / name
        reference.verify_archive(archive, source, package)
        require(reference.load_json(source / ".cargo_vcs_info.json")["git"]["sha1"] == pin["commit"],
                "binding packaged revision differs")
        if package["name"] == "opentlv-sys":
            require(reference.load_json(source / "core/core-artifact.json") == pin["core_lock"], "published Core lock differs")
        hashes = {p.relative_to(source).as_posix(): digest(p) for p in source.rglob("*") if p.is_file()}
        # Standard Cargo directory-source replacement, with the ORIGINAL registry
        # checksum. No path dependency, patch, or modification of packaged files.
        write_json(source / ".cargo-checksum.json", {"files": hashes, "package": package["checksum"]})
        files[str(archive)] = package["checksum"]
        files.update({str(source / name): checksum for name, checksum in hashes.items()})
        files[str(source / ".cargo-checksum.json")] = digest(source / ".cargo-checksum.json")
    config = home / "config.toml"
    config.write_text('[source.crates-io]\nreplace-with = "published"\n[source.published]\ndirectory = ' +
                      json.dumps(vendor.as_posix()) + '\n', encoding="utf-8")
    files[str(config)] = digest(config)
    env = dict(os.environ, CARGO_HOME=str(home), OPENTLV_PYTHON=sys.executable)
    manifest = ROOT / pin["manifest"]
    target = directory / "target"
    log = directory / "build.log"
    base = ["--locked", "--offline", "--manifest-path", manifest]
    metadata = json.loads(run(["cargo", "metadata", *base, "--format-version", "1"], env=env, cwd=ROOT, log=log))
    packages = {p["name"]: p for p in metadata["packages"] if p["source"]}
    require(set(packages) == {p["name"] for p in pin["packages"]}, "binding resolved inventory differs")
    nodes = {p["id"]: p for p in metadata["resolve"]["nodes"]}
    for expected in pin["packages"]:
        actual = packages[expected["name"]]
        require(all(actual[k] == expected[k] for k in ("version", "source", "license", "rust_version")) and
                nodes[actual["id"]]["features"] == expected["features"] and
                Path(actual["manifest_path"]).parent == vendor / f'{expected["name"]}-{expected["version"]}',
                "binding resolution was overridden")
    commands = [["cargo", action, *base, "--target-dir", target] for action in ("test", "build")]
    for command in commands:
        run(command, env=env, cwd=ROOT, log=log, timeout=900)
    selections = list(target.glob("debug/build/opentlv-sys-*/out/core-selection.json"))
    require(len(selections) == 1, "missing or ambiguous binding Core provenance")
    selection = reference.load_json(selections[0])
    verify_selection(selection, pin)
    verification_path = Path(selection["source_dir"]).parent.parent / "verification.json"
    verification = reference.load_json(verification_path)
    require(verification["verified"] is True and all(verification[k] == selection[k]
            for k in ("mode", "repository", "version", "commit", "release_tag")),
            "binding release verification evidence differs")
    binary = target / "debug" / ("testlab-rust-binding.exe" if os.name == "nt" else "testlab-rust-binding")
    require(run([binary, "--version"]) == pin["core_lock"]["version"], "binding linked version differs")
    files.update({str(selections[0]): digest(selections[0]), str(log): digest(log),
                  str(verification_path): digest(verification_path)})
    for package in pin["packages"]:
        name = f'{package["name"]}-{package["version"]}'
        reference.verify_archive(assets / (name + ".crate"), vendor / name, package)
    # Preserve resolver evidence and CMake configuration in the parent receipt.
    for path in target.rglob("*"):
        if path.is_file() and (path.name == "CMakeCache.txt" or path.name in ("core-release.txt", "core-release.json")):
            files[str(path)] = digest(path)
    return binary, {"acquisition": "fresh-crates-io-archives", "core_selection": selection,
                    "core_verification": verification,
                    "commands": [[str(x) for x in c] for c in commands]}, files


if __name__ == "__main__":
    verify_pin(reference.load_json(PIN))
    print("Verified published Rust binding pin; no download, build or differential verdict.")
