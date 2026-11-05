#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel

"""Validate the #29 dependency inventory and corpus; never run a differential comparison."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile

if __package__:
    from . import x690
else:
    import x690

ROOT = Path(__file__).resolve().parents[1]
PIN = ROOT / "dependencies/der-parser.json"
CORPUS = ROOT / "differential/fixtures/rust-ber-der.json"
MATRIX = ROOT / "differential/rust/capabilities.json"
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
CLASSIFICATIONS = ("shared", "unsupported", "inconclusive")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify_pin(pin, root=ROOT):
    """The lockfile hash covers edges as well as package versions and checksums."""
    require(pin["schema"] == 1, "unknown pin schema")
    lock = (root / pin["lockfile"]).read_text(encoding="utf-8")
    require(digest(lock.encode()) == pin["lockfile_sha256"], "lockfile digest mismatch")
    manifest = (root / pin["manifest"]).read_text(encoding="utf-8")
    require(digest(manifest.encode()) == pin["manifest_sha256"], "manifest digest mismatch")
    require('version = "=10.0.0", default-features = false, features = ["std"]' in manifest,
            "reference feature/version selection changed")
    require(f'rust-version = "{pin["baseline_rust_version"]}"' in manifest, "baseline Rust version changed")
    # Read only scalar inventory fields from Cargo's generated package blocks.
    # Cargo itself validates the complete TOML and dependency graph in --verify-cache mode.
    locked = []
    for block in lock.split("[[package]]")[1:]:
        fields = dict(re.findall(r'^(name|version|source|checksum) = "([^"\n]+)"$', block, re.M))
        if "source" in fields:
            locked.append(fields)
        else:
            require(fields == {"name": "testlab-der-reference", "version": "0.1.0"},
                    "unexpected local dependency")
    inventory = [{key: p[key] for key in ("name", "version", "source", "checksum")} for p in pin["packages"]]
    require(locked == inventory, "package inventory differs from lockfile")
    require(all(p["source"] == REGISTRY and p["license"] for p in pin["packages"]),
            "unreviewed registry or license")
    reference = next(p for p in pin["packages"] if p["name"] == "der-parser")
    require(reference["version"] == pin["version"] == "10.0.0" and
            reference["checksum"] == pin["archive"]["sha256"], "reference pin mismatch")
    require(reference["features"] == ["std"], "unexpected reference features")
    require(reference["license"] == pin["license"] and reference["rust_version"] == pin["upstream_rust_version"],
            "reference license/MSRV metadata differs")


def verify_archive(archive, source, package):
    """Verify the cached archive and every packaged source file before using the cache."""
    require(digest(archive.read_bytes()) == package["checksum"], f"archive digest mismatch: {archive.name}")
    prefix = f'{package["name"]}-{package["version"]}/'
    with tarfile.open(archive, "r:gz") as stream:
        for member in stream.getmembers():
            require(member.isfile() or member.isdir(), "unsupported archive member")
            require(member.name.startswith(prefix) and ".." not in Path(member.name).parts,
                    "unsafe archive member")
            if member.isfile():
                installed = source / member.name[len(prefix):]
                require(installed.is_file() and not installed.is_symlink(), f"missing source: {member.name}")
                require(installed.read_bytes() == stream.extractfile(member).read(),
                        f"source differs from archive: {member.name}")
    for name, checksum in package["notices"].items():
        require(digest((source / name).read_bytes()) == checksum, f"license notice differs: {name}")


def verify_cache(pin):
    command = ["cargo", "metadata", "--locked", "--offline", "--format-version", "1",
               "--manifest-path", str(ROOT / pin["manifest"])]
    metadata = json.loads(subprocess.check_output(command, cwd=ROOT, text=True, encoding="utf-8", timeout=120))
    packages = {(p["name"], p["version"]): p for p in metadata["packages"] if p["source"]}
    require(set(packages) == {(p["name"], p["version"]) for p in pin["packages"]}, "resolved inventory differs")
    nodes = {p["id"]: p for p in metadata["resolve"]["nodes"]}
    for expected in pin["packages"]:
        package = packages[expected["name"], expected["version"]]
        for field in ("source", "license", "rust_version"):
            require(package[field] == expected[field], f'{package["name"]}: {field} differs')
        require(sorted(nodes[package["id"]]["features"]) == expected["features"], "resolved features differ")
        source = Path(package["manifest_path"]).parent
        archive = source.parent.parent.parent / "cache" / source.parent.name / (source.name + ".crate")
        verify_archive(archive, source, expected)
        if expected["name"] == "der-parser":
            require(archive.stat().st_size == pin["archive"]["size"], "reference archive size differs")
            require(load_json(source / ".cargo_vcs_info.json")["git"]["sha1"] == pin["commit"],
                    "packaged VCS revision differs")


def normalized_tree(element):
    """Project the independent X.690 reference to the wire-preserving contract."""
    identifier, wire = element.identifier, element.encoding
    first = wire[len(identifier)]
    length_size = 1 + (first & 0x7f if first > 0x80 else 0)
    length_hex = wire[len(identifier):len(identifier) + length_size].hex()
    number = identifier[0] & 31
    if number == 31:
        number = 0
        for octet in identifier[1:]:
            number = (number << 7) | (octet & 127)
    content = wire[len(identifier) + length_size:]
    if first == 0x80:
        content = content[:-2]
    return {
        "class": ("universal", "application", "context", "private")[identifier[0] >> 6],
        "number": str(number), "constructed": element.constructed, "identifier_hex": identifier.hex(),
        "length": {"form": "indefinite" if first == 0x80 else "long" if first > 0x80 else "short",
                   "value": None if first == 0x80 else str(len(content)), "encoded_hex": length_hex},
        "value_hex": content.hex(), "children": [normalized_tree(child) for child in element.children],
    }


def verify_corpus(corpus, matrix):
    require(corpus["schema"] == 1 and corpus["contract"] == "rust-ber-der-1", "unknown corpus contract")
    require(corpus["reproduction"]["packages"] == {"der-parser": "10.0.0"}, "corpus package pin differs")
    require(matrix["schema"] == 1, "unknown capability schema")
    features = {row["id"]: row for row in matrix["features"]}
    require(len(features) == len(matrix["features"]), "duplicate feature id")
    statuses = {"supported", "unsupported", "not-comparable", "not-tested"}
    for row in features.values():
        for name in ("core", "rust_binding", "der_parser_ber", "der_parser_der"):
            require(row[name]["status"] in statuses and row[name]["evidence"], "missing capability evidence")
    types = x690.load_types()
    ids = set()
    origins = {}
    for fixture in corpus["fixtures"]:
        name = fixture["id"]
        require(re.fullmatch(r"(?:ber|der)-[a-z0-9-]+", name) and name not in ids, "invalid/duplicate fixture id")
        ids.add(name)
        require(fixture["encoding"] in ("ber", "der"), f"{name}: invalid encoding")
        require(fixture["classification"] in CLASSIFICATIONS, f"{name}: invalid classification")
        require(fixture["feature"] in features and fixture["reason"] and fixture["rule"].startswith("X.690"),
                f"{name}: missing rationale")
        require(fixture["review"] in ("existing-reviewed-corpus", "reviewed-mutation"), f"{name}: unreviewed input")
        origin_file, origin_id = fixture["origin"].split(":")
        require(origin_file in ("ber-cer-interop", "der-canonical"), "unknown corpus origin")
        if origin_file not in origins:
            origins[origin_file] = {f["id"]: f for f in load_json(ROOT / f"differential/fixtures/{origin_file}.json")["fixtures"]}
        original = origins[origin_file][origin_id]
        data = bytes.fromhex(fixture["wire"])
        origin_data = bytearray.fromhex(original["wire"])
        if fixture["review"] == "reviewed-mutation":
            mutation = fixture["mutation"]
            require(origin_data[mutation["offset"]] == mutation["before"], "mutation preimage differs")
            origin_data[mutation["offset"]] = mutation["after"]
        require(data == origin_data and fixture["type"] == original["type"],
                f"{name}: origin bytes/type differ")
        require(len(data) <= corpus["limits"]["max_input_bytes"], f"{name}: input budget exceeded")
        expected = fixture["expected"]
        original_result = "accept" if original["expected"]["result"] == "canonical" else original["expected"]["result"]
        if fixture["review"] == "existing-reviewed-corpus":
            require(expected["result"] == original_result, f"{name}: origin expectation differs")
        try:
            value = x690.decode(types[fixture["type"]], data, fixture["encoding"])
        except x690.Invalid as error:
            require(expected == {"result": "reject", "error": error.error}, f"{name}: rejection expectation differs")
            if fixture["review"] == "existing-reviewed-corpus":
                require(error.error == original["expected"]["error"], f"{name}: origin rejection differs")
        else:
            require(expected["result"] == "accept" and expected["value"] == value == original["expected"]["value"],
                    f"{name}: typed expectation differs")
            element, consumed = x690.parse_element(data, 0, len(data), True, x690.PROFILES[fixture["encoding"]], 0)
            require(consumed == len(data) and expected["tree"] == normalized_tree(element), f"{name}: tree differs")
            def dimensions(node, depth=0):
                sizes = [dimensions(child, depth + 1) for child in node["children"]]
                return 1 + sum(count for count, _ in sizes), max([depth] + [level for _, level in sizes])
            count, depth = dimensions(expected["tree"])
            require(count <= corpus["limits"]["max_elements"] and depth <= corpus["limits"]["max_depth"],
                    f"{name}: traversal budget exceeded")
    require(ids, "empty corpus")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-cache", action="store_true", help="also verify Cargo's offline registry sources and features")
    args = parser.parse_args()
    try:
        pin, corpus, matrix = load_json(PIN), load_json(CORPUS), load_json(MATRIX)
        verify_pin(pin)
        verify_corpus(corpus, matrix)
        if args.verify_cache:
            verify_cache(pin)
        print(f'Validated {len(pin["packages"])} dependency pins and {len(corpus["fixtures"])} fixture contracts; no differential verdict.')
        return 0
    except (ValueError, KeyError, OSError, subprocess.SubprocessError, tarfile.TarError) as error:
        print(f"Rust reference contract failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
