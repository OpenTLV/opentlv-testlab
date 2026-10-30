#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel

"""Run OpenTLV Lua and lua-asn1 over the same fixture bytes and classify each result."""

import argparse
import json
from pathlib import Path
import re
import string
import subprocess
import sys

if __package__:
    from .check_asn1 import ROOT, load_pin
    from .setup_lua import clean_env, digest, load_release_pin, require, verify_install, write_json
else:
    from check_asn1 import ROOT, load_pin
    from setup_lua import clean_env, digest, load_release_pin, require, verify_install, write_json

HOST = ROOT / "differential/lua/adapter_host.lua"
OPENTLV_ADAPTER = ROOT / "differential/lua/opentlv_adapter.lua"
ASN1_ADAPTER = ROOT / "differential/lua/asn1_adapter.lua"
DEFAULT_FIXTURES = ROOT / "differential/fixtures/seed.json"
ADAPTER_TIMEOUT = 60
MISMATCH_EXIT = 3  # Distinct from uncaught errors (1) and argparse usage errors (2).

CLASSIFICATIONS = ("shared", "unsupported", "inconclusive")
OUTCOMES = ("pass", "mismatch", "unsupported", "inconclusive")
FRAMING_ERRORS = ("empty", "truncated", "trailing")
CATEGORIES = ("primitive", "constructed", "nested", "tag-boundary", "length-boundary", "truncated", "malformed")
PRIMITIVES = ("boolean", "integer", "bit_string", "octet_string", "ia5string")
MAX_WIRE_BYTES = 4096
MAX_SHARED_DEPTH = 4
LUA_STRING_SAFE = frozenset(string.ascii_letters + string.digits + " -_.")


class FramingError(ValueError):
    def __init__(self, kind):
        super().__init__(f"Wire has a {kind} framing error")
        self.kind = kind


def parse_shared_element(data, depth):
    require(depth <= MAX_SHARED_DEPTH, f"Shared fixtures nest at most {MAX_SHARED_DEPTH} levels")
    if not data:
        raise FramingError("truncated")
    identifier = data[0]
    require(identifier & 0x1F != 0x1F, "Shared fixtures need low tag numbers")
    require(identifier >> 6 in (0, 2), "Shared fixtures need universal or context tags")
    if len(data) < 2:
        raise FramingError("truncated")
    length = data[1]
    require(length < 0x80, "Shared fixtures need short-form lengths")
    if len(data) < 2 + length:
        raise FramingError("truncated")
    node = {"identifier": f"{identifier:02x}", "length": length, "length_bytes": f"{length:02x}"}
    value = data[2:2 + length]
    if identifier & 0x20:
        node["children"] = []
        while value:
            child, size = parse_shared_element(value, depth + 1)
            node["children"].append(child)
            value = value[size:]
    else:
        node["value"] = value.hex()
    return node, 2 + length


def parse_shared(wire):
    """Independent eligibility check; neither library output can define a fixture's expectation."""
    if not wire:
        raise FramingError("empty")
    node, size = parse_shared_element(wire, 1)
    if size != len(wire):
        raise FramingError("trailing")
    return node


def validate_shared_schema(schema):
    require(isinstance(schema, dict), "Schema must be an object")
    kind = schema.get("type")
    tag = schema.get("tag")
    require(tag is None or (type(tag) is int and 0 <= tag <= 30), "Shared tags must be 0-30")
    if kind in PRIMITIVES:
        require(schema.keys() <= {"type", "tag"}, f"Unexpected {kind} schema fields")
    elif kind == "sequence":
        require(schema.keys() <= {"type", "tag", "fields"} and isinstance(schema.get("fields"), list),
                "Sequence schema needs fields")
        for field in schema["fields"]:
            require(isinstance(field, dict) and field.keys() == {"name", "schema"} and
                    isinstance(field["name"], str), "Sequence field needs name and schema")
            validate_shared_schema(field["schema"])
    elif kind == "sequence_of":
        require(schema.keys() <= {"type", "tag", "item"} and "item" in schema,
                "Sequence-of schema needs an item")
        validate_shared_schema(schema["item"])
    elif kind == "explicit":
        require(schema.keys() == {"type", "tag", "inner"} and tag is not None,
                "Explicit schema needs a tag and inner type")
        validate_shared_schema(schema["inner"])
    else:
        raise ValueError(f"Schema type is not shared: {kind}")


def validate_expected(fixture, wire):
    expected = fixture.get("expected")
    require(isinstance(expected, dict), "Shared fixture needs an explicit expectation")
    if expected.get("result") == "accept":
        require(expected.keys() == {"result", "tree"}, "Accepted fixture needs only result and tree")
        require(parse_shared(wire) == expected["tree"], "Expected tree does not describe the wire")
    elif expected.get("result") == "reject":
        require(expected.keys() == {"result", "framing"} and expected["framing"] in FRAMING_ERRORS,
                f"Rejected fixture needs framing: {', '.join(FRAMING_ERRORS)}")
        try:
            parse_shared(wire)
        except FramingError as error:
            require(error.kind == expected["framing"], f"Wire has {error.kind}, not declared framing")
        else:
            raise ValueError("Wire is a complete shared element, but the fixture expects rejection")
    else:
        raise ValueError("Expected result must be accept or reject")


def validate_fixture(fixture):
    require(isinstance(fixture, dict) and
            isinstance(fixture.get("id"), str) and re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", fixture["id"]),
            "Fixture id must be lowercase kebab-case")
    try:
        require(fixture.get("operation") == "decode", "Only the decode operation is implemented")
        require(isinstance(fixture.get("wire"), str), "Wire must be a hex string")
        wire = bytes.fromhex(fixture["wire"])
        require(len(wire) <= MAX_WIRE_BYTES, f"Wire exceeds {MAX_WIRE_BYTES} bytes")
        schema = fixture.get("schema")
        require(isinstance(schema, dict) and isinstance(schema.get("type"), str),
                "Every fixture needs an explicit ASN.1 schema")
        classification = fixture.get("classification")
        require(classification in CLASSIFICATIONS, f"Classification must be: {', '.join(CLASSIFICATIONS)}")
        if classification == "shared":
            require("reason" not in fixture, "Shared fixture must not explain away a comparison")
            validate_shared_schema(schema)
            validate_expected(fixture, wire)
        else:
            require(isinstance(fixture.get("reason"), str) and fixture["reason"].strip(),
                    f"{classification.capitalize()} fixture needs a reason")
            require("expected" not in fixture, f"{classification.capitalize()} fixture has no verdict")
    except ValueError as error:
        raise ValueError(f"Fixture {fixture['id']}: {error}") from error


def validate_reproduction(metadata, fixtures):
    """Metadata names exact package versions, so changing a pin forces the corpus to be reverified."""
    require(isinstance(metadata, dict) and metadata.keys() == {"command", "runtime", "packages"},
            "Reproduction metadata needs command, runtime and packages")
    require(metadata["packages"] == {"opentlv": load_release_pin()["version"], "lua-asn1": load_pin()["version"]},
            "Corpus was verified against different package versions")
    for fixture in fixtures:
        require(fixture.get("category") in CATEGORIES, f"Fixture {fixture['id']}: Category must be: {', '.join(CATEGORIES)}")
        require(isinstance(fixture.get("description"), str) and fixture["description"].strip(),
                f"Fixture {fixture['id']}: Needs a description")


def load_corpus(path):
    corpus = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(corpus, dict) and corpus.get("schema") == 1, "Expected fixture schema 1")
    fixtures = corpus.get("fixtures")
    require(isinstance(fixtures, list) and fixtures, "Fixture list must not be empty")
    for fixture in fixtures:
        validate_fixture(fixture)
    identifiers = [fixture["id"] for fixture in fixtures]
    require(len(set(identifiers)) == len(identifiers), "Fixture ids must be unique")
    if "reproduction" in corpus:
        validate_reproduction(corpus["reproduction"], fixtures)
    return corpus


def newest_receipt(runs):
    candidates = []
    for path in runs.glob("*/provenance.json"):
        report = json.loads(path.read_text(encoding="utf-8"))
        if report.get("status") == "passed" and "opentlv" in report:
            candidates.append((report["completed_at"], path))
    require(candidates, f"No complete passed setup in {runs}; run scripts/setup_lua.py first")
    return max(candidates)[1]


def load_receipt(path):
    """Revalidate a setup receipt so results cannot come from changed or foreign libraries."""
    report = json.loads(path.read_text(encoding="utf-8"))
    require(report.get("status") == "passed" and "opentlv" in report,
            f"Receipt is not a complete passed setup: {path}")
    pin, release = load_pin(), load_release_pin()
    external, opentlv = report["external"], report["opentlv"]
    require(external["pin"] == pin and opentlv["pin"] == release, "Receipt uses different dependency pins")
    lua, configuration = Path(report["lua_executable"]), report["configuration"]
    require(digest(lua) == configuration["lua"]["executable_sha256"], "Lua interpreter changed after setup")
    verify_install(Path(external["directory"]), pin, configuration)
    tree = path.parent / "tree"
    files = {str(p.relative_to(tree)) for p in tree.rglob("*") if p.is_file()}
    require(files == set(opentlv["installed_files"]), "OpenTLV installation has a different inventory")
    for name, value in opentlv["installed_files"].items():
        require(digest(tree / name) == value, f"Installed OpenTLV file changed: {name}")
    module_directory = external["module_directory"]
    # One library per process: neither adapter can load the other or share its state.
    adapters = {
        "opentlv": {"script": OPENTLV_ADAPTER, "schema": False,
                    "environment": opentlv["environment"],
                    "module": str(tree / "lib/lua/5.2/opentlv/_core.so"),
                    "version": release["version"]},
        "lua-asn1": {"script": ASN1_ADAPTER, "schema": True,
                     "environment": {"LUA_PATH": module_directory + "/?/init.lua", "LUA_CPATH": ""},
                     "module": module_directory + "/asn1/init.lua"},
    }
    return {"path": path, "lua": lua, "runtime": configuration["lua"]["version"],
            "platform": configuration["platform"], "adapters": adapters,
            "packages": {"opentlv": {"version": release["version"], "commit": release["commit"],
                                     "core_commit": opentlv["core_commit"], "acquisition": opentlv["acquisition"],
                                     "source": opentlv["source"]},
                         "lua-asn1": {"version": pin["version"], "commit": pin["commit"]}}}


def lua_literal(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return '"' + "".join(chr(b) if chr(b) in LUA_STRING_SAFE else f"\\{b:03d}"
                             for b in value.encode("utf-8")) + '"'
    if isinstance(value, list):
        return "{" + ",".join(lua_literal(item) for item in value) + "}"
    if isinstance(value, dict):
        return "{" + ",".join(f"[{lua_literal(k)}]={lua_literal(v)}" for k, v in value.items()) + "}"
    raise ValueError(f"Cannot pass {type(value).__name__} to an adapter")


def current_fixture(stdout, requests):
    if isinstance(stdout, bytes):
        stdout = stdout.decode("utf-8", "replace")
    lines = (stdout or "").splitlines()
    if not lines:
        return "none (adapter startup)"
    completed = len(lines) - 1  # The first line is the identity.
    return requests[completed]["id"] if completed < len(requests) else "none (after the final result)"


def run_adapter(name, adapter, lua, requests):
    """Crashes, timeouts and protocol errors are run failures, never comparison outcomes."""
    environment = clean_env()
    environment.update(adapter["environment"])
    try:
        result = subprocess.run([str(lua), str(HOST), str(adapter["script"])], cwd=ROOT, env=environment,
                                input="return " + lua_literal(requests), capture_output=True,
                                text=True, encoding="utf-8", errors="replace", timeout=ADAPTER_TIMEOUT)
    except subprocess.TimeoutExpired as error:
        raise ValueError(f"{name} timed out at fixture {current_fixture(error.stdout, requests)}") from error
    require(result.returncode == 0, f"{name} failed ({result.returncode}) at fixture "
            f"{current_fixture(result.stdout, requests)}: {result.stderr[-2000:]}")
    lines = [json.loads(line) for line in result.stdout.splitlines()]
    require(len(lines) == len(requests) + 1, f"{name} returned an incomplete result set")
    identity, records = lines[0], lines[1:]
    require(identity.get("adapter") == name, f"{name} reported a different adapter")
    require(identity.get("module") == adapter["module"],
            f"{name} loaded an unexpected module: {identity.get('module')}")
    require(identity.get("version") == adapter.get("version"), f"{name} reported an unexpected version")
    for request, record in zip(requests, records):
        require(record.get("id") == request["id"], f"{name} returned results out of order")
        status = record.get("status")
        require(status in ("accepted", "rejected", "unsupported"), f"{name} returned status {status}")
        require(status != "accepted" or isinstance(record.get("tree"), dict),
                f"{name} accepted {request['id']} without a tree")
    return identity, records


def tree_differences(name, expected, observed, path="root"):
    differences = []
    for key in ("identifier", "length", "length_bytes", "value"):
        # A projected tree has no length bytes; it cannot agree or disagree about them.
        if key == "length_bytes" and key not in observed:
            continue
        if expected.get(key) != observed.get(key):
            differences.append(f"{name} {path}.{key}: expected {expected.get(key)!r}, "
                               f"observed {observed.get(key)!r}")
    wanted, seen = expected.get("children"), observed.get("children")
    if (wanted is None) != (seen is None):
        differences.append(f"{name} {path}: expected {'constructed' if wanted is not None else 'primitive'}")
    elif wanted is not None:
        if len(wanted) != len(seen):
            differences.append(f"{name} {path}: expected {len(wanted)} children, observed {len(seen)}")
        for index, (left, right) in enumerate(zip(wanted, seen)):
            differences.extend(tree_differences(name, left, right, f"{path}.{index}"))
    return differences


def classify(fixture, results):
    """Return (outcome, differences); eligibility comes from the fixture, not library behavior."""
    if fixture["classification"] != "shared":
        return fixture["classification"], []
    expected = fixture["expected"]
    wire_size = len(bytes.fromhex(fixture["wire"]))
    differences = []
    for name, result in results.items():
        status = result["status"]
        require(status != "unsupported",
                f"Fixture {fixture['id']} is shared, but {name} reports: {result.get('detail')}")
        if expected["result"] == "reject":
            # Error text and categories are never compared, only the declared framing rejection.
            if status != "rejected":
                differences.append(f"{name}: expected rejection, observed acceptance")
        elif status != "accepted":
            differences.append(f"{name}: expected acceptance, observed rejection: {result.get('detail')}")
        else:
            differences.extend(tree_differences(name, expected["tree"], result["tree"]))
            if result.get("consumed") != wire_size:
                differences.append(f"{name}: consumed {result.get('consumed')} of {wire_size} bytes")
    return ("mismatch" if differences else "pass"), differences


def run_comparison(fixtures, receipt, reproduction=None):
    records, identities = {}, {}
    for name, adapter in receipt["adapters"].items():
        requests = [{"id": f["id"], "wire": bytes.fromhex(f["wire"]).hex(),
                     **({"schema": f["schema"]} if adapter["schema"] else {})} for f in fixtures]
        identities[name], records[name] = run_adapter(name, adapter, receipt["lua"], requests)
        if reproduction:
            require(identities[name].get("runtime") == reproduction["runtime"],
                    f"Corpus was verified on {reproduction['runtime']}, not {identities[name].get('runtime')}")
    results = []
    for index, fixture in enumerate(fixtures):
        observed = {name: records[name][index] for name in records}
        outcome, differences = classify(fixture, observed)
        results.append({"id": fixture["id"], "category": fixture.get("category"),
                        "description": fixture.get("description"), "operation": fixture["operation"],
                        "wire": bytes.fromhex(fixture["wire"]).hex(),
                        "classification": fixture["classification"], "outcome": outcome,
                        "reason": fixture.get("reason"), "differences": differences,
                        "observed": observed})
    summary = {outcome: sum(r["outcome"] == outcome for r in results) for outcome in OUTCOMES}
    require(summary["pass"] + summary["mismatch"] > 0, "No shared fixture was compared")
    return {"schema": 1, "provenance": str(receipt["path"]), "runtime": receipt["runtime"],
            "platform": receipt["platform"], "packages": receipt["packages"], "reproduction": reproduction,
            "adapters": identities, "summary": summary, "fixtures": results}


def print_report(report):
    print(f"{report['runtime']}; OpenTLV {report['packages']['opentlv']['version']}; "
          f"lua-asn1 {report['packages']['lua-asn1']['version']}")
    print(f"Provenance: {report['provenance']}")
    for result in report["fixtures"]:
        reason = f": {result['reason']}" if result["reason"] else ""
        print(f"{result['outcome']:<12} {result['id']}{reason}")
        for difference in result["differences"]:
            print(f"             {difference}")
    print(", ".join(f"{report['summary'][outcome]} {outcome}" for outcome in OUTCOMES))


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, default=DEFAULT_FIXTURES)
    parser.add_argument("--provenance", type=Path, help="Setup receipt; default is the newest complete run")
    parser.add_argument("--runs-dir", type=Path, default=ROOT / "build/dependency-runs")
    parser.add_argument("--output", type=Path, help="Also write all observations as JSON")
    args = parser.parse_args(arguments)
    try:
        corpus = load_corpus(args.fixtures)
        receipt = load_receipt((args.provenance or newest_receipt(args.runs_dir)).resolve())
        report = run_comparison(corpus["fixtures"], receipt, corpus.get("reproduction"))
        print_report(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            write_json(args.output, report)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"Differential run failed: {error}", file=sys.stderr)
        return 1
    return MISMATCH_EXIT if report["summary"]["mismatch"] else 0


if __name__ == "__main__":
    sys.exit(main())
