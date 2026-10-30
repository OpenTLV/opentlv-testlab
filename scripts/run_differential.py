#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel

"""Run OpenTLV Lua and lua-asn1 over the same fixture bytes and classify each result."""

import argparse
import json
from pathlib import Path
import re
import shlex
import string
import subprocess
import sys

if __package__:
    from .check_asn1 import ROOT, load_pin
    from .setup_lua import clean_env, digest, load_release_pin, require, verify_install
else:
    from check_asn1 import ROOT, load_pin
    from setup_lua import clean_env, digest, load_release_pin, require, verify_install

HOST = ROOT / "differential/lua/adapter_host.lua"
OPENTLV_ADAPTER = ROOT / "differential/lua/opentlv_adapter.lua"
ASN1_ADAPTER = ROOT / "differential/lua/asn1_adapter.lua"
DEFAULT_FIXTURES = ROOT / "differential/fixtures/seed.json"
ADAPTER_TIMEOUT = 60
MISMATCH_EXIT = 3  # Distinct from uncaught errors (1) and argparse usage errors (2).
SETUP_COMMAND = "python3 scripts/setup_lua.py --lua lua5.2"

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


class FixtureFailure(ValueError):
    """A run failure at a known fixture, so the failure report can record its input."""

    def __init__(self, message, fixture_id):
        super().__init__(message)
        self.fixture_id = fixture_id


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


def select_fixtures(fixtures, identifiers):
    if not identifiers:
        return fixtures
    unknown = sorted(set(identifiers) - {fixture["id"] for fixture in fixtures})
    require(not unknown, f"Unknown fixture: {', '.join(unknown)}")
    return [fixture for fixture in fixtures if fixture["id"] in identifiers]


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
        fixture_id = current_fixture(error.stdout, requests)
        raise FixtureFailure(f"{name} timed out at fixture {fixture_id}", fixture_id) from error
    if result.returncode != 0:
        fixture_id = current_fixture(result.stdout, requests)
        raise FixtureFailure(f"{name} failed ({result.returncode}) at fixture {fixture_id}: "
                             f"{result.stderr[-2000:]}", fixture_id)
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


def library_differences(fixture, results):
    """Return how each library differs from a shared fixture's expectation."""
    expected = fixture["expected"]
    wire_size = len(bytes.fromhex(fixture["wire"]))
    differences = {}
    for name, result in results.items():
        status = result["status"]
        if status == "unsupported":
            raise FixtureFailure(f"Fixture {fixture['id']} is shared, but {name} reports: {result.get('detail')}",
                                 fixture["id"])
        found = differences[name] = []
        if expected["result"] == "reject":
            # Error text and categories are never compared, only the declared framing rejection.
            if status != "rejected":
                found.append(f"{name}: expected rejection, observed acceptance")
        elif status != "accepted":
            found.append(f"{name}: expected acceptance, observed rejection: {result.get('detail')}")
        else:
            found.extend(tree_differences(name, expected["tree"], result["tree"]))
            if result.get("consumed") != wire_size:
                found.append(f"{name}: consumed {result.get('consumed')} of {wire_size} bytes")
    return differences


def classify(fixture, results):
    """Return (outcome, differences); eligibility comes from the fixture, not library behavior."""
    if fixture["classification"] != "shared":
        return fixture["classification"], []
    differences = [item for found in library_differences(fixture, results).values() for item in found]
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
        differing = [name for name, found in library_differences(fixture, observed).items() if found] \
            if outcome == "mismatch" else []
        results.append({"id": fixture["id"], "category": fixture.get("category"),
                        "description": fixture.get("description"), "operation": fixture["operation"],
                        "wire": bytes.fromhex(fixture["wire"]).hex(), "schema": fixture["schema"],
                        "classification": fixture["classification"], "expected": fixture.get("expected"),
                        "outcome": outcome, "reason": fixture.get("reason"), "differences": differences,
                        "differing_libraries": differing, "observed": observed})
    summary = {outcome: sum(r["outcome"] == outcome for r in results) for outcome in OUTCOMES}
    return {"schema": 1, "status": "mismatch" if summary["mismatch"] else "passed",
            "provenance": str(receipt["path"]), "runtime": receipt["runtime"],
            "platform": receipt["platform"], "packages": receipt["packages"], "reproduction": reproduction,
            "adapters": identities, "summary": summary, "fixtures": results}


def testlab_revision():
    """A commit alone cannot reproduce modified files, so the report says which case it is."""
    try:
        commit, status = (subprocess.run(["git", *command], cwd=ROOT, capture_output=True, text=True,
                                         check=True, timeout=30).stdout.strip()
                          for command in (["rev-parse", "HEAD"], ["status", "--porcelain"]))
    except (OSError, subprocess.SubprocessError):
        return {"commit": None, "modified": None}
    return {"commit": commit, "modified": bool(status)}


def describe_origin(corpus):
    path = corpus.resolve()
    return {"corpus": path.relative_to(ROOT).as_posix() if path.is_relative_to(ROOT) else str(path),
            "corpus_sha256": digest(path) if path.is_file() else None, "testlab": testlab_revision()}


def reproduction_steps(origin, identifiers=()):
    """Steps for a new checkout, so no path from the original machine's setup is needed."""
    command = ["python3", "scripts/run_differential.py", "--fixtures", origin["corpus"]]
    for identifier in identifiers:
        command += ["--fixture", identifier]
    commit = origin["testlab"]["commit"]
    return ([f"git checkout {commit}"] if commit else []) + [SETUP_COMMAND, shlex.join(command)]


def add_reproduction(report, origin, selected):
    report.update(origin)
    report["reproduce"] = reproduction_steps(origin, selected)
    for result in report["fixtures"]:
        if result["outcome"] == "mismatch":
            result["reproduce"] = reproduction_steps(origin, [result["id"]])


def failure_report(error, origin, fixtures, receipt, selected):
    """A run failure gives no verdict, but its error and any failing input stay reproducible."""
    report = {"schema": 1, "status": "failed", "error": str(error), **origin}
    if receipt:
        report.update({"provenance": str(receipt["path"]), "runtime": receipt["runtime"],
                       "platform": receipt["platform"], "packages": receipt["packages"]})
    fixture = next((f for f in fixtures if f["id"] == getattr(error, "fixture_id", None)), None)
    if fixture:
        report["failed_fixture"] = {"id": fixture["id"], "operation": fixture["operation"],
                                    "wire": bytes.fromhex(fixture["wire"]).hex(), "schema": fixture["schema"],
                                    "classification": fixture["classification"],
                                    "expected": fixture.get("expected")}
    report["reproduce"] = reproduction_steps(origin, [fixture["id"]] if fixture else selected)
    return report


def json_block(value):
    return ["```json", json.dumps(value, sort_keys=True), "```"]


def command_block(steps):
    return ["```sh", *steps, "```"]


def render_input(result):
    return [f"- Operation: `{result['operation']}`",
            f"- Input ({len(bytes.fromhex(result['wire']))} bytes): `{result['wire']}`"]


def render_mismatch(result):
    differing = result["differing_libraries"]
    met = [name for name in result["observed"] if name not in differing]
    triage = f"{', '.join(differing)} differs from the fixture; {', '.join(met)} meets it." if met else \
        "Every library differs from the fixture, so check the fixture first."
    lines = [f"### {result['id']}", ""]
    if result["description"]:
        lines += [result["description"], ""]
    lines += [*render_input(result), f"- Triage: {triage}", "", "Differences:", ""]
    lines += [f"- {difference}" for difference in result["differences"]]
    lines += ["", "Schema:", "", *json_block(result["schema"]), "", "Expected:", "", *json_block(result["expected"])]
    for name, observed in result["observed"].items():
        lines += ["", f"Observed by {name}:", "", *json_block(observed)]
    return lines + ["", f"Reproduce (exit code {MISMATCH_EXIT}):", "", *command_block(result["reproduce"]), ""]


def render_mismatches(report):
    mismatches = [r for r in report["fixtures"] if r["outcome"] == "mismatch"]
    if not mismatches:
        return []
    lines = ["## Mismatches: possible defects", "",
             "A library differs from a fixture declared comparable. Investigate each one: it can be a "
             "library defect, a documented limitation that should be declared `unsupported`, or a "
             "fixture error.", ""]
    for result in mismatches:
        lines += render_mismatch(result)
    return lines


def render_declared(report):
    declared = [r for r in report["fixtures"] if r["classification"] != "shared"]
    if not declared:
        return []
    names = list(declared[0]["observed"])
    lines = ["## Declared by the fixture: not defects", "",
             "These `unsupported` and `inconclusive` fixtures do not decide the run. Observations are "
             "retained in the JSON report.", "",
             "| Fixture | Outcome | " + " | ".join(names) + " | Reason |",
             "| --- | --- | " + "--- | " * len(names) + "--- |"]
    for result in declared:
        statuses = [result["observed"][name]["status"] for name in names]
        reason = result["reason"].replace("|", "\\|")
        lines.append(f"| {result['id']} | {result['outcome']} | " + " | ".join(statuses) + f" | {reason} |")
    return lines + [""]


def render_failure(report):
    lines = ["## Run failure: no verdict", "",
             "The run did not finish, so its results cannot be trusted. A crash or timeout at a "
             "fixture can still be a library defect.", "", "```text", report["error"], "```", ""]
    fixture = report.get("failed_fixture")
    if fixture:
        lines += [f"Failing fixture `{fixture['id']}`:", "", *render_input(fixture), "",
                  "Schema:", "", *json_block(fixture["schema"]), ""]
    return lines + ["Reproduce (exit code 1):", "", *command_block(report["reproduce"]), ""]


def render_report(report):
    lines = ["# Differential report", "", f"- Status: {report['status']}", f"- Corpus: `{report['corpus']}`",
             f"- Corpus SHA-256: `{report['corpus_sha256']}`"]
    testlab = report["testlab"]
    state = " with uncommitted changes, so the commit alone may not reproduce this" if testlab["modified"] else ""
    lines.append(f"- TestLab commit: `{testlab['commit'] or 'unknown'}`{state}")
    if "runtime" in report:
        platform = report["platform"]
        details = [platform.get(key) for key in ("system", "release", "machine")] + list(platform.get("libc", ()))
        lines += [f"- Runtime: {report['runtime']}", f"- Platform: {' '.join(str(d) for d in details if d)}"]
        for name, package in report["packages"].items():
            lines.append(f"- {name}: " + ", ".join(f"{key} {value}" for key, value in sorted(package.items())))
        lines.append(f"- Setup receipt: `{report['provenance']}`")
    if report["status"] == "failed":
        return "\n".join([*lines, "", *render_failure(report)])
    summary = ", ".join(f"{report['summary'][outcome]} {outcome}" for outcome in OUTCOMES)
    lines += [f"- Summary: {summary}", "", *render_mismatches(report), *render_declared(report)]
    return "\n".join(lines)


def write_reports(args, report):
    for path, text in ((args.output, json.dumps(report, indent=2, sort_keys=True) + "\n"),
                       (args.report, render_report(report))):
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")


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
    mismatches = render_mismatches(report)
    if mismatches:
        print("\n" + "\n".join(mismatches))


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, default=DEFAULT_FIXTURES)
    parser.add_argument("--provenance", type=Path, help="Setup receipt; default is the newest complete run")
    parser.add_argument("--runs-dir", type=Path, default=ROOT / "build/dependency-runs")
    parser.add_argument("--fixture", action="append", default=[], metavar="ID",
                        help="Run only this fixture; repeat for more")
    parser.add_argument("--output", type=Path, help="Also write all observations as JSON")
    parser.add_argument("--report", type=Path, help="Also write a Markdown report")
    args = parser.parse_args(arguments)
    origin = describe_origin(args.fixtures)
    fixtures, receipt = [], None
    try:
        corpus = load_corpus(args.fixtures)
        fixtures = select_fixtures(corpus["fixtures"], args.fixture)
        receipt = load_receipt((args.provenance or newest_receipt(args.runs_dir)).resolve())
        report = run_comparison(fixtures, receipt, corpus.get("reproduction"))
        # Selecting a declared fixture is a request to read its observations, not a verdict on a corpus.
        require(args.fixture or report["summary"]["pass"] + report["summary"]["mismatch"] > 0,
                "No shared fixture was compared")
        add_reproduction(report, origin, args.fixture)
        print_report(report)
        write_reports(args, report)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"Differential run failed: {error}", file=sys.stderr)
        try:
            write_reports(args, failure_report(error, origin, fixtures, receipt, args.fixture))
        except OSError as write_error:
            print(f"Could not write the failure report: {write_error}", file=sys.stderr)
        return 1
    return MISMATCH_EXIT if report["summary"]["mismatch"] else 0


if __name__ == "__main__":
    sys.exit(main())
