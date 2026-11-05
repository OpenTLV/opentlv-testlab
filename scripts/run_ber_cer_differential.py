#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel

"""Compare OpenTLV Lua BER and CER interoperability with the asn1c reference against X.690."""

import argparse
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys

if __package__:
    from . import check_asn1c, run_der_differential as der, run_differential as lua_runner, x690
    from .check_asn1 import ROOT
    from .setup_lua import load_release_pin, require
else:
    import check_asn1c
    import run_der_differential as der
    import run_differential as lua_runner
    import x690
    from check_asn1 import ROOT
    from setup_lua import load_release_pin, require

ADAPTER = ROOT / "differential/lua/opentlv_ber_cer_adapter.lua"
DEFAULT_FIXTURES = ROOT / "differential/fixtures/ber-cer-interop.json"
# Earlier corpora a fixture may reuse bytes from: the BER comparison with lua-asn1 (#1) and the DER one (#21).
ORIGINS = {"asn1-ber": ROOT / "differential/fixtures/asn1-ber.json", "der-canonical": der.DEFAULT_FIXTURES}
MISMATCH_EXIT = 3
SETUP_COMMANDS = der.SETUP_COMMANDS
RUNNER = "run_ber_cer_differential.py"

ENCODINGS = ("ber", "cer")
RESULTS = {"ber": ("accept", "reject"), "cer": ("canonical", "reject")}
ERRORS = der.ERRORS
CATEGORIES = ("primitive", "constructed", "nested", "tag-boundary", "length-boundary", "indefinite-length",
              "end-of-contents", "alternate-form", "segmented", "truncated", "malformed", "noncanonical")
OPERATIONS = ("opentlv.decode", "opentlv.encode", "asn1c.decode", "asn1c.encode")
CHECKS = {"accept": ("opentlv.decode", "opentlv.encode", "asn1c.decode", "asn1c.encode",
                     "interop.opentlv-to-asn1c", "interop.asn1c-to-opentlv"),
          "canonical": der.CHECKS["canonical"],
          "reject": ("opentlv.decode", "asn1c.decode")}
DEPENDS = {**der.DEPENDS, "opentlv.encode": ("opentlv.encode",)}
SHOWN_BY = der.SHOWN_BY
OUTCOMES = ("pass", "mismatch", "confirmed", "limitation", "not-comparable", "inconclusive")
# What asn1c cannot do for CER whatever the fixture, from its capability audit; each run confirms it.
CER_ENCODE_LIMITATION = "asn1c has no CER encoder; asn_encode() fails with ENOENT (capability probe cer-encode)"
CER_DECODE_NOT_COMPARABLE = ("asn1c decodes CER with its BER decoder, which accepts this valid BER form "
                             "(capability probe cer-form-as-ber)")
ISSUE = re.compile(r"https://github\.com/OpenTLV/[\w.-]+/issues/\d+")
MAX_WIRE_BYTES = der.MAX_WIRE_BYTES


# --- Corpus ------------------------------------------------------------------------------------

def load_origins():
    corpora = {}
    for name, path in ORIGINS.items():
        corpus = json.loads(path.read_text(encoding="utf-8"))
        corpora[name] = {fixture["id"]: bytes.fromhex(fixture["wire"]) for fixture in corpus["fixtures"]}
    return corpora


def validate_expectation(fixture, schema, wire):
    """The hand-written expectation must agree with the independent X.690 reference."""
    encoding, expected = fixture["encoding"], fixture["expected"]
    require(isinstance(expected, dict) and expected.get("result") in RESULTS[encoding],
            f"A {encoding} fixture expects: {', '.join(RESULTS[encoding])}")
    if expected["result"] == "reject":
        require(expected.keys() == {"result", "error"} and expected["error"] in ERRORS,
                f"A rejection expects one error: {', '.join(ERRORS)}")
        try:
            value = x690.decode(schema, wire, encoding)
        except x690.Invalid as error:
            require(error.error == expected["error"], f"X.690 reference reports {error}, not {expected['error']}")
        else:
            raise ValueError(f"X.690 reference decodes it as {json.dumps(value, sort_keys=True)}")
        return
    require(expected.keys() == {"result", "value"}, f"A {expected['result']} fixture expects only its value")
    der.asn1c.validate_value(expected["value"])
    if encoding == "cer":
        require(x690.cer_encode(schema, expected["value"]) == wire, "Wire is not the CER encoding of the value")
    try:
        value = x690.decode(schema, wire, encoding)
    except x690.Invalid as error:
        raise ValueError(f"X.690 reference rejects the wire: {error}") from error
    require(value == expected["value"], f"X.690 reference decodes {json.dumps(value, sort_keys=True)}")


def validate_declarations(fixture):
    declared = {}
    for key in ("limitations", "not_comparable", "confirmed"):
        entries = fixture.get(key, {})
        names = CHECKS[fixture["expected"]["result"]] if key == "confirmed" else OPERATIONS
        require(isinstance(entries, dict) and entries and entries.keys() <= set(names) if key in fixture else True,
                f"{key} name: {', '.join(names)}")
        require(all(isinstance(reason, str) and reason.strip() for reason in entries.values()),
                f"Each {key} entry needs a reason")
        for name in entries:
            require(name not in declared, f"{name} is declared twice")
            declared[name] = key
    for name, reason in fixture.get("confirmed", {}).items():
        require(ISSUE.search(reason), f"Confirmed mismatch {name} must link the OpenTLV issue that tracks it")
    # A confirmed mismatch is still judged; only a limitation or a not-comparable library is not.
    unjudged = {name for name, key in declared.items() if key != "confirmed"}
    if fixture["expected"]["result"] == "reject":
        require(not {"opentlv.encode", "asn1c.encode"} & declared.keys(), "A rejection has no encode check to limit")
        require(not {"opentlv.decode", "asn1c.decode"} <= unjudged, "No library would be judged")
    else:
        require(not set(OPERATIONS) <= unjudged, "No library would be judged")
    if fixture["encoding"] == "cer":
        require("asn1c.encode" not in declared, "asn1c's missing CER encoder is declared by the runner")


def validate_fixture(fixture, types, origins=None):
    require(isinstance(fixture, dict) and isinstance(fixture.get("id"), str) and
            re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", fixture["id"]), "Fixture id must be lowercase kebab-case")
    try:
        required = {"id", "encoding", "category", "description", "rule", "type", "wire", "expected"}
        allowed = required | {"origin", "limitations", "not_comparable", "confirmed"}
        require(required <= fixture.keys() <= allowed, "Fixture has unexpected or missing fields")
        require(fixture["encoding"] in ENCODINGS, f"Encoding must be: {', '.join(ENCODINGS)}")
        require(fixture["category"] in CATEGORIES, f"Category must be: {', '.join(CATEGORIES)}")
        for key in ("description", "rule"):
            require(isinstance(fixture[key], str) and fixture[key].strip(), f"Fixture needs a {key}")
        require(fixture["type"] in types, f"Unknown schema type: {fixture['type']}")
        require(isinstance(fixture["wire"], str), "Wire must be a hex string")
        wire = bytes.fromhex(fixture["wire"])
        require(len(wire) <= MAX_WIRE_BYTES, f"Wire exceeds {MAX_WIRE_BYTES} bytes")
        validate_expectation(fixture, types[fixture["type"]], wire)
        validate_declarations(fixture)
        if structural(fixture, types)[1]:
            require("asn1c.decode" not in fixture.get("not_comparable", {}) | fixture.get("limitations", {}),
                    "asn1c's BER reading of a valid BER form is declared by the runner")
        if "origin" in fixture:
            corpus, _, identifier = str(fixture["origin"]).partition(":")
            origins = origins or load_origins()
            require(corpus in origins and identifier in origins[corpus],
                    f"Origin must name a fixture of {', '.join(ORIGINS)}")
            require(origins[corpus][identifier] == wire, f"Wire differs from its origin {fixture['origin']}")
    except (ValueError, KeyError, TypeError, IndexError) as error:
        raise ValueError(f"Fixture {fixture['id']}: {error}") from error


def validate_reproduction(metadata):
    require(isinstance(metadata, dict) and metadata.keys() == {"command", "runtime", "schema", "packages"},
            "Reproduction metadata needs command, runtime, schema and packages")
    require(metadata["packages"] == {"opentlv": load_release_pin()["version"],
                                     "asn1c": der.asn1c.load_pin()["version"]},
            "Corpus was verified against different package versions")
    require(metadata["schema"] == der.asn1c.schema_identity()["module"], "Corpus was verified against another schema")


def load_corpus(path, types=None):
    types = types or der.load_types()
    corpus = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(corpus, dict) and corpus.get("schema") == 1 and
            corpus.keys() <= {"schema", "reproduction", "fixtures"}, "Expected fixture schema 1")
    fixtures = corpus.get("fixtures")
    require(isinstance(fixtures, list) and fixtures, "Fixture list must not be empty")
    origins = load_origins()
    for fixture in fixtures:
        validate_fixture(fixture, types, origins)
    identifiers = [fixture["id"] for fixture in fixtures]
    require(len(set(identifiers)) == len(identifiers), "Fixture ids must be unique")
    if "reproduction" in corpus:
        validate_reproduction(corpus["reproduction"])
    return corpus


def ber_valid(fixture, types):
    """A CER rejection that is still valid BER, which asn1c's BER decoder cannot tell apart."""
    try:
        x690.decode(types[fixture["type"]], bytes.fromhex(fixture["wire"]), "ber")
    except x690.Invalid:
        return False
    return True


def structural(fixture, types):
    """Classifications that follow from the encoding, not from the fixture: asn1c and CER."""
    if fixture["encoding"] != "cer":
        return {}, {}
    if fixture["expected"]["result"] == "canonical":
        return {"asn1c.encode": CER_ENCODE_LIMITATION}, {}
    return {}, ({"asn1c.decode": CER_DECODE_NOT_COMPARABLE} if ber_valid(fixture, types) else {})


def declarations(fixture, types):
    limitations, not_comparable = structural(fixture, types)
    return ({**limitations, **fixture.get("limitations", {})},
            {**not_comparable, **fixture.get("not_comparable", {})}, fixture.get("confirmed", {}))


# --- Adapters ----------------------------------------------------------------------------------

def load_receipts(lua_path, asn1c_path):
    receipts = der.load_receipts(lua_path, asn1c_path)
    receipts["opentlv"] = {**receipts["opentlv"], "script": ADAPTER}
    return receipts


def run_opentlv(receipts, requests, reproduction=None):
    return der.run_opentlv(receipts, requests, reproduction)


def run_asn1c(receipts, requests):
    """asn1c decodes BER and CER with its BER decoder; it re-encodes BER as DER and tries CER."""
    if not requests:
        return []
    probes = [{"id": r["id"], "type": r["type"], "decode": "ber", "encode": r["encode"], "wire": r["wire"]}
              for r in requests]
    return der.asn1c.run_adapter(receipts["asn1c"]["path"], probes, receipts["asn1c"]["identity"])


# --- Verdicts ----------------------------------------------------------------------------------

def logical(value):
    """The logical value: SET OF is unordered (X.680 28), so its items compare in a fixed order."""
    if not isinstance(value, dict):
        return value
    normal = {key: logical(item) if isinstance(item, dict) else item for key, item in value.items()}
    if "fields" in value:
        normal["fields"] = [{"name": f["name"], "value": logical(f["value"])} for f in value["fields"]]
    if "items" in value:
        items = [logical(item) for item in value["items"]]
        normal["items"] = sorted(items, key=lambda i: json.dumps(i, sort_keys=True)) \
            if value.get("kind") == "set_of" else items
    return normal


def compare_value(expected, observed, what):
    if logical(observed) == logical(expected):
        return None
    return f"{what}: expected {json.dumps(expected, sort_keys=True)}, observed {json.dumps(observed, sort_keys=True)}"


def decoded(record, value, name):
    if record is None:
        return "no input to decode"
    if record.get("status") != "accepted":
        return f"{name} rejected it: {record.get('error')} {record.get('detail') or ''}".rstrip()
    return compare_value(value, record["value"], f"{name} value")


def canonical_checks(fixture, observed):
    """CER is canonical, so encoders are compared byte for byte: one type, one logical value."""
    value, wire = fixture["expected"]["value"], bytes.fromhex(fixture["wire"]).hex()
    opentlv, reference = observed["opentlv"], observed["asn1c"]
    reference_decode = reference["decode"]
    produced = observed.get("opentlv.encode", {}).get("encode")
    return {
        "opentlv.decode": decoded(opentlv, value, "OpenTLV"),
        "opentlv.round-trip": "OpenTLV decoded no value" if opentlv["status"] != "accepted" else
        der.encoded(opentlv["encode"], wire, "OpenTLV re-encoding"),
        "opentlv.encode": der.encoded(produced, wire, "OpenTLV"),
        "asn1c.decode": decoded(reference_decode, value, "asn1c"),
        "asn1c.encode": "asn1c decoded no value" if reference_decode["status"] != "accepted" else
        der.encoded(reference.get("encode"), wire, "asn1c re-encoding"),
        "interop.opentlv-to-asn1c": decoded(observed.get("interop.asn1c", {}).get("decode"), value, "asn1c"),
        "interop.asn1c-to-opentlv": decoded(observed.get("interop.opentlv"), value, "OpenTLV"),
    }


def reference_reads(schema, encode, value, name):
    """A BER encoder passes when the X.690 reference reads its output as the value, whatever its form."""
    if encode is None:
        return f"{name} produced no encoding"
    if encode["status"] != "encoded":
        return f"{name} encoding {encode['status']}: {encode.get('detail')}"
    try:
        found = x690.decode(schema, bytes.fromhex(encode["wire"]), "ber")
    except x690.Invalid as error:
        return f"{name} encoded {encode['wire']}, which is not BER of the value: {error}"
    return compare_value(value, found, f"{name} encoding {encode['wire']} has value")


def accept_checks(fixture, observed, schema):
    value = fixture["expected"]["value"]
    opentlv, reference = observed["opentlv"], observed["asn1c"]
    reference_decode = reference["decode"]
    return {
        "opentlv.decode": decoded(opentlv, value, "OpenTLV"),
        "opentlv.encode": reference_reads(schema, observed.get("opentlv.encode", {}).get("encode"), value,
                                          "OpenTLV"),
        "asn1c.decode": decoded(reference_decode, value, "asn1c"),
        "asn1c.encode": "asn1c decoded no value" if reference_decode["status"] != "accepted" else
        reference_reads(schema, reference.get("encode"), value, "asn1c re-encoding"),
        "interop.opentlv-to-asn1c": decoded(observed.get("interop.asn1c", {}).get("decode"), value, "asn1c"),
        "interop.asn1c-to-opentlv": decoded(observed.get("interop.opentlv"), value, "OpenTLV"),
    }


def reject_checks(fixture, observed):
    error = fixture["expected"]["error"]
    opentlv, decode = observed["opentlv"], observed["asn1c"]["decode"]
    if opentlv["status"] == "accepted":
        mine = "OpenTLV accepted it"
    elif opentlv["source"] != "opentlv":
        mine = f"only the TestLab adapter rejected it: {opentlv.get('detail')}"
    else:
        mine = None if opentlv["error"] == error else f"OpenTLV error {opentlv['error']}, expected {error}"
    require(decode["status"] in ("accepted", "rejected"), f"asn1c reports BER decoding as {decode['status']}")
    if decode["status"] == "accepted":
        theirs = "asn1c accepted it"
    else:
        normalized = der.ASN1C_ERRORS[decode["error"]]
        theirs = None if normalized == error else f"asn1c error {normalized}, expected {error}"
    return {"opentlv.decode": mine, "asn1c.decode": theirs}


def check_structural(fixture, observed, types):
    """A classification the runner declares must still hold, or the run cannot trust it."""
    limitations, not_comparable = structural(fixture, types)
    if "asn1c.encode" in limitations:
        status = observed["asn1c"].get("encode", {}).get("status")
        require(observed["asn1c"]["decode"]["status"] != "accepted" or status == "unsupported",
                f"Fixture {fixture['id']}: asn1c encoded CER ({status}); revisit the cer-encode probe")
    if "asn1c.decode" in not_comparable:
        require(observed["asn1c"]["decode"]["status"] == "accepted",
                f"Fixture {fixture['id']}: asn1c rejected valid BER; add it as a BER fixture and triage it")


def classify(name, difference, limitations, not_comparable, confirmed):
    limited = [key for key in DEPENDS[name] if key in limitations]
    incomparable = [key for key in DEPENDS[name] if key in not_comparable]
    if name in confirmed:
        return {"outcome": "confirmed", "issue": ISSUE.search(confirmed[name]).group(0), "difference": difference}
    if limited:
        return {"outcome": "limitation", "limitations": limited, "difference": difference}
    if incomparable:
        return {"outcome": "not-comparable", "not_comparable": incomparable, "difference": difference}
    if difference in ("no input to decode", "OpenTLV produced no encoding"):
        return {"outcome": "inconclusive", "reason": "the producing encoder gave no encoding",
                "difference": difference}
    return {"outcome": "mismatch" if difference else "pass", "difference": difference}


def evaluate(fixture, observed, types):
    """Each check against the X.690 expectation; a declared classification keeps its observation."""
    result = fixture["expected"]["result"]
    schema = types[fixture["type"]]
    differences = accept_checks(fixture, observed, schema) if result == "accept" else \
        reject_checks(fixture, observed) if result == "reject" else \
        canonical_checks(fixture, observed)
    check_structural(fixture, observed, types)
    limitations, not_comparable, confirmed = declarations(fixture, types)
    for key in {**fixture.get("limitations", {}), **fixture.get("not_comparable", {})}:
        # A declaration that does not show is a stale claim about a library, so the run cannot trust it.
        require(any(differences.get(name) for name in SHOWN_BY[key]),
                f"Fixture {fixture['id']}: declared {key} did not occur")
    for name in confirmed:
        require(differences[name], f"Fixture {fixture['id']}: confirmed mismatch {name} no longer occurs")
    checks = {name: classify(name, differences[name], limitations, not_comparable, confirmed)
              for name in CHECKS[result]}
    outcomes = {check["outcome"] for check in checks.values()}
    outcome = "mismatch" if "mismatch" in outcomes else "confirmed" if "confirmed" in outcomes else "pass"
    return outcome, checks


def run_comparison(fixtures, types, receipts, reproduction=None):
    schemas = {name: types[name] for name in {fixture["type"] for fixture in fixtures}}
    wires = {f["id"]: bytes.fromhex(f["wire"]).hex() for f in fixtures}
    valued = [f for f in fixtures if f["expected"]["result"] != "reject"]
    first = [{"id": f["id"], "operation": "decode", "encoding": f["encoding"], "wire": wires[f["id"]],
              "schema": schemas[f["type"]]} for f in fixtures]
    first += [{"id": f["id"] + "/encode", "operation": "encode", "encoding": f["encoding"],
               "value": f["expected"]["value"], "schema": schemas[f["type"]]} for f in valued]
    opentlv = dict(zip((r["id"] for r in first), run_opentlv(receipts, first, reproduction)))
    reference = dict(zip(wires, run_asn1c(receipts, [
        {"id": f["id"], "type": f["type"], "wire": wires[f["id"]], "encode": "der" if f["encoding"] == "ber" else "cer"}
        for f in fixtures])))
    # Each library decodes what the other encoded; asn1c re-encodes BER as DER and cannot write CER.
    to_asn1c, to_opentlv = [], []
    for fixture in valued:
        produced = opentlv[fixture["id"] + "/encode"]["encode"]
        if produced["status"] == "encoded":
            to_asn1c.append({"id": fixture["id"], "type": fixture["type"], "wire": produced["wire"], "encode": "none"})
        reencoded = reference[fixture["id"]].get("encode", {})
        if fixture["encoding"] == "ber" and reencoded.get("status") == "encoded":
            to_opentlv.append({"id": fixture["id"] + "/from-asn1c", "operation": "decode", "encoding": "ber",
                               "wire": reencoded["wire"], "schema": schemas[fixture["type"]]})
    cross_asn1c = dict(zip((r["id"] for r in to_asn1c), run_asn1c(receipts, to_asn1c)))
    cross_opentlv = dict(zip((r["id"] for r in to_opentlv), run_opentlv(receipts, to_opentlv)))
    results = []
    for fixture in fixtures:
        identifier = fixture["id"]
        observed = {"opentlv": opentlv[identifier], "asn1c": reference[identifier]}
        if fixture["expected"]["result"] != "reject":
            observed["opentlv.encode"] = opentlv[identifier + "/encode"]
            if identifier in cross_asn1c:
                observed["interop.asn1c"] = cross_asn1c[identifier]
            if identifier + "/from-asn1c" in cross_opentlv:
                observed["interop.opentlv"] = cross_opentlv[identifier + "/from-asn1c"]
        outcome, checks = evaluate(fixture, observed, types)
        limitations, not_comparable, confirmed = declarations(fixture, types)
        results.append({"id": identifier, "encoding": fixture["encoding"], "category": fixture["category"],
                        "description": fixture["description"], "rule": fixture["rule"], "type": fixture["type"],
                        "wire": wires[identifier], "expected": fixture["expected"],
                        "origin": fixture.get("origin"), "limitations": limitations,
                        "not_comparable": not_comparable, "confirmed": confirmed,
                        "outcome": outcome, "checks": checks, "observed": observed})
    return {"schema": 1, "runner": RUNNER,
            "status": "mismatch" if any(r["outcome"] == "mismatch" for r in results) else "passed",
            "provenance": receipts["paths"], "runtime": receipts["runtime"], "platform": receipts["platform"],
            "compiler": receipts["compiler"], "packages": receipts["packages"], "reproduction": reproduction,
            "summary": summarize(results), "fixtures": results}


def denominators(fixtures, types):
    """For each encoding and check: the fixtures it applies to and how many judge it, before any run."""
    counts = {}
    for fixture in fixtures:
        limitations, not_comparable, confirmed = declarations(fixture, types)
        for name in CHECKS[fixture["expected"]["result"]]:
            entry = counts.setdefault(fixture["encoding"], {}).setdefault(name, {"applies": 0, "judged": 0})
            entry["applies"] += 1
            entry["judged"] += name not in confirmed and not any(
                key in limitations or key in not_comparable for key in DEPENDS[name])
    return {encoding: dict(sorted(checks.items())) for encoding, checks in sorted(counts.items())}


def summarize(results):
    """Coverage with explicit denominators: per encoding and check, how often each outcome occurred."""
    checks, categories = {}, {}
    for result in results:
        for name, check in result["checks"].items():
            counts = checks.setdefault(result["encoding"], {}).setdefault(name, dict.fromkeys(OUTCOMES, 0))
            counts[check["outcome"]] += 1
        entry = categories.setdefault(result["category"], {"fixtures": 0, "pass": 0, "mismatch": 0, "confirmed": 0})
        entry["fixtures"] += 1
        entry[result["outcome"]] += 1
    for encoding in checks.values():
        for counts in encoding.values():
            counts["judged"] = counts["pass"] + counts["mismatch"] + counts["confirmed"]
            counts["applies"] = sum(counts[outcome] for outcome in OUTCOMES)
    totals = {}
    for encoding in checks.values():
        for counts in encoding.values():
            for key, count in counts.items():
                totals[key] = totals.get(key, 0) + count
    origins = sorted({r["origin"].partition(":")[0] for r in results if r["origin"]})
    return {"fixtures": len(results), "pass": sum(r["outcome"] == "pass" for r in results),
            "mismatch": sum(r["outcome"] == "mismatch" for r in results),
            "confirmed": sum(r["outcome"] == "confirmed" for r in results),
            "encodings": {encoding: {result: sum(r["encoding"] == encoding and r["expected"]["result"] == result
                                                 for r in results) for result in RESULTS[encoding]}
                          for encoding in ENCODINGS},
            "reused": {name: sum((r["origin"] or "").startswith(name + ":") for r in results) for name in origins},
            "checks": {encoding: dict(sorted(names.items())) for encoding, names in sorted(checks.items())},
            "outcomes": totals, "coverage": percent(totals.get("judged", 0), totals.get("applies", 0)),
            "categories": dict(sorted(categories.items()))}


def percent(part, whole):
    return round(100 * part / whole, 1) if whole else 0.0


# --- Reports -----------------------------------------------------------------------------------

def reproduction_steps(origin, identifiers=()):
    command = ["python3", "scripts/" + RUNNER, "--fixtures", origin["corpus"]]
    for identifier in identifiers:
        command += ["--fixture", identifier]
    commit = origin["testlab"]["commit"]
    return ([f"git checkout {commit}"] if commit else []) + SETUP_COMMANDS + [shlex.join(command)]


def add_reproduction(report, origin, selected):
    report.update(origin)
    report["reproduce"] = reproduction_steps(origin, selected)
    for result in report["fixtures"]:
        if result["outcome"] in ("mismatch", "confirmed"):
            result["reproduce"] = reproduction_steps(origin, [result["id"]])


CELL = {"pass": "pass", "mismatch": "**MISMATCH**", "confirmed": "confirmed", "limitation": "limitation",
        "not-comparable": "not comparable", "inconclusive": "inconclusive"}


def cell(text):
    return str(text).replace("|", "\\|")


def label(expected):
    return expected["result"] if expected["result"] != "reject" else f"reject {expected['error']}"


def render_matrix(report):
    lines = ["## Outcome matrix", "",
             "Only `pass`, `mismatch` and `confirmed` are judged. `limitation`, `not comparable` and `inconclusive` "
             "keep their observation in the JSON report and never count as a pass.", ""]
    for encoding in ENCODINGS:
        results = [r for r in report["fixtures"] if r["encoding"] == encoding]
        if not results:
            continue
        names = list(dict.fromkeys(name for r in results for name in r["checks"]))
        lines += [f"### {encoding.upper()}", "", "| Fixture | Expected | " + " | ".join(f"`{n}`" for n in names) + " |",
                  "|" + " --- |" * (len(names) + 2)]
        for result in results:
            cells = [CELL[result["checks"][n]["outcome"]] if n in result["checks"] else "—" for n in names]
            lines.append(f"| {result['id']} | {label(result['expected'])} | " + " | ".join(cells) + " |")
        lines.append("")
    return lines


def render_coverage(report):
    summary = report["summary"]
    totals = summary["outcomes"]
    lines = ["## Coverage", "",
             f"{totals.get('judged', 0)} of {totals.get('applies', 0)} checks were judged ({summary['coverage']}%). "
             "A check is judged unless a declared limitation, a not-comparable reference or a missing input "
             "removes it; missing functionality never counts as a defect.", "",
             "| Encoding | Check | Applies | Judged | Pass | Mismatch | Confirmed | Limitation | Not comparable "
             "| Inconclusive |", "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for encoding, checks in summary["checks"].items():
        for name, counts in checks.items():
            lines.append(f"| {encoding} | `{name}` | {counts['applies']} | {counts['judged']} "
                         f"({percent(counts['judged'], counts['applies'])}%) | " +
                         " | ".join(str(counts[o]) for o in OUTCOMES) + " |")
    lines += ["", "| Category | Fixtures | Pass | Mismatch | Confirmed |", "| --- | --- | --- | --- | --- |"]
    for name, counts in summary["categories"].items():
        lines.append(f"| {name} | {counts['fixtures']} | {counts['pass']} | {counts['mismatch']} | "
                     f"{counts['confirmed']} |")
    if summary["reused"]:
        lines += ["", "Fixtures reusing earlier evidence: " +
                  ", ".join(f"{count} from `{name}`" for name, count in summary["reused"].items()) + "."]
    return lines + [""]


def render_findings(report, outcome, title, intro):
    found = [r for r in report["fixtures"] if any(c["outcome"] == outcome for c in r["checks"].values())]
    if not found:
        return []
    lines = [title, "", intro, ""]
    for result in found:
        names = [name for name, check in result["checks"].items() if check["outcome"] == outcome]
        lines += [f"### {result['id']}", "", result["description"], "", f"- Encoding: {result['encoding'].upper()}",
                  f"- Rule: {result['rule']}", f"- Type: `{result['type']}`",
                  f"- Input: `{result['wire'] or '(empty)'}`", f"- Checks: {', '.join(f'`{n}`' for n in names)}", ""]
        for name in names:
            check = result["checks"][name]
            issue = f" ({check['issue']})" if "issue" in check else ""
            lines.append(f"- `{name}`{issue}: {check['difference']}")
        lines += ["", "Expected:", "", "```json", json.dumps(result["expected"], sort_keys=True), "```", ""]
        if "reproduce" in result:
            lines += [f"Reproduce (exit code {MISMATCH_EXIT if outcome == 'mismatch' else 0}):", "", "```sh",
                      *result["reproduce"], "```", ""]
    return lines


def render_declared(report):
    rows = []
    for result in report["fixtures"]:
        for kind, entries in (("limitation", result["limitations"]), ("not comparable", result["not_comparable"])):
            for key, reason in entries.items():
                observed = "; ".join(result["checks"][name]["difference"] for name in SHOWN_BY[key]
                                     if result["checks"].get(name, {}).get("difference"))
                rows.append(f"| {result['id']} | {kind} | `{key}` | {cell(observed or '—')} | {cell(reason)} |")
    if not rows:
        return []
    return ["## Limitations and not-comparable cases: not defects", "",
            "Each was observed in this run; a declaration that no longer shows fails the run.", "",
            "| Fixture | Classification | Operation | Observed | Reason |", "| --- | --- | --- | --- | --- |",
            *rows, ""]


def render_report(report):
    testlab = report["testlab"]
    state = " with uncommitted changes, so the commit alone may not reproduce this" if testlab["modified"] else ""
    lines = ["# BER and CER differential report", "", f"- Status: {report['status']}",
             f"- Corpus: `{report['corpus']}`", f"- Corpus SHA-256: `{report['corpus_sha256']}`",
             f"- TestLab commit: `{testlab['commit'] or 'unknown'}`{state}"]
    if "runtime" in report:
        platform = report["platform"]
        details = [platform.get(key) for key in ("system", "release", "machine")] + list(platform.get("libc", ()))
        lines += [f"- Runtime: {report['runtime']}; compiler: {report['compiler']}",
                  f"- Platform: {' '.join(str(d) for d in details if d)}"]
        for name, package in report["packages"].items():
            lines.append(f"- {name}: " + ", ".join(f"{key} {value}" for key, value in sorted(package.items())))
        lines.append(f"- Setup receipts: `{report['provenance']['lua']}`, `{report['provenance']['asn1c']}`")
    if report["status"] == "failed":
        return "\n".join([*lines, "", "## Run failure: no verdict", "", "```text", report["error"], "```", "",
                          "Reproduce (exit code 1):", "", "```sh", *report["reproduce"], "```", ""])
    summary = report["summary"]
    shape = "; ".join(f"{encoding.upper()} " + ", ".join(f"{count} {result}" for result, count in results.items())
                      for encoding, results in summary["encodings"].items())
    lines += [f"- Summary: {summary['pass']} pass, {summary['mismatch']} mismatch, {summary['confirmed']} confirmed "
              f"of {summary['fixtures']} fixtures ({shape})", ""]
    return "\n".join([
        *lines,
        *render_findings(report, "mismatch", "## Mismatches: possible defects",
                         "A judged check differs from the X.690 expectation. It can be a defect in that library, an "
                         "undeclared limitation or a fixture error; neither library is the specification."),
        *render_findings(report, "confirmed", "## Bugs: confirmed mismatches",
                         "Triaged defects, each tracked by the linked issue; they do not fail the run."),
        *render_coverage(report), *render_matrix(report), *render_declared(report)])


def write_reports(args, report):
    for path, render in ((args.output, lambda: json.dumps(report, indent=2, sort_keys=True) + "\n"),
                         (args.report, lambda: render_report(report))):
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(render(), encoding="utf-8")


def print_report(report):
    packages = report["packages"]
    print(f"{report['runtime']}; OpenTLV {packages['opentlv']['version']}; asn1c {packages['asn1c']['version']} "
          f"({packages['asn1c']['schema']})")
    for result in report["fixtures"]:
        print(f"{result['outcome']:<9} {result['encoding']} {result['id']}")
        for name, check in result["checks"].items():
            if check["outcome"] in ("mismatch", "confirmed"):
                print(f"          {name}: {check['difference']}")
    summary = report["summary"]
    print(f"{summary['pass']} pass, {summary['mismatch']} mismatch, {summary['confirmed']} confirmed "
          f"of {summary['fixtures']} fixtures")
    totals = summary["outcomes"]
    print(f"  {totals.get('judged', 0)} of {totals.get('applies', 0)} checks judged ({summary['coverage']}%): " +
          ", ".join(f"{totals.get(o, 0)} {o}" for o in OUTCOMES))


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, default=DEFAULT_FIXTURES)
    parser.add_argument("--fixture", action="append", default=[], metavar="ID",
                        help="Run only this fixture; repeat for more")
    parser.add_argument("--lua-runs-dir", type=Path, default=ROOT / "build/dependency-runs")
    parser.add_argument("--lua-provenance", type=Path, help="Lua setup receipt; default is the newest complete one")
    parser.add_argument("--asn1c-runs-dir", type=Path, default=ROOT / "build/asn1c-runs")
    parser.add_argument("--asn1c-provenance", type=Path, help="asn1c setup receipt; default is the newest passed one")
    parser.add_argument("--output", type=Path, help="Also write all observations as JSON")
    parser.add_argument("--report", type=Path, help="Also write a Markdown report")
    args = parser.parse_args(arguments)
    origin = lua_runner.describe_origin(args.fixtures)
    try:
        types = der.load_types()
        corpus = load_corpus(args.fixtures, types)
        fixtures = lua_runner.select_fixtures(corpus["fixtures"], args.fixture)
        receipts = load_receipts(
            (args.lua_provenance or lua_runner.newest_receipt(args.lua_runs_dir)).resolve(),
            (args.asn1c_provenance or check_asn1c.newest_receipt(args.asn1c_runs_dir)).resolve())
        report = run_comparison(fixtures, types, receipts, corpus.get("reproduction"))
        add_reproduction(report, origin, args.fixture)
        print_report(report)
        write_reports(args, report)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"BER and CER differential run failed: {error}", file=sys.stderr)
        try:
            write_reports(args, {"schema": 1, "runner": RUNNER, "status": "failed", "error": str(error), **origin,
                                 "reproduce": reproduction_steps(origin, args.fixture)})
        except OSError as write_error:
            print(f"Could not write the failure report: {write_error}", file=sys.stderr)
        return 1
    return MISMATCH_EXIT if report["summary"]["mismatch"] else 0


if __name__ == "__main__":
    sys.exit(main())
