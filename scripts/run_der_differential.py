#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel

"""Compare OpenTLV Lua DER decoding and encoding with the asn1c reference against X.690."""

import argparse
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys

if __package__:
    from . import check_asn1c, run_differential as lua_runner, setup_asn1c as asn1c
    from .check_asn1 import ROOT
    from .setup_lua import digest, load_release_pin, require
else:
    import check_asn1c
    import run_differential as lua_runner
    import setup_asn1c as asn1c
    from check_asn1 import ROOT
    from setup_lua import digest, load_release_pin, require

TYPES = ROOT / "differential/der/TestLabReference-1.json"
DER_ADAPTER = ROOT / "differential/lua/opentlv_der_adapter.lua"
DEFAULT_FIXTURES = ROOT / "differential/fixtures/der-canonical.json"
MISMATCH_EXIT = 3
SETUP_COMMANDS = ["python3 scripts/setup_lua.py --lua lua5.2", "python3 scripts/setup_asn1c.py"]

LIBRARIES = ("opentlv", "asn1c")
RESULTS = ("canonical", "reject")
ERRORS = ("empty", "truncated", "trailing", "invalid")
CATEGORIES = ("primitive", "constructed", "nested", "tag-boundary", "length-boundary", "zero-length",
              "truncated", "malformed", "noncanonical")
# A limitation names one library operation; the checks it covers follow from it.
LIMITATIONS = ("opentlv.decode", "opentlv.encode", "asn1c.decode", "asn1c.encode")
CHECKS = {"canonical": ("opentlv.decode", "opentlv.round-trip", "opentlv.encode", "asn1c.decode",
                        "asn1c.encode", "interop.opentlv-to-asn1c", "interop.asn1c-to-opentlv"),
          "reject": ("opentlv.decode", "asn1c.decode")}
# The library operations each check exercises: a limitation of any of them limits the check.
DEPENDS = {"opentlv.decode": ("opentlv.decode",), "opentlv.round-trip": ("opentlv.decode", "opentlv.encode"),
           "opentlv.encode": ("opentlv.encode",), "asn1c.decode": ("asn1c.decode",),
           "asn1c.encode": ("asn1c.decode", "asn1c.encode"),
           "interop.opentlv-to-asn1c": ("opentlv.encode", "asn1c.decode"),
           "interop.asn1c-to-opentlv": ("asn1c.decode", "asn1c.encode", "opentlv.decode")}
# Where a declared limitation must show; one that does not is stale.
SHOWN_BY = {"opentlv.decode": ("opentlv.decode",), "opentlv.encode": ("opentlv.encode", "opentlv.round-trip"),
            "asn1c.decode": ("asn1c.decode",), "asn1c.encode": ("asn1c.encode",)}
OUTCOMES = ("pass", "fail", "limited", "not-run")
ASN1C_ERRORS = {"empty": "empty", "truncated": "truncated", "trailing": "trailing", "malformed": "invalid",
                "constraint": "invalid"}
LEAVES = ("boolean", "integer", "bit_string", "octet_string", "ia5string", "null", "object_identifier")
KINDS = LEAVES + ("sequence", "set", "sequence_of", "set_of", "choice", "explicit")
MAX_WIRE_BYTES = asn1c.MAX_WIRE_BYTES


class FramingError(ValueError):
    pass


# --- Type descriptions -------------------------------------------------------------------------

def identifier_number(identifier):
    """(class, number) of a minimal identifier, which is how X.690 orders SET components."""
    data = bytes.fromhex(identifier)
    if data[0] & 0x1F != 0x1F:
        return data[0] >> 6, data[0] & 0x1F
    number = 0
    for octet in data[1:]:
        number = number << 7 | octet & 0x7F
    return data[0] >> 6, number


def validate_identifier(identifier):
    require(isinstance(identifier, str) and re.fullmatch(r"([0-9a-f]{2})+", identifier), "Identifier must be hex")
    data = bytes.fromhex(identifier)
    if data[0] & 0x1F == 0x1F:
        require(len(data) > 1 and data[1] != 0x80 and all(o & 0x80 for o in data[1:-1]) and not data[-1] & 0x80,
                f"Identifier {identifier} is not a minimal high-tag form")
        require(identifier_number(identifier)[1] >= 31, f"Identifier {identifier} needs the low-tag form")
    else:
        require(len(data) == 1, f"Identifier {identifier} has trailing octets")


def resolve(schema, types, seen=()):
    """Inline type references, so the adapter receives one self-contained description."""
    require(isinstance(schema, dict), "Type description must be an object")
    if "ref" in schema:
        require(schema.keys() == {"ref"} and schema["ref"] in types and schema["ref"] not in seen,
                f"Invalid type reference: {schema.get('ref')}")
        return resolve(types[schema["ref"]], types, seen + (schema["ref"],))
    kind = schema.get("kind")
    require(kind in KINDS, f"Unknown kind: {kind}")
    resolved = dict(schema)
    if kind != "choice":
        validate_identifier(schema.get("identifier"))
        constructed = bool(bytes.fromhex(schema["identifier"])[0] & 0x20)
        require(constructed == (kind not in LEAVES), f"{kind} identifier {schema['identifier']} has the wrong form")
    if kind in LEAVES:
        require(schema.keys() == {"kind", "identifier"}, f"Unexpected {kind} fields")
    elif kind in ("sequence", "set"):
        require(schema.keys() == {"kind", "identifier", "fields"} and isinstance(schema["fields"], list),
                f"{kind} needs fields")
        resolved["fields"] = []
        for field in schema["fields"]:
            require(isinstance(field, dict) and {"name", "type"} <= field.keys() <=
                    {"name", "type", "optional", "default"} and isinstance(field["name"], str),
                    f"Invalid {kind} field")
            require(field.get("optional", True) is True and not ("optional" in field and "default" in field),
                    f"Field {field['name']} is either OPTIONAL or DEFAULT")
            entry = {**field, "type": resolve(field["type"], types, seen)}
            if "default" in field:
                asn1c.validate_value(field["default"])
            resolved["fields"].append(entry)
        tags = [f["type"].get("identifier") for f in resolved["fields"]]
        require(None not in tags and len(set(tags)) == len(tags), f"{kind} components need distinct tags")
    elif kind in ("sequence_of", "set_of"):
        require(schema.keys() == {"kind", "identifier", "item"}, f"{kind} needs an item")
        resolved["item"] = resolve(schema["item"], types, seen)
    elif kind == "choice":
        require(schema.keys() == {"kind", "alternatives"} and isinstance(schema["alternatives"], list),
                "choice needs alternatives")
        resolved["alternatives"] = [{"name": a["name"], "type": resolve(a["type"], types, seen)}
                                    for a in schema["alternatives"]]
        tags = [a["type"].get("identifier") for a in resolved["alternatives"]]
        require(None not in tags and len(set(tags)) == len(tags), "choice alternatives need distinct tags")
    else:
        require(schema.keys() == {"kind", "identifier", "inner"}, "explicit needs an inner type")
        resolved["inner"] = resolve(schema["inner"], types, seen)
    return resolved


def load_types(path=TYPES):
    data = json.loads(path.read_text(encoding="utf-8"))
    schema = asn1c.schema_identity()
    require(isinstance(data, dict) and data.keys() == {"schema", "module", "types"} and data["schema"] == 1,
            "Expected type description schema 1")
    require(data["module"] == schema["module"], "Type descriptions name a different schema module")
    require(list(data["types"]) == schema["types"], "Type descriptions must list the schema's types in order")
    return {name: resolve(value, data["types"], (name,)) for name, value in data["types"].items()}


# --- Independent DER encoder that checks hand-written fixtures ----------------------------------

def der_length(size):
    if size < 0x80:
        return bytes([size])
    octets = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(octets)]) + octets


def tlv(identifier, contents):
    return bytes.fromhex(identifier) + der_length(len(contents)) + contents


def leaf_contents(kind, value):
    if kind == "boolean":
        require(type(value["value"]) is bool, "BOOLEAN value must be true or false")
        return b"\xff" if value["value"] else b"\x00"
    if kind == "integer":
        require(isinstance(value["value"], str) and re.fullmatch(r"-?(0|[1-9][0-9]*)", value["value"]),
                "INTEGER value must be a decimal string")
        number = int(value["value"])
        return number.to_bytes((number + (number < 0)).bit_length() // 8 + 1, "big", signed=True)
    if kind == "null":
        return b""
    if kind == "object_identifier":
        require(re.fullmatch(r"[0-2](\.(0|[1-9][0-9]*))+", value["value"] or ""), "Invalid OBJECT IDENTIFIER")
        arcs = [int(arc) for arc in value["value"].split(".")]
        require(arcs[0] == 2 or arcs[1] < 40, "Second arc must be below 40 under arcs 0 and 1")
        contents = b""
        for arc in [arcs[0] * 40 + arcs[1], *arcs[2:]]:
            septets = [arc & 0x7F]
            while arc := arc >> 7:
                septets.append(0x80 | arc & 0x7F)
            contents += bytes(reversed(septets))
        return contents
    require(isinstance(value["value"], str) and re.fullmatch(r"([0-9a-f]{2})*", value["value"]),
            f"{kind} value must be lowercase hex")
    data = bytes.fromhex(value["value"])
    if kind == "bit_string":
        unused = value["unused_bits"]
        require(type(unused) is int and 0 <= unused <= 7 and (data or unused == 0) and
                (not data or data[-1] & ((1 << unused) - 1) == 0), "BIT STRING is not canonical")
        return bytes([unused]) + data
    if kind == "ia5string":
        require(all(octet < 0x80 for octet in data), "IA5String octets must be below 0x80")
    return data


def set_of_key(encoding, width):
    return encoding + b"\x00" * (width - len(encoding))


def der_encode(schema, value):
    """X.690 DER of a typed value; disagreement with a fixture's wire means the fixture is wrong."""
    kind = schema["kind"]
    if kind == "choice":
        require(value["kind"] == "choice", "Value is not a CHOICE")
        alternative = next((a for a in schema["alternatives"] if a["name"] == value["alternative"]), None)
        require(alternative, f"Unknown alternative {value['alternative']}")
        return der_encode(alternative["type"], value["value"])
    if kind == "explicit":
        return tlv(schema["identifier"], der_encode(schema["inner"], value))
    require(value["kind"] == kind, f"Value of kind {value['kind']} does not match {kind}")
    if kind in LEAVES:
        return tlv(schema["identifier"], leaf_contents(kind, value))
    if kind in ("sequence", "set"):
        names = [field["name"] for field in value["fields"]]
        definition = [field["name"] for field in schema["fields"]]
        require(names == [name for name in definition if name in names], f"{kind} fields out of definition order")
        given = {field["name"]: field["value"] for field in value["fields"]}
        parts = []
        for field in schema["fields"]:
            if field["name"] not in given:
                require("optional" in field or "default" in field, f"Missing component {field['name']}")
            elif given[field["name"]] != field.get("default"):  # DER omits a DEFAULT value (11.5).
                parts.append((identifier_number(field["type"]["identifier"]),
                              der_encode(field["type"], given[field["name"]])))
        if kind == "set":
            parts.sort(key=lambda part: part[0])  # Canonical tag order (10.3).
        return tlv(schema["identifier"], b"".join(part for _, part in parts))
    encodings = [der_encode(schema["item"], item) for item in value["items"]]
    if kind == "set_of":
        width = max(map(len, encodings), default=0)
        encodings.sort(key=lambda encoding: set_of_key(encoding, width))  # Ascending encodings (11.6).
    return tlv(schema["identifier"], b"".join(encodings))


def frame(wire):
    """Size of the first definite-length element; None when its length is not a definite count."""
    if not wire:
        raise FramingError("empty")
    index = 1
    if wire[0] & 0x1F == 0x1F:
        while index < len(wire) and wire[index] & 0x80:
            index += 1
        index += 1
    if index >= len(wire):
        raise FramingError("truncated")
    first = wire[index]
    index += 1
    if first < 0x80:
        size = first
    elif first in (0x80, 0xFF):
        return None
    else:
        count = first & 0x7F
        if index + count > len(wire):
            raise FramingError("truncated")
        size = int.from_bytes(wire[index:index + count], "big")
        index += count
    if index + size > len(wire):
        raise FramingError("truncated")
    return index + size


# --- Corpus ------------------------------------------------------------------------------------

def validate_fixture(fixture, types):
    require(isinstance(fixture, dict) and isinstance(fixture.get("id"), str) and
            re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", fixture["id"]), "Fixture id must be lowercase kebab-case")
    try:
        allowed = {"id", "category", "description", "rule", "type", "wire", "expected", "limitations"}
        require(fixture.keys() <= allowed and allowed - {"limitations"} <= fixture.keys(),
                "Fixture has unexpected or missing fields")
        require(fixture["category"] in CATEGORIES, f"Category must be: {', '.join(CATEGORIES)}")
        for key in ("description", "rule"):
            require(isinstance(fixture[key], str) and fixture[key].strip(), f"Fixture needs a {key}")
        require(fixture["type"] in types, f"Unknown schema type: {fixture['type']}")
        require(isinstance(fixture["wire"], str), "Wire must be a hex string")
        wire = bytes.fromhex(fixture["wire"])
        require(len(wire) <= MAX_WIRE_BYTES, f"Wire exceeds {MAX_WIRE_BYTES} bytes")
        expected = fixture["expected"]
        require(isinstance(expected, dict) and expected.get("result") in RESULTS,
                f"Expected result must be: {', '.join(RESULTS)}")
        if expected["result"] == "canonical":
            require(expected.keys() == {"result", "value"}, "A canonical fixture expects only its value")
            asn1c.validate_value(expected["value"])
            require(der_encode(types[fixture["type"]], expected["value"]) == wire,
                    "Wire is not the DER encoding of the expected value")
        else:
            require(expected.keys() == {"result", "error"} and expected["error"] in ERRORS,
                    f"A rejection expects one error: {', '.join(ERRORS)}")
            try:
                size = frame(wire)
            except FramingError as error:
                require(str(error) == expected["error"], f"Wire has a {error} root, not {expected['error']}")
            else:
                require(expected["error"] in ("trailing", "invalid") and
                        (size is None or (size < len(wire)) == (expected["error"] == "trailing")),
                        f"Wire framing contradicts the expected {expected['error']} error")
        limitations = fixture.get("limitations", {})
        require(isinstance(limitations, dict) and limitations.keys() <= set(LIMITATIONS),
                f"Limitations name: {', '.join(LIMITATIONS)}")
        require(all(isinstance(reason, str) and reason.strip() for reason in limitations.values()),
                "Each limitation needs a reason")
        if expected["result"] == "reject":
            require(not {"opentlv.encode", "asn1c.encode"} & limitations.keys(),
                    "A rejection has no encode check to limit")
            require(not {"opentlv.decode", "asn1c.decode"} <= limitations.keys(), "No library would be judged")
        else:
            require(set(LIMITATIONS) != limitations.keys(), "No library would be judged")
    except (ValueError, KeyError, TypeError) as error:
        raise ValueError(f"Fixture {fixture['id']}: {error}") from error


def validate_reproduction(metadata):
    require(isinstance(metadata, dict) and metadata.keys() == {"command", "runtime", "schema", "packages"},
            "Reproduction metadata needs command, runtime, schema and packages")
    require(metadata["packages"] == {"opentlv": load_release_pin()["version"], "asn1c": asn1c.load_pin()["version"]},
            "Corpus was verified against different package versions")
    require(metadata["schema"] == asn1c.schema_identity()["module"], "Corpus was verified against another schema")


def load_corpus(path, types=None):
    types = types or load_types()
    corpus = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(corpus, dict) and corpus.get("schema") == 1 and corpus.keys() <= {"schema", "reproduction",
                                                                                        "fixtures"},
            "Expected fixture schema 1")
    fixtures = corpus.get("fixtures")
    require(isinstance(fixtures, list) and fixtures, "Fixture list must not be empty")
    for fixture in fixtures:
        validate_fixture(fixture, types)
    identifiers = [fixture["id"] for fixture in fixtures]
    require(len(set(identifiers)) == len(identifiers), "Fixture ids must be unique")
    if "reproduction" in corpus:
        validate_reproduction(corpus["reproduction"])
    return corpus


# --- Receipts and adapters ---------------------------------------------------------------------

def load_receipts(lua_path, asn1c_path):
    lua = lua_runner.load_receipt(lua_path)
    report, pin, schema = check_asn1c.load_receipt(asn1c_path)
    require(report.get("capabilities", {}).get("sha256") == digest(asn1c.CAPABILITIES),
            "The asn1c setup audited other capability probes; run scripts/setup_asn1c.py again")
    opentlv = {**lua["adapters"]["opentlv"], "script": DER_ADAPTER}
    release = lua["packages"]["opentlv"]
    return {"lua": lua, "opentlv": opentlv, "asn1c": {"path": report["adapter"]["path"],
                                                     "identity": asn1c.adapter_identity(pin, schema)},
            "paths": {"lua": str(lua_path), "asn1c": str(asn1c_path)},
            "runtime": lua["runtime"], "platform": lua["platform"],
            "compiler": report["configuration"]["compiler"]["version"],
            "packages": {"opentlv": release, "asn1c": {"version": pin["version"], "commit": pin["commit"],
                                                       "schema": schema["module"]}}}


def check_der_record(name, request, record):
    if request["operation"] == "encode":
        require(record.keys() == {"id", "encode"}, f"{name} returned no encoding for {request['id']}")
    else:
        status = record.get("status")
        require(status in ("accepted", "rejected"), f"{name} returned status {status}")
        if status == "accepted":
            asn1c.validate_value(record.get("value"))
            require(isinstance(record.get("encode"), dict), f"{name} did not re-encode {request['id']}")
        else:
            require(record.get("error") in ERRORS and record.get("source") in ("opentlv", "adapter"),
                    f"{name} returned an unknown rejection")
    encode = record.get("encode")
    require(encode is None or encode.get("status") in ("encoded", "failed", "unsupported"),
            f"{name} returned an unknown encode status")


def run_opentlv(receipts, requests, reproduction=None):
    if not requests:
        return []
    identity, records = lua_runner.run_adapter("opentlv", receipts["opentlv"], receipts["lua"]["lua"], requests,
                                               check=check_der_record)
    if reproduction:
        require(identity.get("runtime") == reproduction["runtime"],
                f"Corpus was verified on {reproduction['runtime']}, not {identity.get('runtime')}")
    return records


def run_asn1c(receipts, requests):
    if not requests:
        return []
    probes = [{"id": r["id"], "type": r["type"], "decode": "der", "encode": "der", "wire": r["wire"]}
              for r in requests]
    return asn1c.run_adapter(receipts["asn1c"]["path"], probes, receipts["asn1c"]["identity"])


# --- Verdicts ----------------------------------------------------------------------------------

def asn1c_verdict(record, wire):
    """asn1c decodes DER as BER, so its DER verdict also requires the canonical re-encoding."""
    decode = record["decode"]
    if decode["status"] == "rejected":
        return {"status": "rejected", "error": ASN1C_ERRORS[decode["error"]], "native": decode["error"]}
    require(decode["status"] == "accepted", f"asn1c reports DER decoding as {decode['status']}")
    encode = record["encode"]
    if encode["status"] != "encoded":
        return {"status": "undecided", "detail": f"re-encoding {encode['status']}"}
    if encode["wire"] != wire:
        return {"status": "rejected", "error": "invalid", "native": "noncanonical", "canonical": encode["wire"]}
    return {"status": "accepted"}


def compare_value(expected, observed, what):
    return None if observed == expected else f"{what}: expected {json.dumps(expected, sort_keys=True)}, " \
                                               f"observed {json.dumps(observed, sort_keys=True)}"


def decoded(record, value, name):
    if record is None:
        return "no input to decode"
    if record.get("status") != "accepted":
        return f"{name} rejected it: {record.get('error')} {record.get('detail') or ''}".rstrip()
    return compare_value(value, record["value"], f"{name} value")


def encoded(encode, wire, name):
    if encode is None:
        return f"{name} produced no encoding"
    if encode["status"] != "encoded":
        return f"{name} encoding {encode['status']}: {encode.get('detail')}"
    return None if encode["wire"] == wire else f"{name} encoded {encode['wire']}, expected {wire}"


def canonical_checks(fixture, observed):
    value, wire = fixture["expected"]["value"], bytes.fromhex(fixture["wire"]).hex()
    opentlv, reference = observed["opentlv"], observed["asn1c"]
    reference_decode = reference["decode"]
    produced = observed.get("opentlv.encode", {}).get("encode")
    return {
        "opentlv.decode": decoded(opentlv, value, "OpenTLV"),
        "opentlv.round-trip": "OpenTLV decoded no value" if opentlv["status"] != "accepted" else
        encoded(opentlv["encode"], wire, "OpenTLV re-encoding"),
        "opentlv.encode": encoded(produced, wire, "OpenTLV"),
        "asn1c.decode": decoded(reference_decode, value, "asn1c"),
        "asn1c.encode": "asn1c decoded no value" if reference_decode["status"] != "accepted" else
        encoded(reference.get("encode"), wire, "asn1c re-encoding"),
        "interop.opentlv-to-asn1c": decoded(observed.get("interop.asn1c", {}).get("decode"), value, "asn1c"),
        "interop.asn1c-to-opentlv": decoded(observed.get("interop.opentlv"), value, "OpenTLV"),
    }


def reject_checks(fixture, observed):
    error = fixture["expected"]["error"]
    opentlv, verdict = observed["opentlv"], observed["asn1c.verdict"]
    if opentlv["status"] == "accepted":
        mine = "OpenTLV accepted it"
    elif opentlv["source"] != "opentlv":
        mine = f"only the TestLab adapter rejected it: {opentlv.get('detail')}"
    else:
        mine = None if opentlv["error"] == error else f"OpenTLV error {opentlv['error']}, expected {error}"
    if verdict["status"] != "rejected":
        theirs = f"asn1c DER verdict {verdict['status']}"
    else:
        theirs = None if verdict["error"] == error else f"asn1c error {verdict['error']}, expected {error}"
    return {"opentlv.decode": mine, "asn1c.decode": theirs}


def evaluate(fixture, observed):
    """Each check against the X.690 expectation; a declared limitation keeps its observation."""
    limitations = fixture.get("limitations", {})
    result = fixture["expected"]["result"]
    differences = canonical_checks(fixture, observed) if result == "canonical" else reject_checks(fixture, observed)
    for key in limitations:
        # A limitation that does not show is a stale claim about a library, so the run cannot trust it.
        require(any(differences.get(name) for name in SHOWN_BY[key]),
                f"Fixture {fixture['id']}: declared limitation {key} did not occur")
    checks = {}
    for name in CHECKS[result]:
        difference = differences[name]
        limited = [key for key in DEPENDS[name] if key in limitations]
        if limited:
            checks[name] = {"outcome": "limited", "limitations": limited, "difference": difference}
        elif difference == "no input to decode":
            checks[name] = {"outcome": "not-run", "reason": "the producing encoder gave no encoding"}
        else:
            checks[name] = {"outcome": "fail" if difference else "pass", "difference": difference}
    outcome = "mismatch" if any(check["outcome"] == "fail" for check in checks.values()) else "pass"
    return outcome, checks


def run_comparison(fixtures, types, receipts, reproduction=None):
    schemas = {name: types[name] for name in {fixture["type"] for fixture in fixtures}}
    wires = {f["id"]: bytes.fromhex(f["wire"]).hex() for f in fixtures}
    canonical = [f for f in fixtures if f["expected"]["result"] == "canonical"]
    first = [{"id": f["id"], "operation": "decode", "wire": wires[f["id"]], "schema": schemas[f["type"]]}
             for f in fixtures]
    first += [{"id": f["id"] + "/encode", "operation": "encode", "value": f["expected"]["value"],
               "schema": schemas[f["type"]]} for f in canonical]
    opentlv = dict(zip((r["id"] for r in first), run_opentlv(receipts, first, reproduction)))
    reference = dict(zip(wires, run_asn1c(receipts, [{"id": f["id"], "type": f["type"], "wire": wires[f["id"]]}
                                                      for f in fixtures])))
    # Each library decodes what the other encoded: OpenTLV's encoding and asn1c's re-encoding.
    to_asn1c, to_opentlv = [], []
    for fixture in canonical:
        produced = opentlv[fixture["id"] + "/encode"]["encode"]
        if produced["status"] == "encoded":
            to_asn1c.append({"id": fixture["id"], "type": fixture["type"], "wire": produced["wire"]})
        reencoded = reference[fixture["id"]].get("encode", {})
        if reencoded.get("status") == "encoded":
            to_opentlv.append({"id": fixture["id"] + "/from-asn1c", "operation": "decode",
                               "wire": reencoded["wire"], "schema": schemas[fixture["type"]]})
    cross_asn1c = dict(zip((r["id"] for r in to_asn1c), run_asn1c(receipts, to_asn1c)))
    cross_opentlv = dict(zip((r["id"] for r in to_opentlv), run_opentlv(receipts, to_opentlv)))
    results = []
    for fixture in fixtures:
        identifier = fixture["id"]
        observed = {"opentlv": opentlv[identifier], "asn1c": reference[identifier]}
        if fixture["expected"]["result"] == "canonical":
            observed["opentlv.encode"] = opentlv[identifier + "/encode"]
            if identifier in cross_asn1c:
                observed["interop.asn1c"] = cross_asn1c[identifier]
            if identifier + "/from-asn1c" in cross_opentlv:
                observed["interop.opentlv"] = cross_opentlv[identifier + "/from-asn1c"]
        else:
            observed["asn1c.verdict"] = asn1c_verdict(reference[identifier], wires[identifier])
        outcome, checks = evaluate(fixture, observed)
        results.append({"id": identifier, "category": fixture["category"], "description": fixture["description"],
                        "rule": fixture["rule"], "type": fixture["type"], "wire": wires[identifier],
                        "expected": fixture["expected"], "limitations": fixture.get("limitations", {}),
                        "outcome": outcome, "checks": checks, "observed": observed})
    return {"schema": 1, "status": "mismatch" if any(r["outcome"] == "mismatch" for r in results) else "passed",
            "provenance": receipts["paths"], "runtime": receipts["runtime"], "platform": receipts["platform"],
            "compiler": receipts["compiler"], "packages": receipts["packages"], "reproduction": reproduction,
            "summary": summarize(results), "fixtures": results}


def denominators(fixtures):
    """For each check: the fixtures it applies to and how many of them judge it, before any run."""
    counts = {}
    for fixture in fixtures:
        limitations = fixture.get("limitations", {})
        for name in CHECKS[fixture["expected"]["result"]]:
            entry = counts.setdefault(name, {"applies": 0, "judged": 0})
            entry["applies"] += 1
            entry["judged"] += not any(key in limitations for key in DEPENDS[name])
    return dict(sorted(counts.items()))


def summarize(results):
    """Coverage denominators: how many checks each library was judged on, and the outcomes."""
    checks = {}
    for result in results:
        for name, check in result["checks"].items():
            counts = checks.setdefault(name, {outcome: 0 for outcome in OUTCOMES})
            counts[check["outcome"]] += 1
    for counts in checks.values():
        counts["judged"] = counts["pass"] + counts["fail"]
    categories = {}
    for result in results:
        entry = categories.setdefault(result["category"], {"fixtures": 0, "pass": 0, "mismatch": 0})
        entry["fixtures"] += 1
        entry[result["outcome"]] += 1
    return {"fixtures": len(results), "pass": sum(r["outcome"] == "pass" for r in results),
            "mismatch": sum(r["outcome"] == "mismatch" for r in results),
            "results": {name: sum(r["expected"]["result"] == name for r in results) for name in RESULTS},
            "limited_fixtures": sum(bool(r["limitations"]) for r in results),
            "checks": dict(sorted(checks.items())), "categories": dict(sorted(categories.items()))}


# --- Reports -----------------------------------------------------------------------------------

def reproduction_steps(origin, identifiers=()):
    command = ["python3", "scripts/run_der_differential.py", "--fixtures", origin["corpus"]]
    for identifier in identifiers:
        command += ["--fixture", identifier]
    commit = origin["testlab"]["commit"]
    return ([f"git checkout {commit}"] if commit else []) + SETUP_COMMANDS + [shlex.join(command)]


def add_reproduction(report, origin, selected):
    report.update(origin)
    report["reproduce"] = reproduction_steps(origin, selected)
    for result in report["fixtures"]:
        if result["outcome"] == "mismatch":
            result["reproduce"] = reproduction_steps(origin, [result["id"]])


CELL = {"pass": "pass", "fail": "**FAIL**", "limited": "limited", "not-run": "not run"}


def render_matrix(report):
    names = list(dict.fromkeys(name for r in report["fixtures"] for name in r["checks"]))
    lines = ["## Outcome matrix", "", "`limited` is a declared limitation of that library; its observation is kept "
             "in the JSON report and never counts as a pass.", "",
             "| Fixture | Expected | " + " | ".join(f"`{n}`" for n in names) + " |",
             "|" + " --- |" * (len(names) + 2)]
    for result in report["fixtures"]:
        expected = result["expected"]
        label = "canonical" if expected["result"] == "canonical" else f"reject {expected['error']}"
        cells = [CELL[result["checks"][n]["outcome"]] if n in result["checks"] else "—" for n in names]
        lines.append(f"| {result['id']} | {label} | " + " | ".join(cells) + " |")
    return lines + [""]


def render_coverage(report):
    lines = ["## Coverage", "", "| Check | Judged | Pass | Fail | Limited | Not run |",
             "| --- | --- | --- | --- | --- | --- |"]
    for name, counts in report["summary"]["checks"].items():
        lines.append(f"| `{name}` | {counts['judged']} | {counts['pass']} | {counts['fail']} | {counts['limited']} "
                     f"| {counts['not-run']} |")
    lines += ["", "| Category | Fixtures | Pass | Mismatch |", "| --- | --- | --- | --- |"]
    for name, counts in report["summary"]["categories"].items():
        lines.append(f"| {name} | {counts['fixtures']} | {counts['pass']} | {counts['mismatch']} |")
    return lines + [""]


def render_mismatches(report):
    mismatches = [r for r in report["fixtures"] if r["outcome"] == "mismatch"]
    if not mismatches:
        return []
    lines = ["## Mismatches: possible defects", "",
             "A judged check differs from the X.690 expectation. It can be a defect in that library, an "
             "undeclared limitation or a fixture error; neither library is the specification.", ""]
    for result in mismatches:
        failed = [name for name, check in result["checks"].items() if check["outcome"] == "fail"]
        lines += [f"### {result['id']}", "", result["description"], "", f"- Rule: {result['rule']}",
                  f"- Type: `{result['type']}`", f"- Input: `{result['wire'] or '(empty)'}`",
                  f"- Failed checks: {', '.join(f'`{name}`' for name in failed)}", ""]
        lines += [f"- `{name}`: {result['checks'][name]['difference']}" for name in failed]
        lines += ["", "Expected:", "", "```json", json.dumps(result["expected"], sort_keys=True), "```", "",
                  f"Reproduce (exit code {MISMATCH_EXIT}):", "", "```sh", *result["reproduce"], "```", ""]
    return lines


def render_limitations(report):
    limited = [r for r in report["fixtures"] if r["limitations"]]
    if not limited:
        return []
    lines = ["## Declared limitations: not defects", "",
             "Each declared limitation was observed in this run; a limitation that no longer shows fails the run.",
             "", "| Fixture | Limitation | Observed | Reason |", "| --- | --- | --- | --- |"]
    for result in limited:
        for key, reason in result["limitations"].items():
            observed = "; ".join(result["checks"][name]["difference"] for name in SHOWN_BY[key]
                                 if result["checks"].get(name, {}).get("difference"))
            cells = [text.replace("|", "\\|") for text in (observed, reason)]
            lines.append(f"| {result['id']} | `{key}` | {cells[0]} | {cells[1]} |")
    return lines + [""]


def render_report(report):
    testlab = report["testlab"]
    state = " with uncommitted changes, so the commit alone may not reproduce this" if testlab["modified"] else ""
    lines = ["# DER differential report", "", f"- Status: {report['status']}", f"- Corpus: `{report['corpus']}`",
             f"- Corpus SHA-256: `{report['corpus_sha256']}`",
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
    lines += [f"- Summary: {summary['pass']} pass, {summary['mismatch']} mismatch of {summary['fixtures']} "
              f"fixtures ({summary['results']['canonical']} canonical, {summary['results']['reject']} rejected); "
              f"{summary['limited_fixtures']} declare a limitation", ""]
    return "\n".join([*lines, *render_mismatches(report), *render_coverage(report), *render_matrix(report),
                      *render_limitations(report)])


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
        limited = ", ".join(result["limitations"])
        print(f"{result['outcome']:<9} {result['id']}" + (f" (limited: {limited})" if limited else ""))
        for name, check in result["checks"].items():
            if check["outcome"] == "fail":
                print(f"          {name}: {check['difference']}")
    summary = report["summary"]
    print(f"{summary['pass']} pass, {summary['mismatch']} mismatch of {summary['fixtures']} fixtures")
    for name, counts in summary["checks"].items():
        print(f"  {name}: {counts['pass']} of {counts['judged']} judged pass, {counts['limited']} limited")


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
        types = load_types()
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
        print(f"DER differential run failed: {error}", file=sys.stderr)
        try:
            write_reports(args, {"schema": 1, "status": "failed", "error": str(error), **origin,
                                 "reproduce": reproduction_steps(origin, args.fixture)})
        except OSError as write_error:
            print(f"Could not write the failure report: {write_error}", file=sys.stderr)
        return 1
    return MISMATCH_EXIT if report["summary"]["mismatch"] else 0


if __name__ == "__main__":
    sys.exit(main())
