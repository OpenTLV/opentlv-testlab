#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel

"""Compare reviewed BER/DER bytes through Core and der-parser against X.690."""

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile

if __package__:
    from . import check_rust_reference as reference, setup_rust_differential as setup
    from .run_differential import testlab_revision
    from .setup_lua import digest, require, write_json
else:
    import check_rust_reference as reference
    import setup_rust_differential as setup
    from run_differential import testlab_revision
    from setup_lua import digest, require, write_json

ROOT = reference.ROOT
REPORTS = ROOT / "build/rust-reports"
OUTCOMES = ("pass", "mismatch", "unsupported", "inconclusive")
APIS = {"core": {"ber": "tlv_format_decode(tlv_format_ber); tlv_ber_tag_number",
                 "der": "tlv_der_read_strict; tlv_format_decode(tlv_format_der); tlv_ber_tag_number"},
        "der-parser": {"ber": "parse_ber_recursive(fuel=32)", "der": "parse_der_recursive(fuel=32)"}}


def wire_tree(nodes, wire):
    """Project library-supplied ranges; never invoke the X.690 parser on observations."""
    require(isinstance(nodes, list) and 0 < len(nodes) <= 256, "missing/oversized adapter tree")
    position = 0

    def visit(start, depth):
        nonlocal position
        require(position < len(nodes), "incomplete adapter tree")
        raw = nodes[position]
        position += 1
        require(set(raw) == {"offset", "size", "tag_size", "value_offset", "value_size", "depth",
                             "number", "class", "constructed"}, "invalid node fields")
        for key in ("offset", "size", "tag_size", "value_offset", "value_size", "depth", "class"):
            require(type(raw[key]) is int and raw[key] >= 0, "invalid node range")
        require(raw["offset"] == start and raw["depth"] == depth <= 16, "invalid tree order/depth")
        require(type(raw["constructed"]) is bool and raw["class"] in range(4) and
                isinstance(raw["number"], str) and re.fullmatch(r"0|[1-9][0-9]*", raw["number"]),
                "invalid node identity")
        tag_end = start + raw["tag_size"]
        value_start, value_end = raw["value_offset"], raw["value_offset"] + raw["value_size"]
        end = start + raw["size"]
        require(start < tag_end < value_start <= value_end <= end <= len(wire), "node outside input")
        length = wire[tag_end:value_start]
        indefinite = length == b"\x80"
        require((indefinite and end == value_end + 2 and wire[value_end:end] == b"\0\0") or
                (not indefinite and end == value_end), "invalid trailer range")
        require(not indefinite or raw["constructed"], "primitive indefinite observation")
        require(len(length) == (1 if length[0] <= 128 else 1 + (length[0] & 127)) and length[0] != 255,
                "invalid length range")
        children = []
        child_start = value_start
        if raw["constructed"]:
            while child_start < value_end:
                child, child_start = visit(child_start, depth + 1)
                require(child_start <= value_end, "child outside parent")
                children.append(child)
        node = {"class": ("universal", "application", "context", "private")[raw["class"]],
                "number": raw["number"], "constructed": raw["constructed"],
                "identifier_hex": wire[start:tag_end].hex(),
                "length": {"form": "indefinite" if indefinite else "long" if length[0] > 128 else "short",
                           "value": None if indefinite else str(raw["value_size"]), "encoded_hex": length.hex()},
                "value_hex": wire[value_start:value_end].hex(), "children": children}
        return node, end

    tree, consumed = visit(0, 0)
    require(position == len(nodes) and consumed == len(wire), "incomplete or extra tree nodes")
    return tree


def normalize(name, fixture, record):
    require(isinstance(record, dict), "adapter output is not an object")
    result = record.get("result")
    require(result in ("accept", "reject", "unsupported"), "invalid adapter result")
    encoding = fixture["encoding"]
    checks = ["single-root", "framing", "wire-tree"]
    if encoding == "der":
        checks.append("recursive-DER-framing-and-primitive-contents" if name == "core" else
                      "generic-DER-root-checks; nested-SEQUENCE/SET-use-BER")
    out = {"schema": 1, "contract": "rust-ber-der-1", "fixture": fixture["id"], "encoding": encoding,
           "participant": name, "api": APIS[name][encoding], "checks": checks,
           "result": result, "consumed": None, "tree": None, "error": None, "reason": None}
    if result == "accept":
        require(set(record) == {"result", "consumed", "nodes"}, "invalid accept fields")
        wire = bytes.fromhex(fixture["wire"])
        require(type(record["consumed"]) is int and record["consumed"] == len(wire), "invalid consumed size")
        out.update(consumed=len(wire), tree=wire_tree(record["nodes"], wire))
    elif result == "reject":
        require(set(record) == {"result", "error"}, "invalid reject fields")
        error = record["error"]
        require(isinstance(error, dict) and set(error) == {"category", "source", "stage", "native_code", "offset"},
                "invalid adapter error")
        require(error["category"] in ("empty", "truncated", "trailing", "invalid", "limit", "unknown") and
                error["source"] in ("library", "adapter", "policy") and
                error["stage"] in ("framing", "contents", "canonicality", "schema", "policy", "unknown") and
                (error["native_code"] is None or isinstance(error["native_code"], str)) and
                (error["offset"] is None or type(error["offset"]) is int and error["offset"] >= 0),
                "invalid error category/provenance")
        out["error"] = error
    else:
        require(set(record) == {"result", "reason"} and isinstance(record["reason"], str) and record["reason"],
                "unsupported result lacks reason")
        out["reason"] = record["reason"]
    return out


def run_adapter(name, fixture, binary):
    wire = bytes.fromhex(fixture["wire"])
    require(len(wire) <= 4096, "input budget exceeded")
    command = [sys.executable, str(ROOT / "scripts/rust_adapter_process.py"), str(binary),
               fixture["encoding"], wire.hex()]
    # Windows wrapper gives its child five seconds; allow wrapper startup/cleanup separately.
    timeout = 7 if os.name == "nt" else 5
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.run(command, cwd=ROOT, stdout=stdout, stderr=stderr, timeout=timeout)
        require(process.returncode == 0, f"{name}: adapter process failed ({process.returncode})")
        require(stdout.tell() <= 1024 * 1024 and stderr.tell() == 0, f"{name}: unexpected output size/stderr")
        stdout.seek(0)
        record = json.loads(stdout.read())
    return normalize(name, fixture, record)


def classify(fixture, observed):
    differences = []
    unknown = []
    expected = fixture["expected"]
    for name, result in observed.items():
        if result["result"] in ("unsupported", "inconclusive"):
            unknown.append(name + ": " + result["reason"])
        elif result["result"] == "reject" and result["error"]["category"] == "unknown":
            unknown.append(name + ": native error category has no justified mapping")
        elif result["result"] != expected["result"]:
            differences.append(f"{name}: expected {expected['result']}, observed {result['result']}")
        elif result["result"] == "accept" and result["tree"] != expected["tree"]:
            differences.append(name + ": wire tree differs from the independent expectation")
        elif result["result"] == "reject" and result["error"]["category"] != expected["error"]:
            differences.append(f"{name}: expected error {expected['error']}, observed {result['error']['category']}")
    if fixture["classification"] != "shared":
        return fixture["classification"], differences, [fixture["reason"], *unknown]
    # A missing previously declared shared capability is also a failing mismatch.
    # An unclassifiable error is inconclusive, and the gate rejects that loss of evidence.
    if any(o["result"] == "unsupported" for o in observed.values()):
        return "mismatch", [*differences, *unknown], ["declared shared capability was unavailable"]
    return ("mismatch" if differences else "inconclusive" if unknown else "pass"), differences, unknown


def coverage(fixtures):
    result = {}
    for encoding in ("ber", "der", "all"):
        rows = [f for f in fixtures if encoding == "all" or f["encoding"] == encoding]
        shared = [f for f in rows if f["classification"] == "shared"]
        passed = sum(f["outcome"] == "pass" for f in shared)
        result[encoding] = {"executed": len(rows), "shared": len(shared), "shared_pass": passed,
                            "shared_pass_percent": round(100 * passed / len(shared), 2) if shared else None,
                            "outcomes": {s: sum(f["outcome"] == s for f in rows) for s in OUTCOMES}}
    return result


def render(report):
    lines = ["# Core / der-parser differential", "", f"Status: **{report['status']}**", "",
             "Committed reviewed inputs only. Agreement is scoped to the listed checks; it is not full conformance.",
             "Rust binding execution and exposure are not tested (#31).", ""]
    if report.get("error"):
        lines += ["Run failure: " + report["error"], ""]
    lines += ["| Encoding | Executed | Shared | Shared pass | Shared pass % |",
              "| --- | ---: | ---: | ---: | ---: |"]
    for name, data in report.get("coverage", {}).items():
        lines.append(f"| {name} | {data['executed']} | {data['shared']} | {data['shared_pass']} | {data['shared_pass_percent']} |")
    lines += ["", "| Fixture | Outcome | Reason / differences |", "| --- | --- | --- |"]
    for row in report["fixtures"]:
        detail = "; ".join(row["differences"] + row["reasons"]).replace("|", "\\|")
        lines.append(f"| {row['id']} | {row['outcome']} | {detail} |")
    lines += ["", "The JSON companion preserves each wire input, rule, expectation, normalized observations,",
              "native errors, exact versions, build receipt, implementation hashes and reproduction commands.",
              "Mismatches require triage; this report does not label a confirmed defect.", ""]
    return "\n".join(lines)


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provenance", type=Path, default=setup.RECEIPT)
    parser.add_argument("--fixture", action="append", default=[])
    parser.add_argument("--output", type=Path, default=REPORTS / "comparison.json")
    parser.add_argument("--report", type=Path, default=REPORTS / "comparison.md")
    args = parser.parse_args(arguments)
    report = {"schema": 1, "runner": "run_rust_differential.py", "status": "failed", "fixtures": [],
              "testlab": testlab_revision(), "provenance": str(args.provenance.resolve())}
    active = None
    try:
        corpus = reference.load_json(reference.CORPUS)
        reference.verify_corpus(corpus, reference.load_json(reference.MATRIX))
        require(corpus["limits"] == {"max_input_bytes": 4096, "max_depth": 16, "max_elements": 256,
                                      "timeout_seconds": 5, "process_memory_mib": 256}, "execution limits changed")
        fixtures = corpus["fixtures"]
        identifiers = set(args.fixture)
        require(identifiers <= {f["id"] for f in fixtures}, "unknown fixture selection")
        if identifiers:
            fixtures = [f for f in fixtures if f["id"] in identifiers]
        receipt = setup.load_receipt(args.provenance)
        report.update(packages=receipt["packages"], runtime=receipt["runtime"], setup=receipt,
                      corpus_sha256=digest(reference.CORPUS), limits=corpus["limits"],
                      memory_enforcement="Windows Job process commit" if os.name == "nt" else "Linux RLIMIT_AS")
        for fixture in fixtures:
            active = fixture["id"]
            observed = {name: run_adapter(name, fixture, Path(receipt["binaries"][name]["path"]))
                        for name in ("core", "der-parser")}
            outcome, differences, reasons = classify(fixture, observed)
            command = [sys.executable, "scripts/run_rust_differential.py", "--fixture", active]
            row = {**fixture, "observed": observed, "outcome": outcome, "differences": differences,
                   "reasons": reasons, "reproduce": ["python3 scripts/setup_rust_differential.py", shlex.join(command)]}
            report["fixtures"].append(row)
        report["coverage"] = coverage(report["fixtures"])
        incomplete = any(f["classification"] == "shared" and f["outcome"] == "inconclusive" for f in report["fixtures"])
        report["status"] = "failed" if incomplete else "mismatch" if any(f["outcome"] == "mismatch" for f in report["fixtures"]) else "passed"
        if incomplete:
            report["error"] = "shared scenario has inconclusive evidence"
        code = {"passed": 0, "mismatch": 3, "failed": 1}[report["status"]]
    except (OSError, ValueError, KeyError, TypeError, IndexError, subprocess.SubprocessError) as error:
        report.update(status="failed", error=str(error), active_fixture=active)
        code = 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    write_json(args.output, report)
    args.report.write_text(render(report), encoding="utf-8")
    counts = Counter(f["outcome"] for f in report["fixtures"])
    print(report["status"] + ": " + ", ".join(f"{counts[name]} {name}" for name in OUTCOMES))
    if report.get("error"):
        print(report["error"], file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())
