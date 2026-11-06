#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel

"""Build the Rust BER/DER coverage, triage and ergonomics report from committed evidence."""

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

if __package__:
    from . import check_rust_binding as audit, check_rust_reference as reference
    from . import check_rust_regressions as gate, run_rust_differential as runner
    from . import setup_rust_differential as setup
    from .setup_lua import require, write_json
else:
    import check_rust_binding as audit
    import check_rust_reference as reference
    import check_rust_regressions as gate
    import run_rust_differential as runner
    import setup_rust_differential as setup
    from setup_lua import require, write_json

ROOT = reference.ROOT
TRIAGE = ROOT / "differential/rust/triage.json"
ERGONOMICS = ROOT / "differential/rust/ergonomics.json"
CLASSIFICATIONS = ("defect", "limitation", "inconclusive")
STATUSES = ("supported", "unsupported", "not-comparable", "not-tested")
UPSTREAM_STATES = ("open", "closed", "not-reported", "documented")
DIMENSIONS = ("setup", "parse-flow", "diagnostics", "lifetimes", "api-complexity")
MATRIX_COLUMNS = ("core", "rust_binding", "der_parser_ber", "der_parser_der")
OBSERVATION = re.compile(r"accept|unsupported|reject:(empty|truncated|trailing|invalid|limit|unknown)")
NAMES = {"core": "Core", "rust-binding": "Rust binding", "der-parser": "der-parser"}


def ratio(count, denominator):
    """A percentage always carries the numerator and denominator it came from."""
    return {"count": count, "denominator": denominator,
            "percent": round(100 * count / denominator, 2) if denominator else None}


def scenarios(corpus, baseline):
    """Fixture coverage that the regression gate enforces for every passing run.

    The gate requires Core and the binding to meet every shared expectation and
    the reference to differ only on the recorded divergences.
    """
    diverging = {case["fixture"] for case in baseline["cases"]}
    result = {}
    for encoding in ("ber", "der", "all"):
        rows = [f for f in corpus["fixtures"] if encoding == "all" or f["encoding"] == encoding]
        shared = [f for f in rows if f["classification"] == "shared"]
        agreeing = sum(f["id"] not in diverging for f in shared)
        result[encoding] = {
            "fixtures": len(rows),
            "classification": {name: sum(f["classification"] == name for f in rows)
                               for name in reference.CLASSIFICATIONS},
            "shared": ratio(len(shared), len(rows)),
            "agreement": ratio(agreeing, len(shared)),
            "participants": {"core": ratio(len(shared), len(shared)),
                             "rust-binding": ratio(len(shared), len(shared)),
                             "der-parser": ratio(agreeing, len(shared))}}
    return result


def capabilities(matrix):
    """Core-to-binding exposure and three-way overlap over the reviewed capability matrix."""
    features = matrix["features"]
    for feature in features:
        require(all(feature[column]["status"] in STATUSES for column in MATRIX_COLUMNS),
                f"{feature['id']}: unknown capability status")

    def reference_supports(feature):
        return any(feature[c]["status"] == "supported" for c in ("der_parser_ber", "der_parser_der"))

    core = [f for f in features if f["core"]["status"] == "supported"]
    exposed = [f["id"] for f in core if f["rust_binding"]["status"] == "supported"]
    three_way = [f["id"] for f in core if f["id"] in exposed and reference_supports(f)]
    return {
        "matrix": {f["id"]: {column: f[column]["status"] for column in MATRIX_COLUMNS} for f in features},
        "features": len(features),
        "core_supported": len(core),
        "exposure": ratio(len(exposed), len(core)),
        "binding_status": {status: sum(f["rust_binding"]["status"] == status for f in core) for status in STATUSES},
        "binding_missing": [f["id"] for f in core if f["rust_binding"]["status"] == "unsupported"],
        "binding_not_tested": [f["id"] for f in core if f["rust_binding"]["status"] == "not-tested"],
        "three_way": ratio(len(three_way), len(core)),
        "three_way_features": three_way,
    }


def validate_triage(triage, corpus, baseline, gaps):
    """Every unsupported, inconclusive and diverging fixture has exactly one reviewed finding."""
    require(triage.get("schema") == 1 and triage.get("contract") == corpus["contract"], "unknown triage contract")
    require(tuple(triage["classifications"]) == CLASSIFICATIONS, "triage classifications changed")
    fixtures = {f["id"]: f for f in corpus["fixtures"]}
    diverging = {case["fixture"] for case in baseline["cases"]}
    outcomes = {name: "mismatch" if name in diverging else f["classification"]
                for name, f in fixtures.items() if name in diverging or f["classification"] != "shared"}
    gap_rows = {gap["id"]: gap for gap in gaps["gaps"]}
    keys = {"id", "classification", "participants", "owner", "component", "summary", "rules", "fixtures",
            "minimized", "upstream", "disclosure"}
    seen, identifiers, gap_links = {}, set(), set()
    for finding in triage["findings"]:
        name = finding.get("id")
        require(set(finding) in (keys, keys | {"gap"}), f"{name}: invalid finding fields")
        require(isinstance(name, str) and re.fullmatch(r"[a-z0-9-]+", name) and name not in identifiers,
                f"{name}: invalid or duplicate finding id")
        identifiers.add(name)
        classification = finding["classification"]
        require(classification in CLASSIFICATIONS, f"{name}: unknown classification")
        require(finding["participants"] and set(finding["participants"]) <= set(setup.PARTICIPANTS),
                f"{name}: unknown participant")
        require(all(isinstance(finding[k], str) and finding[k].strip()
                    for k in ("owner", "component", "summary", "disclosure")), f"{name}: missing description")
        for fixture in finding["fixtures"]:
            require(fixture in outcomes, f"{name}: {fixture} is not a triaged outcome")
            require(fixture not in seen, f"{fixture}: triaged by {seen.get(fixture)} and {name}")
            seen[fixture] = name
        # A defect rests on a shared standards expectation that a participant failed.
        if classification == "defect":
            require(finding["fixtures"] and all(outcomes[f] == "mismatch" for f in finding["fixtures"]) and
                    finding["rules"], f"{name}: a defect needs diverging shared fixtures and an X.690 rule")
        if any(outcomes[f] == "mismatch" for f in finding["fixtures"]):
            require(classification != "inconclusive", f"{name}: a shared mismatch has a definite expectation")
        require(finding["fixtures"] or finding["minimized"] or "gap" in finding,
                f"{name}: a finding needs fixture, minimized or gap evidence")
        smallest = min((len(bytes.fromhex(fixtures[f]["wire"])) for f in finding["fixtures"]), default=4096)
        for case in finding["minimized"]:
            require(set(case) == {"encoding", "wire", "observed"} and case["encoding"] in ("ber", "der"),
                    f"{name}: invalid minimized case")
            require(re.fullmatch(r"[0-9a-f]{2}( [0-9a-f]{2})*", case["wire"]) and
                    len(bytes.fromhex(case["wire"])) <= smallest, f"{name}: minimized case is not minimal hex")
            require(set(case["observed"]) == set(setup.PARTICIPANTS) and
                    all(OBSERVATION.fullmatch(v) for v in case["observed"].values()),
                    f"{name}: invalid minimized observation")
        upstream = finding["upstream"]
        require(set(upstream) == {"issue", "state", "checked", "filed_by_testlab"} and
                upstream["state"] in UPSTREAM_STATES and isinstance(upstream["filed_by_testlab"], bool),
                f"{name}: invalid upstream record")
        tracked = upstream["state"] in ("open", "closed")
        require(tracked == (isinstance(upstream["issue"], str) and upstream["issue"].startswith("https://github.com/")),
                f"{name}: an open or closed state needs an issue link, and only then")
        if "gap" in finding:
            gap = gap_rows.get(finding["gap"])
            require(gap is not None and gap["issue"] == upstream["issue"] and gap["status"] == upstream["state"] and
                    classification == "limitation" and finding["participants"] == ["rust-binding"],
                    f"{name}: does not match the published gap inventory")
            gap_links.add(finding["gap"])
    require(set(seen) == set(outcomes), "untriaged outcomes: " + ", ".join(sorted(set(outcomes) - set(seen))))
    require(gap_links == set(gap_rows), "every published Rust gap needs a finding")
    return {"findings": len(triage["findings"]),
            "classification": {c: sum(f["classification"] == c for f in triage["findings"]) for c in CLASSIFICATIONS},
            "outcomes": {f: outcomes[f] for f in sorted(outcomes)},
            "opentlv_defects": sum(f["classification"] == "defect" and
                                   bool({"core", "rust-binding"} & set(f["participants"])) for f in triage["findings"])}


def code_lines(text):
    """Adapter lines excluding tests, comments and blank lines."""
    body = text.split("#[cfg(test)]", 1)[0]
    return sum(bool(line.strip()) and not line.strip().startswith(("//", "/*", "*")) for line in body.splitlines())


def registry_packages(manifest):
    lockfile = (ROOT / manifest).with_name("Cargo.lock")
    if not lockfile.is_file():
        return 0
    return len(re.findall(r'^source = "registry\+', lockfile.read_text(encoding="utf-8"), re.M))


def assess_ergonomics(ergonomics):
    """Verify every anchor in the committed sources and derive reproducible metrics."""
    require(ergonomics.get("schema") == 1 and ergonomics.get("scope"), "unknown ergonomics schema")
    participants = ergonomics["participants"]
    require(tuple(participants) == setup.PARTICIPANTS, "ergonomics participant set changed")
    metrics = {}
    for name, participant in participants.items():
        source = (ROOT / participant["adapter"]).read_text(encoding="utf-8")
        missing = [e for e in participant["entry_points"] if e not in source]
        require(participant["entry_points"] and not missing, f"{name}: entry points not used: {missing}")
        rust = participant["adapter"].endswith(".rs")
        metrics[name] = {"package": participant["package"], "adapter": participant["adapter"],
                         "adapter_code_lines": code_lines(source),
                         "entry_points": len(participant["entry_points"]),
                         "registry_packages": registry_packages(participant["manifest"]),
                         "unsafe_code": ("forbidden" if "#![forbid(unsafe_code)]" in source else
                                         "absent" if "unsafe" not in source else "present") if rust else
                                        "not applicable (C)"}
    dimensions = ergonomics["dimensions"]
    require(tuple(d["id"] for d in dimensions) == DIMENSIONS, "ergonomics dimensions changed")
    for dimension in dimensions:
        require(isinstance(dimension["question"], str) and dimension["question"], "missing dimension question")
        require(tuple(dimension["assessments"]) == setup.PARTICIPANTS, f"{dimension['id']}: participant set changed")
        for name, assessment in dimension["assessments"].items():
            require(assessment["finding"].strip() and assessment["evidence"], f"{dimension['id']}/{name}: no evidence")
            for anchor in assessment["evidence"]:
                path = ROOT / anchor["path"]
                require(path.is_file() and anchor["contains"] in path.read_text(encoding="utf-8"),
                        f"{dimension['id']}/{name}: stale anchor in {anchor['path']}")
    return metrics


def execution(comparison, corpus, baseline, expected):
    """Check a run report against the gate and the coverage it implies."""
    matched = gate.validate(comparison, baseline, corpus, setup.package_pins())
    participants = {}
    for encoding in ("ber", "der", "all"):
        shared = [row for row in comparison["fixtures"] if row["classification"] == "shared" and
                  (encoding == "all" or row["encoding"] == encoding)]
        participants[encoding] = {
            name: ratio(sum(runner.classify(row, {name: row["observed"][name]})[0] == "pass" for row in shared),
                        len(shared)) for name in setup.PARTICIPANTS}
        require(participants[encoding] == expected[encoding]["participants"],
                f"{encoding}: executed participant coverage differs from the gated coverage")
        observed = comparison["coverage"][encoding]
        require(ratio(observed["shared_pass"], observed["shared"]) == expected[encoding]["agreement"],
                f"{encoding}: executed agreement differs from the gated coverage")
    return {"status": comparison["status"], "testlab": comparison.get("testlab"),
            "runtime": comparison.get("runtime"), "memory_enforcement": comparison.get("memory_enforcement"),
            "coverage": comparison["coverage"], "participants": participants, "matched_divergences": matched}


def summarize(observation):
    if observation["result"] == "reject":
        return "reject:" + observation["error"]["category"]
    return observation["result"]


def reproduce(triage, provenance):
    """Rerun every minimized case through all three verified adapters."""
    receipt = setup.load_receipt(provenance)
    results = []
    for finding in triage["findings"]:
        for case in finding["minimized"]:
            fixture = {"id": finding["id"], "encoding": case["encoding"], "wire": case["wire"].replace(" ", "")}
            observed = {name: summarize(runner.run_adapter(name, fixture, Path(receipt["binaries"][name]["path"])))
                        for name in setup.PARTICIPANTS}
            require(observed == case["observed"],
                    f"{finding['id']}: minimized {case['encoding']} {case['wire']} now observes {observed}")
            results.append({"finding": finding["id"], **case})
    return results


def build(comparison=None, provenance=None):
    corpus = reference.load_json(reference.CORPUS)
    matrix = reference.load_json(reference.MATRIX)
    reference.verify_corpus(corpus, matrix)
    baseline = reference.load_json(gate.BASELINE)
    gaps = reference.load_json(audit.GAPS)
    triage = reference.load_json(TRIAGE)
    ergonomics = reference.load_json(ERGONOMICS)
    report = {"schema": 1, "contract": corpus["contract"],
              "scope": "Fixture-scoped evidence for the reviewed rust-ber-der-1 corpus. Not X.690 or Core API coverage.",
              "corpus_sha256": gate.identity(corpus), "packages": setup.package_pins(),
              "scenarios": scenarios(corpus, baseline), "capabilities": capabilities(matrix),
              "triage": validate_triage(triage, corpus, baseline, gaps), "findings": triage["findings"],
              "gaps": [{k: g[k] for k in ("id", "status", "issue", "tested_fix")} for g in gaps["gaps"]],
              "ergonomics": {"metrics": assess_ergonomics(ergonomics), "dimensions": ergonomics["dimensions"]},
              "execution": None, "minimized_reproduction": None}
    if comparison is not None:
        report["execution"] = execution(comparison, corpus, baseline, report["scenarios"])
    if provenance is not None:
        report["minimized_reproduction"] = reproduce(triage, provenance)
    return report


def cell(value):
    return f"{value['count']}/{value['denominator']} ({value['percent']}%)"


def tables(report):
    """Markdown tables shared by the generated report and the published guide."""
    out = {"scenarios": ["| Encoding | Fixtures | Shared | Unsupported | Inconclusive | All three agree | Core | "
                         "Rust binding | der-parser |", "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"]}
    for encoding, data in report["scenarios"].items():
        counts, parts = data["classification"], data["participants"]
        out["scenarios"].append(
            f"| {encoding.upper() if encoding != 'all' else 'All'} | {data['fixtures']} | {cell(data['shared'])} | "
            f"{counts['unsupported']} | {counts['inconclusive']} | {cell(data['agreement'])} | "
            f"{cell(parts['core'])} | {cell(parts['rust-binding'])} | {cell(parts['der-parser'])} |")
    caps, total = report["capabilities"], report["scenarios"]["all"]
    out["denominators"] = [
        "| Measure | Numerator / denominator |", "| --- | ---: |",
        f"| Reviewed fixtures that all three participants can decide (shared) | {cell(total['shared'])} |",
        f"| Shared fixtures where all three meet the X.690 expectation | {cell(total['agreement'])} |",
        f"| Core-supported matrix features exposed by published Rust 0.2.2 | {cell(caps['exposure'])} |",
        f"| Core-supported matrix features also supported by der-parser and Rust | {cell(caps['three_way'])} |"]
    out["matrix"] = ["| Feature | Core | Rust binding | der-parser BER | der-parser DER |",
                     "| --- | --- | --- | --- | --- |"]
    for feature, row in caps["matrix"].items():
        out["matrix"].append(f"| `{feature}` | " + " | ".join(row[c] for c in MATRIX_COLUMNS) + " |")
    out["findings"] = ["| Finding | Class | Participants | Fixtures | Minimized | Upstream |",
                       "| --- | --- | --- | --- | --- | --- |"]
    for finding in report["findings"]:
        upstream = finding["upstream"]
        link = f"[{upstream['state']}]({upstream['issue']})" if upstream["issue"] else upstream["state"]
        participants = ", ".join(NAMES[p] for p in finding["participants"])
        fixtures = ", ".join("`" + f + "`" for f in finding["fixtures"]) or "-"
        minimized = ", ".join(c["encoding"].upper() + " `" + c["wire"] + "`" for c in finding["minimized"]) or "-"
        out["findings"].append(f"| `{finding['id']}` | {finding['classification']} | {participants} | "
                               f"{fixtures} | {minimized} | {link} |")
    out["ergonomics"] = ["| Participant | Adapter code lines | Library entry points | Registry packages | Unsafe code |",
                         "| --- | ---: | ---: | ---: | --- |"]
    for name, metric in report["ergonomics"]["metrics"].items():
        out["ergonomics"].append(f"| {NAMES[name]} | {metric['adapter_code_lines']} | {metric['entry_points']} | "
                                 f"{metric['registry_packages']} | {metric['unsafe_code']} |")
    return out


def render(report):
    lines = ["# Rust BER/DER coverage, triage and ergonomics report", "", f"Status: **{report['status']}**", ""]
    if report.get("error"):
        return "\n".join(lines + ["Report failure: " + report["error"], ""])
    table = tables(report)
    triage = report["triage"]
    lines += [report["scope"], "", "## Coverage", "", *table["scenarios"], "", *table["denominators"], "",
              "## Capability matrix", "", *table["matrix"], "",
              "## Findings", "",
              f"{triage['findings']} findings: " + ", ".join(f"{n} {c}" for c, n in triage["classification"].items()) +
              f". OpenTLV defects: {triage['opentlv_defects']}.", "", *table["findings"], "",
              "## Ergonomics metrics", "", *table["ergonomics"], ""]
    execution = report["execution"]
    lines.append("Execution: " + ("not checked; pass `--comparison`." if execution is None else
                                 f"comparison `{execution['status']}` matches the gated coverage, with "
                                 f"{len(execution['matched_divergences'])} exact recorded divergences."))
    minimized = report["minimized_reproduction"]
    lines += ["", "Minimized cases: " + ("not rerun; pass `--reproduce`." if minimized is None else
                                        f"{len(minimized)} rerun through all three adapters with unchanged observations."), ""]
    return "\n".join(lines)


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--comparison", type=Path, help="also check a run_rust_differential.py JSON report")
    parser.add_argument("--reproduce", action="store_true", help="rerun minimized cases against a verified setup")
    parser.add_argument("--provenance", type=Path, default=setup.RECEIPT)
    parser.add_argument("--output", type=Path, default=runner.REPORTS / "report.json")
    parser.add_argument("--report", type=Path, default=runner.REPORTS / "report.md")
    args = parser.parse_args(arguments)
    try:
        comparison = reference.load_json(args.comparison) if args.comparison else None
        report = build(comparison, args.provenance if args.reproduce else None)
        report["status"] = "passed"
    except (OSError, ValueError, KeyError, TypeError, IndexError, subprocess.SubprocessError) as error:
        report = {"schema": 1, "status": "failed", "error": str(error)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    write_json(args.output, report)
    args.report.write_text(render(report), encoding="utf-8")
    if report["status"] == "passed":
        triage = report["triage"]["classification"]
        print(f"Rust report: passed; {report['triage']['findings']} findings "
              f"({', '.join(f'{n} {c}' for c, n in triage.items())}); "
              f"execution {'checked' if report['execution'] else 'not checked'}; minimized cases "
              f"{'rerun' if report['minimized_reproduction'] is not None else 'not rerun'}")
        return 0
    print("Rust report: failed", file=sys.stderr)
    print(report["error"], file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
