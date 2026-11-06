#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel

"""Check published Rust gap evidence against a verified three-way setup."""

import argparse
from pathlib import Path
import sys

if __package__:
    from . import setup_rust_differential as setup, setup_rust_binding as binding
    from .setup_lua import digest, require, write_json
else:
    import setup_rust_differential as setup
    import setup_rust_binding as binding
    from setup_lua import digest, require, write_json

ROOT = binding.ROOT
GAPS = ROOT / "differential/rust-binding/gaps.json"


def validate(gaps, core, vendor):
    require(gaps["schema"] == 1 and gaps["published_version"] == "0.2.2", "gap baseline changed")
    rows = gaps["gaps"]
    require({r["id"] for r in rows} == {"asn1-helpers", "asn1-codecs", "der-schema"} and len(rows) == 3,
            "gap inventory changed; review scope")
    raw_sources = "\n".join(p.read_text(encoding="utf-8") for p in
                            (vendor / "opentlv-sys-0.2.2/src").rglob("*.rs"))
    for gap in rows:
        require(gap["status"] == "open" and gap["tested_fix"] is None and
                gap["core_support"] == "supported" and gap["published_rust_exposure"] == "missing",
                "published gap cannot be marked fixed without reviewed evidence")
        require(gap["issue"].startswith("https://github.com/OpenTLV/opentlv-rust/issues/") and
                gap["coordination"] == "https://github.com/OpenTLV/opentlv-rust/issues/46", "gap lacks owning issue")
        header = core / gap["core_header"]["path"]
        require(digest(header) == gap["core_header"]["sha256"], "Core gap evidence changed")
        text = header.read_text(encoding="utf-8")
        require(gap["native_anchors"] and all(name in text and name not in raw_sources
                                              for name in gap["native_anchors"]), "native gap evidence changed")
        require(gap["reviewed_sources"], "gap lacks public facade review")
        for path, checksum in gap["reviewed_sources"].items():
            require(digest(vendor / path) == checksum, "reviewed public facade changed")
    return [{k: row[k] for k in ("id", "status", "issue", "tested_fix")} for row in rows]


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provenance", type=Path, default=setup.RECEIPT)
    parser.add_argument("--output", type=Path, default=ROOT / "build/rust-reports/binding-audit.json")
    args = parser.parse_args(arguments)
    report = {"schema": 1, "status": "failed", "error": None, "gaps": []}
    try:
        receipt = setup.load_receipt(args.provenance)
        binding.verify_pin(receipt["packages"]["rust-binding"])
        directory = Path(receipt["directory"])
        core = directory / "source" / receipt["packages"]["core"]["source_directory"]
        gaps = binding.reference.load_json(GAPS)
        rows = validate(gaps, core, directory / "binding/vendor")
        report.update(status="passed", gaps=rows, gap_closure="pending", packages=receipt["packages"],
                      gap_inventory_sha256=digest(GAPS),
                      checker_sha256=binding.reference.digest(Path(__file__).read_text(encoding="utf-8").encode()),
                      note="Evidence audit passed; three published API gaps remain open. Not full API/ABI coverage.")
    except (OSError, ValueError, KeyError, TypeError) as error:
        report["error"] = str(error)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_json(args.output, report)
    print(f'Published Rust evidence audit: {report["status"]}; {len(report["gaps"])} open gaps')
    if report["error"]:
        print(report["error"], file=sys.stderr)
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
