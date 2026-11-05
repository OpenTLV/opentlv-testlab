#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel

"""Build the pinned asn1c into a cache, generate the TestLab schema and audit its adapter."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import uuid

if __package__:
    from .check_asn1 import ROOT
    from .setup_lua import digest, executable, require, run, write_json
else:
    from check_asn1 import ROOT
    from setup_lua import digest, executable, require, run, write_json

PIN = ROOT / "dependencies/asn1c.json"
SCHEMA = ROOT / "differential/asn1c/TestLabReference-1.asn1"
ADAPTER_SOURCE = ROOT / "differential/asn1c/asn1c_adapter.c"
CAPABILITIES = ROOT / "differential/asn1c/capabilities.json"
INSTALL_SCHEMA = 1
# Wide types keep INTEGER arbitrary-precision; only the BER/DER codecs are generated.
ASN1C_FLAGS = ("-fwide-types", "-fcompound-names", "-fincludes-quoted",
               "-no-gen-OER", "-no-gen-PER", "-no-gen-example")
MODULE_CFLAGS = ["-DASN_DISABLE_OER_SUPPORT", "-DASN_DISABLE_PER_SUPPORT"]
CFLAGS = ["-std=gnu99", "-O2"]
ADAPTER_WARNINGS = ["-Wall", "-Wextra", "-Werror"]
# --sanitize: the generated code, asn1c's runtime and the adapter, for the fuzzer. A sanitizer
# report stops the adapter, so it can never pass as a result. The nonnull-attribute check is off:
# asn1c 0.9.29's dynamic_encoder_cb() (asn_application.c) copies zero octets from a null pointer
# whenever it re-encodes an empty string read in constructed form, which touches no memory.
SANITIZERS = ["address", "undefined"]
SANITIZER_FLAGS = ["-fsanitize=address,undefined", "-fno-sanitize=nonnull-attribute", "-fno-sanitize-recover=all",
                   "-fno-omit-frame-pointer", "-g"]
SANITIZED_RUNS = ROOT / "build/asn1c-sanitized-runs"
REQUIRED_FILES = {"bin/asn1c", "share/asn1c/asn_application.c", "share/asn1c/ber_decoder.c",
                  "share/asn1c/der_encoder.c"}
# Inherited settings that would change what is built or how.
BUILD_OVERRIDES = {"CC", "CFLAGS", "CPPFLAGS", "LDFLAGS", "LIBS", "CPATH", "C_INCLUDE_PATH",
                   "LIBRARY_PATH", "GCC_EXEC_PREFIX", "COMPILER_PATH", "CONFIG_SITE",
                   "MAKEFLAGS", "MFLAGS", "MAKEFILES", "GNUMAKEFLAGS"}
DECODE_SYNTAXES = ("ber", "der", "cer")
ENCODE_SYNTAXES = ("ber", "der", "cer", "none")
AREAS = ("ber-decode", "der-decode", "der-encode", "cer")
CLASSIFICATIONS = ("supported", "unsupported", "not-comparable")
ERRORS = {"empty": "RC_WMORE", "truncated": "RC_WMORE", "malformed": "RC_FAIL",
          "trailing": "RC_OK", "constraint": "RC_OK"}
KINDS = {"boolean", "integer", "bit_string", "octet_string", "ia5string", "null", "object_identifier",
         "sequence", "set", "sequence_of", "set_of", "choice"}
MAX_WIRE_BYTES = 4096
ADAPTER_TIMEOUT = 60


def build_env():
    env = {k: v for k, v in os.environ.items() if k not in BUILD_OVERRIDES}
    env["LC_ALL"] = "C"
    return env


def load_pin():
    pin = json.loads(PIN.read_text(encoding="utf-8"))
    require(pin.get("schema") == 1 and pin.get("repository") == "vlm/asn1c", "Invalid asn1c pin")
    require(re.fullmatch(r"\d+\.\d+\.\d+", pin["version"]) and pin["tag"] == "v" + pin["version"],
            "Invalid asn1c version")
    require(re.fullmatch(r"[0-9a-f]{40}", pin["commit"]), "Invalid asn1c commit")
    require(type(pin["environment_version"]) is int, "Invalid asn1c runtime version")
    require(pin["license"] == "BSD-2-Clause" and re.fullmatch(r"[0-9a-f]{64}", pin["license_sha256"]),
            "Invalid asn1c license pin")
    archive = pin["archive"]
    name = f"asn1c-{pin['version']}.tar.gz"
    require(archive["name"] == name and
            archive["url"] == f"https://github.com/{pin['repository']}/releases/download/{pin['tag']}/{name}",
            "asn1c must come from its pinned GitHub release")
    require(type(archive["size"]) is int and archive["size"] > 0 and
            re.fullmatch(r"[0-9a-f]{64}", archive["sha256"]), "Invalid asn1c archive pin")
    return pin


def context(cc, make):
    require(platform.system() == "Linux", "asn1c setup supports Linux/WSL with a C compiler and GNU Make")
    env = build_env()
    return {"installer_schema": INSTALL_SCHEMA,
            "compiler": {"version": run([cc, "--version"], env=env).splitlines()[0],
                         "target": run([cc, "-dumpmachine"], env=env), "executable_sha256": digest(cc)},
            "make": {"version": run([make, "--version"], env=env).splitlines()[0],
                     "executable_sha256": digest(make)},
            "platform": {"system": platform.system(), "release": platform.release(),
                         "machine": platform.machine(), "libc": list(platform.libc_ver())}}


def cache_key(pin, configuration):
    payload = json.dumps({"pin": pin, "configuration": configuration}, sort_keys=True).encode()
    return "asn1c-" + pin["version"] + "-" + hashlib.sha256(payload).hexdigest()


def download(pin, target):
    """Fetch the release archive; bytes that differ from the pin are never written."""
    archive = pin["archive"]
    with urllib.request.urlopen(archive["url"], timeout=60) as response:
        data = response.read()
    require(len(data) == archive["size"] and hashlib.sha256(data).hexdigest() == archive["sha256"],
            f"SHA-256 mismatch: {archive['name']}")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)


def extract(archive_path, destination, pin):
    root = f"asn1c-{pin['version']}"
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive.getmembers():
            path = PurePosixPath(member.name)
            require(not path.is_absolute() and ".." not in path.parts and path.parts[:1] == (root,),
                    f"Unsafe archive path: {member.name}")
            require(member.isfile() or member.isdir(), f"Archive member is not a file or directory: {member.name}")
        archive.extractall(destination, **({"filter": "data"} if hasattr(tarfile, "data_filter") else {}))
    return destination / root


def inventory(directory):
    paths = list(directory.rglob("*"))
    require(not any(p.is_symlink() for p in paths), "Symlinks are not allowed in the asn1c cache")
    return {p.relative_to(directory).as_posix(): digest(p) for p in sorted(paths) if p.is_file()}


def verify_install(entry, pin, configuration):
    """Reject a changed, partial or foreign cache entry instead of rebuilding over it."""
    require(not entry.is_symlink(), "Cache entry must not be a symlink")
    receipt = json.loads((entry / "installation.json").read_text(encoding="utf-8"))
    require(receipt.get("pin") == pin and receipt.get("configuration") == configuration, "Cache identity mismatch")
    files = receipt.get("files")
    require(isinstance(files, dict) and REQUIRED_FILES <= files.keys(), "Cache lacks the asn1c compiler or runtime")
    archive = "source/" + pin["archive"]["name"]
    require(digest(entry / archive) == pin["archive"]["sha256"], f"SHA-256 mismatch: {pin['archive']['name']}")
    require(digest(entry / "LICENSE") == pin["license_sha256"], "asn1c license changed")
    for name, value in files.items():
        require(digest(entry / "prefix" / name) == value, f"Installed file changed: {name}")
    expected = {"installation.json", "LICENSE", archive} | {"prefix/" + name for name in files}
    require(set(inventory(entry)) == expected, "Unexpected cache contents")


def build(source, prefix, cc, make, log):
    env = build_env()
    run([source / "configure", "--prefix=" + str(prefix), "CC=" + str(cc)], cwd=source, env=env, log=log, timeout=600)
    run([make, f"-j{os.cpu_count() or 1}"], cwd=source, env=env, log=log, timeout=1800)
    run([make, "install"], cwd=source, env=env, log=log, timeout=600)


def external_setup(cache, pin, configuration, cc, make, *, log, offline=False):
    key = cache_key(pin, configuration)
    entry = cache / key
    hit = entry.exists()
    if not hit:
        require(not offline, f"Offline cache miss: {key}")
        cache.mkdir(parents=True, exist_ok=True)
        # Configure and libtool mishandle some paths, so the build tree is a system temporary directory.
        with tempfile.TemporaryDirectory(prefix=".install-", dir=cache) as temp, \
                tempfile.TemporaryDirectory(prefix="asn1c-build-") as work:
            stage, work = Path(temp), Path(work)
            archive = stage / "source" / pin["archive"]["name"]
            download(pin, archive)
            source = extract(archive, work, pin)
            require(digest(source / "LICENSE") == pin["license_sha256"], "asn1c license changed")
            shutil.copyfile(source / "LICENSE", stage / "LICENSE")
            build(source, work / "prefix", cc, make, log)
            shutil.copytree(work / "prefix", stage / "prefix", symlinks=True)
            write_json(stage / "installation.json", {"pin": pin, "configuration": configuration,
                                                     "files": inventory(stage / "prefix")})
            verify_install(stage, pin, configuration)
            # Publish only a complete verified entry; a concurrent winner is rechecked below.
            try:
                stage.rename(entry)
            except OSError:
                if not entry.exists():
                    raise
    verify_install(entry, pin, configuration)
    return {"key": key, "cache_hit": hit, "directory": str(entry), "pin": pin,
            "compiler": str(entry / "prefix/bin/asn1c"), "skeletons": str(entry / "prefix/share/asn1c")}


def schema_identity(path=SCHEMA):
    text = path.read_text(encoding="utf-8")
    module = re.findall(r"^([A-Z][A-Za-z0-9-]*) DEFINITIONS\b", text, re.M)
    types = re.findall(r"^([A-Z][A-Za-z0-9]*) ::=", text, re.M)
    require(module == [path.stem], "The schema file must hold one module named after the file")
    require(types and len(set(types)) == len(types), "Schema types must be unique")
    return {"module": module[0], "path": path.relative_to(ROOT).as_posix() if path.is_relative_to(ROOT) else str(path),
            "sha256": digest(path), "types": types}


def generate(compiler, skeletons, directory, log):
    (directory / "generated").mkdir(parents=True)
    run([compiler, "-S", skeletons, "-D", "generated", *ASN1C_FLAGS, SCHEMA],
        cwd=directory, env=build_env(), log=log)
    return inventory(directory / "generated")


def generate_twice(compiler, skeletons, run_directory, log):
    """Generation must be deterministic; identical relative paths keep the comments identical."""
    first = generate(compiler, skeletons, run_directory / "generation-1", log)
    second = generate(compiler, skeletons, run_directory / "generation-2", log)
    require(first == second, "asn1c generated different sources from the same schema")
    shutil.rmtree(run_directory / "generation-2")
    (run_directory / "generation-1/generated").rename(run_directory / "generated")
    (run_directory / "generation-1").rmdir()
    return first


def module_sources(generated, schema, pin):
    """Take the source list and flags from asn1c's own generated build description."""
    text = (generated / "Makefile.am.libasncodec").read_text(encoding="utf-8").replace("\\\n", " ")
    sources, cflags = [], None
    for line in text.splitlines():
        if match := re.match(r"ASN_MODULE_SRCS\+?=(.*)", line):
            sources.extend(name for name in match.group(1).split() if name not in sources)
        elif match := re.match(r"ASN_MODULE_CFLAGS=(.*)", line):
            cflags = match.group(1).split()
    require(cflags == MODULE_CFLAGS, f"Unexpected generated codec flags: {cflags}")
    require(sources and all(re.fullmatch(r"generated/[\w-]+\.c", name) for name in sources),
            "Unexpected generated source list")
    modules = []
    for name in sources:
        header = (generated.parent / name).read_text(encoding="utf-8")[:400]
        if f'From ASN.1 module "{schema["module"]}"' in header:
            require(f"Generated by asn1c-{pin['version']} " in header, f"{name} was generated by another asn1c")
            modules.append(PurePosixPath(name).stem)
    require(sorted(modules) == sorted(schema["types"]), "Generated types differ from the schema")
    return sources


def compile_adapter(run_directory, cc, sources, schema, pin, log, sanitize=False):
    build_directory = run_directory / "build"
    (build_directory / "obj").mkdir(parents=True)
    (build_directory / "testlab_types.h").write_text("".join(f"TESTLAB_TYPE({name})\n" for name in schema["types"]),
                                                    encoding="utf-8")
    defines = [f'-DTESTLAB_ASN1C_VERSION="{pin["version"]}"', f'-DTESTLAB_SCHEMA="{schema["module"]}"',
               f'-DTESTLAB_SCHEMA_SHA256="{schema["sha256"]}"']
    cflags = CFLAGS + (SANITIZER_FLAGS if sanitize else [])
    commands = [[cc, *cflags, *MODULE_CFLAGS, "-Igenerated", "-c", name,
                 "-o", f"build/obj/{PurePosixPath(name).stem}.o"] for name in sources]
    commands.append([cc, *cflags, *ADAPTER_WARNINGS, *MODULE_CFLAGS, *defines, "-Igenerated", "-Ibuild",
                     "-c", ADAPTER_SOURCE, "-o", "build/obj/testlab-adapter.o"])
    env = build_env()
    with ThreadPoolExecutor(max_workers=os.cpu_count() or 1) as pool:
        outputs = list(pool.map(lambda command: run(command, cwd=run_directory, env=env, timeout=300), commands))
    with log.open("a", encoding="utf-8") as stream:
        for command, output in zip(commands, outputs):
            stream.write("+ " + subprocess.list2cmdline([str(p) for p in command]) + "\n" + output + "\n")
    objects = sorted(f"build/obj/{p.name}" for p in (build_directory / "obj").glob("*.o"))
    run([cc, *(SANITIZER_FLAGS if sanitize else []), "-o", "asn1c-adapter", *objects], cwd=run_directory, env=env,
        log=log)
    adapter = run_directory / "asn1c-adapter"
    built = {"path": str(adapter), "sha256": digest(adapter), "source_sha256": digest(ADAPTER_SOURCE),
             "cflags": cflags, "module_cflags": MODULE_CFLAGS, "adapter_flags": ADAPTER_WARNINGS + defines}
    if sanitize:
        built["sanitizers"] = SANITIZERS
    return built


def validate_value(value):
    require(isinstance(value, dict) and value.get("kind") in KINDS, f"Invalid typed value: {value}")
    kind = value["kind"]
    if kind == "null":
        require(value.keys() == {"kind"}, "NULL has no value")
    elif kind in ("sequence", "set"):
        require(value.keys() == {"kind", "fields"} and isinstance(value["fields"], list), f"Invalid {kind}")
        for field in value["fields"]:
            require(isinstance(field, dict) and field.keys() == {"name", "value"}, f"Invalid {kind} field")
            validate_value(field["value"])
    elif kind in ("sequence_of", "set_of"):
        require(value.keys() == {"kind", "items"} and isinstance(value["items"], list), f"Invalid {kind}")
        for item in value["items"]:
            validate_value(item)
    elif kind == "choice":
        require(value.keys() == {"kind", "alternative", "value"}, "Invalid choice")
        validate_value(value["value"])
    else:
        allowed = {"kind", "value", "unused_bits"} if kind == "bit_string" else {"kind", "value"}
        require(value.keys() == allowed, f"Invalid {kind}")


def validate_expected(probe, wire):
    expected = probe.get("expected")
    require(isinstance(expected, dict) and isinstance(expected.get("decode"), dict), "Probe needs an expected decode")
    decode = expected["decode"]
    status = decode.get("status")
    if status == "accepted":
        require(decode.keys() == {"status", "code", "consumed", "value"} and decode["code"] == "RC_OK" and
                decode["consumed"] == len(wire), "Accepted decode consumes the whole wire with RC_OK")
        validate_value(decode["value"])
    elif status == "rejected":
        error = decode.get("error")
        require(decode.keys() == {"status", "code", "consumed", "error"} and error in ERRORS and
                decode["code"] == ERRORS[error] and type(decode["consumed"]) is int,
                f"Rejected decode needs a code matching its error: {', '.join(ERRORS)}")
        require((error == "empty") == (not wire), "Only empty input is an empty rejection")
        require(error != "trailing" or decode["consumed"] < len(wire), "Trailing rejection leaves bytes")
        require(error != "constraint" or decode["consumed"] == len(wire), "Constraint rejection decodes all bytes")
    elif status == "unsupported":
        require(decode == {"status": "unsupported", "code": "RC_FAIL"}, "Unsupported decode has only its code")
    else:
        raise ValueError("Decode status must be accepted, rejected or unsupported")
    encodes = status == "accepted" and probe["encode"] != "none"
    require(("encode" in expected) == encodes, "Expected encode exactly when an accepted value is encoded")
    require(expected.keys() <= {"decode", "encode"}, "Unexpected expectation fields")
    if encodes:
        encode = expected["encode"]
        if encode.get("status") == "encoded":
            require(encode.keys() == {"status", "wire"} and re.fullmatch(r"([0-9a-f]{2})+", encode["wire"]),
                    "Encoded result needs lowercase hex wire")
        else:
            require(encode in ({"status": "unsupported"}, {"status": "failed"}), "Invalid expected encode")


def validate_probe(probe, types):
    require(isinstance(probe, dict) and isinstance(probe.get("id"), str) and
            re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", probe["id"]), "Probe id must be lowercase kebab-case")
    try:
        allowed = {"id", "area", "classification", "description", "rule", "reason", "type", "decode", "encode",
                   "wire", "expected"}
        require(probe.keys() <= allowed and allowed - {"reason"} <= probe.keys(), "Probe has unexpected or missing fields")
        require(probe["area"] in AREAS, f"Area must be: {', '.join(AREAS)}")
        require(probe["classification"] in CLASSIFICATIONS, f"Classification must be: {', '.join(CLASSIFICATIONS)}")
        require(("reason" in probe) == (probe["classification"] != "supported"),
                "A reason explains exactly the probes that are not supported")
        for key in ("description", "rule", "reason"):
            require(key not in probe or (isinstance(probe[key], str) and probe[key].strip()), f"Probe needs a {key}")
        require(probe["type"] in types, f"Unknown schema type: {probe['type']}")
        require(probe["decode"] in DECODE_SYNTAXES and probe["encode"] in ENCODE_SYNTAXES, "Unknown transfer syntax")
        require(isinstance(probe["wire"], str), "Wire must be a hex string")
        wire = bytes.fromhex(probe["wire"])
        require(len(wire) <= MAX_WIRE_BYTES, f"Wire exceeds {MAX_WIRE_BYTES} bytes")
        validate_expected(probe, wire)
    except (ValueError, KeyError) as error:
        raise ValueError(f"Probe {probe['id']}: {error}") from error


def load_capabilities(path=CAPABILITIES):
    data = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(data, dict) and data.keys() == {"schema", "reference", "probes"} and data["schema"] == 1,
            "Expected capability schema 1")
    schema = schema_identity()
    require(data["reference"] == {"asn1c": load_pin()["version"], "schema": schema["module"]},
            "Probes were verified against a different asn1c or schema")
    probes = data["probes"]
    require(isinstance(probes, list) and probes, "Probe list must not be empty")
    for probe in probes:
        validate_probe(probe, schema["types"])
    identifiers = [probe["id"] for probe in probes]
    require(len(set(identifiers)) == len(identifiers), "Probe ids must be unique")
    return data


def select_probes(probes, identifiers):
    if not identifiers:
        return probes
    unknown = sorted(set(identifiers) - {probe["id"] for probe in probes})
    require(not unknown, f"Unknown probe: {', '.join(unknown)}")
    return [probe for probe in probes if probe["id"] in identifiers]


def request_line(probe):
    wire = bytes.fromhex(probe["wire"]).hex() or "-"
    return f"{probe['id']} {probe['type']} {probe['decode']} {probe['encode']} {wire}\n"


def run_adapter(adapter, probes, identity):
    """Crashes, timeouts and protocol errors are run failures, never a capability result."""
    def stopped_at(stdout):
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", "replace")
        done = max(len((stdout or "").splitlines()) - 1, 0)
        return probes[done]["id"] if done < len(probes) else "none (after the final result)"
    try:
        result = subprocess.run([str(adapter)], input="".join(request_line(p) for p in probes), env=build_env(),
                                capture_output=True, text=True, encoding="utf-8", errors="replace",
                                timeout=ADAPTER_TIMEOUT)
    except subprocess.TimeoutExpired as error:
        raise ValueError(f"asn1c adapter timed out at probe {stopped_at(error.stdout)}") from error
    require(result.returncode == 0, f"asn1c adapter failed ({result.returncode}) at probe "
                                    f"{stopped_at(result.stdout)}: {result.stderr[-2000:]}")
    lines = [json.loads(line) for line in result.stdout.splitlines()]
    require(len(lines) == len(probes) + 1, "asn1c adapter returned an incomplete result set")
    require(lines[0] == identity, f"asn1c adapter reported a different identity: {lines[0]}")
    for probe, record in zip(probes, lines[1:]):
        require(record.get("id") == probe["id"] and record.get("type") == probe["type"],
                "asn1c adapter returned results out of order")
        require(record.get("decode", {}).get("syntax") == probe["decode"], "asn1c adapter decoded another syntax")
        require("encode" not in record or record["encode"].get("syntax") == probe["encode"],
                "asn1c adapter encoded another syntax")
    return lines[1:]


def observation(record):
    """The comparable part of a result: syntax is the request, and detail is diagnostic text."""
    return {key: {k: v for k, v in record[key].items() if k not in ("syntax", "detail")}
            for key in ("decode", "encode") if key in record}


def adapter_identity(pin, schema):
    return {"adapter": "asn1c", "version": pin["version"], "environment_version": pin["environment_version"],
            "schema": schema["module"], "schema_sha256": schema["sha256"], "types": schema["types"]}


def audit(adapter, probes, pin, schema, log=None):
    records = run_adapter(adapter, probes, adapter_identity(pin, schema))
    results = []
    for probe, record in zip(probes, records):
        status = "pass" if observation(record) == probe["expected"] else "changed"
        results.append({"id": probe["id"], "area": probe["area"], "classification": probe["classification"],
                        "status": status, "expected": probe["expected"], "observed": record})
    lines = [f"{r['status']:<8} {r['classification']:<15} {r['id']}" for r in results]
    for result in results:
        if result["status"] == "changed":
            lines.append(f"changed  {result['id']}: expected {json.dumps(result['expected'], sort_keys=True)}, "
                         f"observed {json.dumps(observation(result['observed']), sort_keys=True)}")
    passed = sum(r["status"] == "pass" for r in results)
    lines.append(f"{passed} of {len(results)} probes match the documented asn1c behavior")
    text = "\n".join(lines) + "\n"
    print(text, end="", flush=True)
    if log:
        log.write_text(text, encoding="utf-8")
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--make", default="make")
    parser.add_argument("--cache-dir", type=Path, default=ROOT / "build/dependency-cache")
    parser.add_argument("--runs-dir", type=Path,
                        help="Default build/asn1c-runs, or build/asn1c-sanitized-runs with --sanitize")
    parser.add_argument("--offline", action="store_true", help="Require a cached asn1c build; download nothing")
    parser.add_argument("--sanitize", action="store_true",
                        help="Build the adapter with AddressSanitizer and UndefinedBehaviorSanitizer, for fuzzing")
    parser.add_argument("--print-cache-key", action="store_true")
    args = parser.parse_args()
    # Sanitized receipts stay apart, so the corpus runners keep using the plain adapter by default.
    args.runs_dir = args.runs_dir or (SANITIZED_RUNS if args.sanitize else ROOT / "build/asn1c-runs")
    directory = None
    report = None
    try:
        cc, make = executable(args.cc), executable(args.make)
        pin, configuration = load_pin(), context(cc, make)
        if args.print_cache_key:
            print(cache_key(pin, configuration))
            return 0
        args.runs_dir.mkdir(parents=True, exist_ok=True)
        directory = args.runs_dir.resolve() / str(uuid.uuid4())
        directory.mkdir()
        report = {"schema": 1, "run_id": directory.name, "status": "running",
                  "started_at": datetime.now(timezone.utc).isoformat(), "configuration": configuration,
                  "compiler_executable": str(cc)}
        write_json(directory / "provenance.json", report)
        external = external_setup(args.cache_dir.resolve(), pin, configuration, cc, make,
                                  log=directory / "asn1c-build.log", offline=args.offline)
        report["external"] = external
        write_json(directory / "provenance.json", report)
        version = run([external["compiler"], "-version"], env=build_env()).splitlines()[0]
        require(version == f"ASN.1 Compiler, v{pin['version']}", f"Unexpected asn1c version: {version}")
        schema = schema_identity()
        log = directory / "generate.log"
        report["generation"] = {"asn1c_version": version, "schema": schema, "flags": list(ASN1C_FLAGS),
                                "deterministic": True,
                                "files": generate_twice(external["compiler"], external["skeletons"], directory, log)}
        sources = module_sources(directory / "generated", schema, pin)
        report["adapter"] = compile_adapter(directory, cc, sources, schema, pin, directory / "build.log",
                                            sanitize=args.sanitize)
        write_json(directory / "provenance.json", report)
        probes = load_capabilities()["probes"]
        results = audit(report["adapter"]["path"], probes, pin, schema, directory / "capabilities.log")
        changed = [r["id"] for r in results if r["status"] != "pass"]
        require(not changed, f"asn1c behavior differs from the capability probes: {', '.join(changed)}")
        report["capabilities"] = {"file": CAPABILITIES.relative_to(ROOT).as_posix(), "sha256": digest(CAPABILITIES),
                                  "passed": len(results),
                                  "classifications": {c: sum(p["classification"] == c for p in probes)
                                                      for c in CLASSIFICATIONS}}
        report["status"] = "passed"
        report["completed_at"] = datetime.now(timezone.utc).isoformat()
        write_json(directory / "provenance.json", report)
        print(f"asn1c cache {'hit' if external['cache_hit'] else 'miss'}: {external['key']}")
        print(f"Provenance: {directory / 'provenance.json'}")
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, tarfile.TarError) as error:
        if directory and report is not None:
            # The running receipt never becomes a success receipt after a partial setup.
            report["status"] = "failed"
            report["error"] = str(error)
            write_json(directory / "provenance.json", report)
            write_json(directory / "failure.json", {"status": "failed", "error": str(error)})
        print(f"asn1c setup failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
