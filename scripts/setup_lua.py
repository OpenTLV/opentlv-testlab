#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel

"""Stage cached lua-asn1 and freshly install the pinned OpenTLV release rock."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import uuid

if __package__:
    from .check_asn1 import ROOT, load_pin, verify_source
else:
    from check_asn1 import ROOT, load_pin, verify_source

INSTALL_SCHEMA = 1
MODULE_DIR = Path("usr/share/lua/common")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def clean_env():
    return {k: v for k, v in os.environ.items()
            if not k.startswith(("LUA_", "LUAROCKS_")) and
            k not in {"MAKEFLAGS", "MFLAGS", "MAKEFILES", "GNUMAKEFLAGS"}}


def run(command, *, cwd=None, env=None, log=None, timeout=60):
    command = [str(p) for p in command]
    result = subprocess.run(command, cwd=cwd, env=env, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    if log:
        with log.open("a", encoding="utf-8") as stream:
            stream.write("+ " + subprocess.list2cmdline(command) + "\n" + result.stdout + "\n")
    require(result.returncode == 0,
            f"Command failed ({result.returncode}): {command[0]}\n{result.stdout[-4000:]}")
    return result.stdout.strip()


def executable(name):
    path = shutil.which(str(name))
    require(path, f"Executable not found: {name}")
    return Path(path).resolve()


def context(lua, make):
    require(platform.system() == "Linux", "Initial setup supports Linux/WSL with PUC Lua 5.2")
    env = clean_env()
    probe = run([lua, "-e", 'assert(_VERSION == "Lua 5.2"); '
                 'assert(type(require("bit32").band) == "function"); '
                 'assert(type(table.unpack) == "function"); print(_VERSION)'], env=env)
    return {"installer_schema": INSTALL_SCHEMA, "layout": MODULE_DIR.as_posix(),
            "lua": {"abi": probe, "version": run([lua, "-v"], env=env),
                    "executable_sha256": digest(lua)},
            "platform": {"system": platform.system(), "release": platform.release(),
                         "machine": platform.machine(), "libc": list(platform.libc_ver())},
            "make": {"version": run([make, "--version"], env=env).splitlines()[0],
                     "executable_sha256": digest(make)}}


def cache_key(pin, configuration):
    payload = json.dumps({"pin": pin, "configuration": configuration}, sort_keys=True).encode()
    return "lua-asn1-" + pin["version"] + "-" + hashlib.sha256(payload).hexdigest()


def verify_install(entry, pin, configuration):
    require(not entry.is_symlink(), "Cache entry must not be a symlink")
    receipt = json.loads((entry / "installation.json").read_text(encoding="utf-8"))
    require(receipt == {"pin": pin, "configuration": configuration}, "Cache identity mismatch")
    verify_source(entry / "source", pin)
    expected = {"source/" + name for name in pin["files"]} | {"installation.json"}
    installed = {"usr/share/doc/lua-asn1/LICENSE": pin["files"]["LICENSE"]}
    installed.update({(MODULE_DIR / name).as_posix(): value
                      for name, value in pin["files"].items() if name.endswith(".lua")})
    for name, value in installed.items():
        require(digest(entry / "stage" / name) == value, f"Installed file changed: {name}")
        expected.add("stage/" + name)
    paths = list(entry.rglob("*"))
    require(not any(p.is_symlink() for p in paths), "Symlinks are not allowed in the cache")
    require({p.relative_to(entry).as_posix() for p in paths if p.is_file()} == expected,
            "Unexpected cache contents")


def external_setup(cache, pin, configuration, make, *, offline=False):
    key = cache_key(pin, configuration)
    entry = cache / key
    hit = entry.exists()
    if not hit:
        require(not offline, f"Offline cache miss: {key}")
        cache.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".install-", dir=cache) as temp:
            stage = Path(temp)
            source = stage / "source"
            verify_source(source, pin, download=True)
            # Upstream's recipe does not quote paths; a relative root also works
            # when the caller's cache directory contains spaces.
            run([make, "install", "ROOT_DIR=../stage"],
                cwd=source, env=clean_env())
            license_path = stage / "stage/usr/share/doc/lua-asn1/LICENSE"
            license_path.parent.mkdir(parents=True)
            shutil.copyfile(source / "LICENSE", license_path)
            write_json(stage / "installation.json", {"pin": pin, "configuration": configuration})
            verify_install(stage, pin, configuration)
            # Publish only a complete verified entry; a concurrent winner is rechecked below.
            try:
                stage.rename(entry)
            except OSError:
                if not entry.exists():
                    raise
    verify_install(entry, pin, configuration)
    return {"key": key, "cache_hit": hit, "directory": str(entry),
            "module_directory": str(entry / "stage" / MODULE_DIR), "pin": pin}


def load_release_pin():
    pin = json.loads((ROOT / "dependencies/opentlv-lua.json").read_text(encoding="utf-8"))
    require(pin["schema"] == 1 and pin["repository"] == "OpenTLV/opentlv-lua", "Invalid release pin")
    require(re.fullmatch(r"\d+\.\d+\.\d+", pin["version"]) and
            pin["tag"] == "v" + pin["version"] and
            re.fullmatch(re.escape(pin["version"]) + r"-\d+", pin["rock_version"]),
            "Invalid release version")
    for key in ("commit", "core_commit"):
        require(re.fullmatch(r"[0-9a-f]{40}", pin[key]), "Invalid release commit")
    require(set(pin["assets"]) == {"release-manifest.json",
            f"opentlv-{pin['rock_version']}.rockspec", f"opentlv-{pin['rock_version']}.src.rock"},
            "Unexpected release asset inventory")
    require(all(re.fullmatch(r"[0-9a-f]{64}", v) for v in pin["assets"].values()), "Invalid asset digest")
    return pin


def fetch_bytes(url):
    # Public downloads only: never forward credentials to release-asset redirects.
    request = urllib.request.Request(url, headers={"Cache-Control": "no-cache"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def acquire_release(directory, pin):
    """Always fetch all assets; existing files or previous run receipts cannot satisfy this."""
    directory.mkdir(parents=True, exist_ok=False)
    base = f"https://github.com/{pin['repository']}/releases/download/{pin['tag']}/"
    assets = []
    for name, expected in pin["assets"].items():
        data = fetch_bytes(base + name)
        require(hashlib.sha256(data).hexdigest() == expected, f"Release SHA-256 mismatch: {name}")
        (directory / name).write_bytes(data)
        assets.append({"name": name, "url": base + name, "sha256": expected, "size": len(data)})
    manifest = json.loads((directory / "release-manifest.json").read_text(encoding="utf-8"))
    request = manifest["request"]
    require(manifest["schema"] == 1 and request["repository"] == pin["repository"] and
            request["tag"] == pin["tag"] and request["version"] == pin["version"] and
            request["commit"] == request["lua_sha"] == pin["commit"] and
            request["core_sha"] == pin["core_commit"], "Release manifest identity mismatch")
    rocks = [r["release_rock"] for r in manifest["quality"]["records"] if r.get("release_rock")]
    require(rocks and all(r == rocks[0] for r in rocks), "Inconsistent release rock evidence")
    rock = rocks[0]
    require(rock["sha256"] == pin["assets"][rock["rock"]] and
            rock["rockspec_sha256"] == pin["assets"][f"opentlv-{pin['rock_version']}.rockspec"] and
            rock["commit"] == pin["commit"] and rock["core_commit"] == pin["core_commit"] and
            rock["tag"] == pin["tag"], "Release rock provenance mismatch")
    return assets


def install_release(directory, pin, lua, rocks, lua_prefix):
    assets = acquire_release(directory / "downloads", pin)
    log = directory / "install.log"
    env = clean_env()
    # A fresh config prevents a user's LuaRocks variables from replacing build commands.
    config = directory / "luarocks-config.lua"
    config.write_text("rocks_servers = {}\n", encoding="utf-8")
    env["LUAROCKS_CONFIG"] = str(config)
    command = [rocks, "--lua-version=5.2", "--lua-dir=" + str(lua_prefix),
               "--tree=" + str(directory / "tree")]
    name = "opentlv-" + pin["rock_version"]
    run(command + ["unpack", directory / "downloads" / (name + ".src.rock")],
        cwd=directory, env=env, log=log)
    source = directory / name / "opentlv-lua"
    require((source / (name + ".rockspec")).read_bytes() ==
            (directory / "downloads" / (name + ".rockspec")).read_bytes(), "Unpacked rockspec differs")
    run(command + ["make", name + ".rockspec", "--deps-mode=none"],
        cwd=source, env=env, log=log, timeout=600)
    core = source / "build/luarocks/_deps/opentlv_core-src"
    core_commit = run(["git", "rev-parse", "HEAD"], cwd=core, env=env)
    require(core_commit == pin["core_commit"], "Installed release used a different Core")
    tree = directory / "tree"
    metadata_dir = tree / "lib/luarocks/rocks-5.2/opentlv" / pin["rock_version"]
    metadata = json.loads((metadata_dir / "lua-version.json").read_text(encoding="utf-8"))
    require(metadata == {"binding_version": pin["version"], "binding_revision": "",
                         "release_tag": pin["tag"], "dirty": False}, "Installed version mismatch")
    pure = tree / "share/lua/5.2/opentlv/init.lua"
    native = tree / "lib/lua/5.2/opentlv/_core.so"
    for installed, original in [(pure, source / "lua/opentlv/init.lua"),
                                (metadata_dir / (name + ".rockspec"), source / (name + ".rockspec")),
                                (metadata_dir / "doc/LICENSE", source / "LICENSE"),
                                (metadata_dir / "doc/LICENSE-Core", core / "LICENSE")]:
        require(installed.read_bytes() == original.read_bytes(), f"Installed payload differs: {installed}")
    paths = {"LUA_PATH": str(tree / "share/lua/5.2/?/init.lua"),
             "LUA_CPATH": str(tree / "lib/lua/5.2/?.so")}
    run([lua, ROOT / "tests/dependency_smoke.lua", pin["version"], native],
        cwd=directory, env={**env, **paths}, log=log)
    return {"acquisition": "fresh", "pin": pin, "assets": assets, "metadata": metadata,
            "core_commit": core_commit, "environment": paths,
            "installed_files": {str(p.relative_to(tree)): digest(p)
                                for p in tree.rglob("*") if p.is_file()},
            "tools": {"luarocks": run([rocks, "--version"], env=env),
                      "cmake": run(["cmake", "--version"], env=env).splitlines()[0]},
            "install_log": str(log)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lua", default="lua5.2")
    parser.add_argument("--make", default="make")
    parser.add_argument("--luarocks", default="luarocks")
    parser.add_argument("--lua-prefix", type=Path, help="Interpreter/headers prefix; default inferred from bin/lua")
    parser.add_argument("--cache-dir", type=Path, default=ROOT / "build/dependency-cache")
    parser.add_argument("--runs-dir", type=Path, default=ROOT / "build/dependency-runs")
    parser.add_argument("--external-only", action="store_true")
    parser.add_argument("--offline", action="store_true", help="Require cached external install; external-only mode")
    parser.add_argument("--print-cache-key", action="store_true")
    args = parser.parse_args()
    directory = None
    report = None
    try:
        require(not args.offline or args.external_only, "Offline mode requires --external-only")
        lua, make = executable(args.lua), executable(args.make)
        pin, configuration = load_pin(), context(lua, make)
        if args.print_cache_key:
            print(cache_key(pin, configuration))
            return 0
        args.runs_dir.mkdir(parents=True, exist_ok=True)
        directory = args.runs_dir.resolve() / str(uuid.uuid4())
        directory.mkdir()
        report = {"schema": 1, "run_id": directory.name, "status": "running",
                  "started_at": datetime.now(timezone.utc).isoformat(),
                  "configuration": configuration, "lua_executable": str(lua)}
        write_json(directory / "provenance.json", report)
        external = external_setup(args.cache_dir.resolve(), pin, configuration, make, offline=args.offline)
        report["external"] = external
        write_json(directory / "provenance.json", report)
        run([lua, ROOT / "tests/asn1_capabilities.lua", external["module_directory"]],
            env=clean_env(), log=directory / "capabilities.log")
        if not args.external_only:
            report["selected_opentlv"] = load_release_pin()
            write_json(directory / "provenance.json", report)
            report["opentlv"] = install_release(directory, report["selected_opentlv"], lua,
                                                executable(args.luarocks),
                                                (args.lua_prefix or lua.parent.parent).resolve())
        report["environment"] = {"LUA_PATH": external["module_directory"] + "/?/init.lua"}
        if "opentlv" in report:
            report["environment"]["LUA_PATH"] += ";" + report["opentlv"]["environment"]["LUA_PATH"]
            report["environment"]["LUA_CPATH"] = report["opentlv"]["environment"]["LUA_CPATH"]
        else:
            report["environment"]["LUA_CPATH"] = ""
        report["status"] = "passed"
        report["completed_at"] = datetime.now(timezone.utc).isoformat()
        write_json(directory / "provenance.json", report)
        print(f"External cache {'hit' if external['cache_hit'] else 'miss'}: {external['key']}")
        print(f"Provenance: {directory / 'provenance.json'}")
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        if directory and report is not None:
            # The running receipt never becomes a success receipt after a partial install.
            report["status"] = "failed"
            report["error"] = str(error)
            write_json(directory / "provenance.json", report)
            write_json(directory / "failure.json", {"status": "failed", "error": str(error)})
        print(f"Dependency setup failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
