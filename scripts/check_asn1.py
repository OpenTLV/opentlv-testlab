#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel

"""Verify the source pin and run the narrow issue #2 capability audit."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "dependencies/lua-asn1.json"


def load_pin():
    pin = json.loads(LOCK.read_text(encoding="utf-8"))
    if pin["schema"] != 1 or not re.fullmatch(r"[0-9a-f]{40}", pin["commit"]):
        raise ValueError("Expected schema 1 and an exact upstream commit")
    if not re.fullmatch(r"[\w.-]+/[\w.-]+", pin["repository"]):
        raise ValueError("Invalid upstream repository")
    if pin["tag"] != "v" + pin["version"] or pin["runtime"] != "Lua 5.2":
        raise ValueError("Inconsistent version or unsupported audit runtime")
    if not {"LICENSE", "Makefile", "asn1/init.lua"} <= pin["files"].keys():
        raise ValueError("Source pin must include module, installation recipe and license")
    for name, digest in pin["files"].items():
        if not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", name):
            raise ValueError("Invalid source path")
        if any(part in (".", "..") for part in name.split("/")):
            raise ValueError("Source path escapes dependency directory")
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("Expected a SHA-256 digest")
    return pin


def verify_source(source, pin, download=False):
    for name, digest in pin["files"].items():
        path = source / name
        if download:
            url = (f"https://raw.githubusercontent.com/{pin['repository']}/"
                   f"{pin['commit']}/{name}")
            with urllib.request.urlopen(url, timeout=30) as response:
                data = response.read()
        else:
            data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError(f"SHA-256 mismatch: {name}")
        if download:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lua", default="lua5.2", help="Lua 5.2 executable")
    parser.add_argument("--source-dir", type=Path, default=ROOT / "build/asn1-source")
    parser.add_argument("--download", action="store_true",
                        help="Fetch pinned files, validating each before writing")
    args = parser.parse_args()
    try:
        pin = load_pin()
        source = args.source_dir.resolve()
        verify_source(source, pin, args.download)
        env = os.environ.copy()
        # Prevent startup hooks or Lua search paths from replacing the audited module.
        for key in list(env):
            if key.startswith(("LUA_INIT", "LUA_PATH", "LUA_CPATH")):
                del env[key]
        print(f"{pin['repository']} {pin['tag']} @ {pin['commit']}", flush=True)
        subprocess.run([args.lua, str(ROOT / "tests/asn1_capabilities.lua"),
                        str(source)], env=env, check=True, timeout=30)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"Capability audit failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
