#!/usr/bin/env python3
# File purpose: Checks that the SBOM contains every dependency embedded in packaged Go binaries.
# Copyright (c) 2026 RealisLux
# SPDX-License-Identifier: MIT
# Project: https://github.com/RealisLux/NeoDSE

"""Require the SBOM to contain every dependency embedded in packaged Go binaries."""

import json
from pathlib import Path
import subprocess
import sys


def main():
    if len(sys.argv) != 3:
        raise SystemExit("Usage: check-package-sbom.py STAGING_DIRECTORY SPDX_JSON")
    root, report = map(Path, sys.argv[1:])
    packages = json.loads(report.read_text())["packages"]
    found = {(p["name"], p.get("versionInfo")) for p in packages}
    binaries = sorted([
        *root.glob("*/payload/usr/bin/neodse-*"),
        *root.glob("*/payload/usr/lib/neodse/neodse-vnc-auth"),
    ])
    count = 0
    for binary in binaries:
        if binary.name == "neodse-ui":
            continue
        output = subprocess.check_output(["go", "version", "-m", str(binary)], text=True)
        lines = output.splitlines()
        if not lines or ": go" not in lines[0]:
            raise SystemExit(f"Missing Go build information: {binary}")
        required = {("stdlib", lines[0].rsplit(": ", 1)[1])}
        for line in lines[1:]:
            fields = line.split()
            if fields and fields[0] == "=>":
                raise SystemExit(f"Review replaced dependency in {binary}")
            if fields and fields[0] == "dep":
                required.add((fields[1], fields[2]))
        missing = required - found
        if missing:
            raise SystemExit(f"SBOM omits dependencies from {binary}: {sorted(missing)}")
        count += 1
    if not count:
        raise SystemExit("No packaged Go binaries found")
    print(f"SBOM covers embedded dependencies in {count} Go binaries")


if __name__ == "__main__":
    main()
