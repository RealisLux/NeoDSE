#!/usr/bin/env python3
# File purpose: Collects upstream notices for the Go dependencies actually linked into a package.
# Copyright (c) 2026 RealisLux
# SPDX-License-Identifier: MIT
# Project: https://github.com/RealisLux/NeoDSE

"""Collect upstream notices for the Go dependencies actually linked into a package."""

import json
from pathlib import Path
import subprocess
import sys


def go(*args):
    return subprocess.check_output(["go", *args], text=True)


def documents(text):
    decoder = json.JSONDecoder()
    while text.strip():
        value, end = decoder.raw_decode(text.lstrip())
        yield value
        text = text.lstrip()[end:]


def notices(directory):
    for path in sorted(directory.iterdir()):
        name = path.name.upper()
        if path.is_file() and any(name == key or name.startswith((key + "-", key + ".", key + "_"))
                                  for key in ("LICENSE", "COPYING", "NOTICE", "COPYRIGHT", "PATENTS")):
            yield path


def main():
    if len(sys.argv) < 4 or sys.argv[1] not in ("client", "server"):
        raise SystemExit("Usage: package-notices.py client|server OUTPUT BINARY...")
    component, output, *binaries = sys.argv[1:]
    dependencies = {}
    commands = []
    for binary in binaries:
        for line in go("version", "-m", binary).splitlines()[1:]:
            fields = line.split()
            if fields and fields[0] == "=>":
                raise SystemExit("Replaced dependencies require license review")
            if fields and fields[0] == "path":
                commands.append(fields[1])
            if fields and fields[0] == "dep":
                name, version = fields[1:3]
                if name in dependencies and dependencies[name] != version:
                    raise SystemExit(f"Conflicting linked versions: {name}")
                dependencies[name] = version
    if not commands or not dependencies:
        raise SystemExit("Missing linked dependency information")
    modules = {m["Path"]: m for m in documents(go("list", "-m", "-json", *sorted(dependencies)))}
    directories = {}
    for name, version in dependencies.items():
        module = modules[name]
        if module["Version"] != version or module.get("Replace"):
            raise SystemExit(f"Binary does not match current module: {name}")
        directory = Path(module["Dir"])
        if not list(notices(directory)):
            raise SystemExit(f"No upstream license found: {name}")
        directories[name] = {directory}
    # Include additional notices in ancestors of compiled dependency packages.
    for package in documents(go("list", "-deps", "-json", *commands)):
        name = package.get("Module", {}).get("Path")
        if name not in directories:
            continue
        root = Path(modules[name]["Dir"])
        directory = Path(package["Dir"])
        while directory != root:
            if root not in directory.parents:
                raise SystemExit(f"Package escapes module: {directory}")
            directories[name].add(directory)
            directory = directory.parent
    sections = ["Third-party notices for NeoDSE\n\n"
                "These notices cover linked Go dependencies and embedded assets.\n"
                "System libraries are supplied and licensed by the host distribution.\n"]
    goroot = Path(go("env", "GOROOT").strip())
    for path in notices(goroot):
        sections.append(f"Go toolchain / {path.name}\n\n{path.read_text()}")
    for name in sorted(directories):
        for directory in sorted(directories[name]):
            for path in notices(directory):
                label = path.relative_to(modules[name]["Dir"])
                sections.append(f"{name} {dependencies[name]} / {label}\n\n{path.read_text()}")
    if component == "server":
        sections.append("Embedded Swagger UI\n\n" + Path("internal/swagger/vendor/LICENSE").read_text())
        sections.append("Embedded Swagger UI dependency notices\n\n" + Path("internal/swagger/vendor/swagger-ui-bundle.js.LICENSE.txt").read_text())
        sections.append(Path("internal/swagger/vendor/THIRD-PARTY-NOTICES").read_text())
    Path(output).write_text("\n\n".join(sections))


if __name__ == "__main__":
    main()
