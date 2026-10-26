#!/usr/bin/env python3
# File purpose: Validates scanner vulnerability findings with narrowly scoped SDK exceptions.
# Copyright (c) 2026 RealisLux
# SPDX-License-Identifier: MIT
# Project: https://github.com/RealisLux/NeoDSE

"""Validate scanner vulnerability findings with narrowly scoped SDK exceptions."""

import argparse
import json
import sys


def documents(raw):
    """Decode govulncheck's JSON stream, rejecting truncated or malformed records."""
    decoder = json.JSONDecoder()
    offset = 0
    result = []
    while offset < len(raw):
        if raw[offset].isspace():
            offset += 1
            continue
        record, offset = decoder.raw_decode(raw, offset)
        if not isinstance(record, dict) or len(record) != 1:
            raise ValueError("Invalid govulncheck record")
        result.append(record)
    return result


def verify(records, scanner, mode="source"):
    """Reject affected packages except reviewed Docker SDK attribution errors."""
    configs = [item["config"] for item in records if "config" in item]
    sboms = [item["SBOM"] for item in records if "SBOM" in item]
    if (len(configs) != 1 or len(sboms) != 1
            or configs[0].get("scanner_name") != "govulncheck"
            or configs[0].get("scan_mode") != mode
            or configs[0].get("scan_level") != ("package" if mode == "source" else "symbol")):
        raise ValueError("Missing scanner analysis evidence")
    if any(next(iter(item)) not in {"config", "SBOM", "osv", "finding", "progress"}
           for item in records):
        raise ValueError("Unknown govulncheck record")
    advisories = {}
    for item in records:
        if "osv" not in item:
            continue
        advisory = item["osv"]
        identifier = advisory["id"]
        # One advisory can affect multiple modules and appear once per module.
        if identifier in advisories and advisories[identifier] != advisory:
            raise ValueError("Conflicting advisory evidence")
        advisories[identifier] = advisory
    findings = [item["finding"] for item in records if "finding" in item]
    reviewed = set()
    module_only = set()
    for finding in findings:
        identifier = finding.get("osv")
        trace = finding.get("trace")
        if (not isinstance(identifier, str) or identifier not in advisories
                or not isinstance(trace, list) or len(trace) != 1
                or any(not isinstance(frame, dict) for frame in trace)):
            raise ValueError("Invalid vulnerability finding")
        frame = trace[0]
        if (not isinstance(frame.get("module"), str) or not frame["module"]
                or not isinstance(frame.get("version"), str) or not frame["version"]
                or ("function" in frame and (mode != "binary"
                    or not isinstance(frame["function"], str) or not frame["function"]
                    or "package" not in frame))):
            raise ValueError("Missing affected module/version")
        package = frame.get("package")
        if "package" not in frame:
            module_only.add(identifier)
            continue
        if not isinstance(package, str) or not package:
            raise ValueError("Invalid affected package")
        # These unreviewed records omit package scope and attribute daemon-only
        # plugin flaws to every SDK package. SECURITY_EXCEPTIONS.md records the
        # evidence. The review concerns the Docker SDK, not the Grype release that
        # imports it: a changed Docker or helper version, package scope or advisory
        # scope fails closed.
        affected = [item for item in advisories[identifier].get("affected", [])
                    if item.get("package", {}).get("name") == "github.com/docker/docker"]
        sdk = (frame["module"] == "github.com/docker/docker"
               and frame["version"] == "v28.5.2+incompatible"
               and (package == "github.com/docker/docker/client"
                    or package == "github.com/docker/docker/api"
                    or package == "github.com/docker/docker/api/types"
                    or package.startswith("github.com/docker/docker/api/types/")))
        # In binary mode, the unknown-module lookup also attributes these
        # module-wide Docker records to the separately versioned SDK helpers.
        helpers = (mode == "binary"
                   and frame["module"] == "github.com/docker/docker-credential-helpers"
                   and frame["version"] == "v0.9.8"
                   and package in {"github.com/docker/docker-credential-helpers/client",
                                   "github.com/docker/docker-credential-helpers/credentials"})
        grype = any(item.get("path") == "github.com/anchore/grype"
                    for item in sboms[0].get("modules", []))
        docker = any(item.get("path") == "github.com/docker/docker"
                     and item.get("version") == "v28.5.2+incompatible"
                     for item in sboms[0].get("modules", []))
        if (scanner == "grype" and grype and docker and (sdk or helpers)
                and identifier in {"GO-2026-4883", "GO-2026-4887"}
                and len(affected) == 1 and affected[0].get("ecosystem_specific") == {}):
            reviewed.add(identifier)
            continue
        raise ValueError(f"Affected scanner package: {identifier}: {package}")
    return reviewed, module_only - reviewed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scanner", required=True, choices=("syft", "grype"))
    parser.add_argument("--mode", choices=("source", "binary"), default="source")
    args = parser.parse_args()
    try:
        raw = sys.stdin.read(16 * 1024 * 1024 + 1)
        if len(raw) > 16 * 1024 * 1024:
            raise ValueError("Scanner evidence exceeds 16 MiB")
        reviewed, module_only = verify(documents(raw), args.scanner, mode=args.mode)
    except (KeyError, TypeError, AttributeError, ValueError) as error:
        raise SystemExit(f"Scanner evidence rejected: {error}") from error
    print(f"{args.scanner} {args.mode}: no unresolved affected code; "
          f"reviewed SDK findings={sorted(reviewed)}, module-only findings={sorted(module_only)}")


if __name__ == "__main__":
    main()
