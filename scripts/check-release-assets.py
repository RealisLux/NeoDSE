#!/usr/bin/env python3
# File purpose: Verifies the exact release matrix, checksums, SBOMs and vulnerability evidence.
# Copyright (c) 2026 RealisLux
# SPDX-License-Identifier: MIT
# Project: https://github.com/RealisLux/NeoDSE

"""Verify the exact release matrix, checksums, SBOMs and vulnerability evidence."""

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import sys


def package_names(version):
    """Enumerate the supported distribution, component and architecture matrix."""
    names = {
        f"NeoDSE-{component}_{version}_{target}_{arch}.deb"
        for target in ("debian13", "ubuntu26.04")
        for component in ("client", "server")
        for arch in ("amd64", "arm64")
    }
    names.update(f"NeoDSE-server_{version}_{target}_amd64.rpm" for target in ("el9", "el10"))
    return sorted(names)


def verify_published_assets(document, version):
    """Reject missing, duplicate or unexpected assets on a resumed GitHub draft."""
    assets = document.get("assets") if isinstance(document, dict) else None
    if (not isinstance(assets, list)
            or any(not isinstance(asset, dict) or not isinstance(asset.get("name"), str)
                   or asset.get("state") != "uploaded" for asset in assets)):
        raise ValueError("GitHub release assets must be completely uploaded")
    expected = {name + suffix for name in package_names(version)
                for suffix in ("", ".sha256")} | {"SHA256SUMS"}
    names = [asset["name"] for asset in assets]
    if len(names) != len(expected) or set(names) != expected:
        raise ValueError("GitHub release assets differ from the expected packages and checksums")
    print(f"Verified all {len(expected)} uploaded GitHub release assets")


def digest(path):
    """Hash large packages with bounded memory."""
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_checksums(path, expected, hashes):
    """Reject incomplete, duplicate or escaping manifest entries before comparison."""
    if path.stat().st_size > 64 * 1024:
        raise ValueError(f"Checksum manifest is oversized: {path.name}")
    entries = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64}) [ *](?:\./)?([A-Za-z0-9_+.-]+)", line)
        if match is None:
            raise ValueError(f"Invalid checksum entry in {path.name}")
        checksum, name = match.groups()
        if name in entries:
            raise ValueError(f"Duplicate checksum entry in {path.name}: {name}")
        entries[name] = checksum
    if set(entries) != expected:
        raise ValueError(f"Checksum coverage differs from the expected assets: {path.name}")
    for name, checksum in entries.items():
        if checksum != hashes[name]:
            raise ValueError(f"Checksum mismatch: {name}")


def read_evidence(path):
    """Read one bounded JSON evidence object from a verified regular file."""
    with path.open("rb") as stream:
        raw = stream.read(64 * 1024 * 1024 + 1)
    if len(raw) > 64 * 1024 * 1024:
        raise ValueError(f"Evidence exceeds 64 MiB: {path.name}")
    document = json.loads(raw)
    if not isinstance(document, dict):
        raise ValueError(f"Evidence must be a JSON object: {path.name}")
    return document


def verify_evidence(directory, package, package_digest):
    """Bind SPDX evidence to its archive and reject invalid or high-risk scan results."""
    sbom = read_evidence(directory / f"{package}.spdx.json")
    packages = sbom.get("packages")
    if (sbom.get("spdxVersion") not in ("SPDX-2.2", "SPDX-2.3")
            or sbom.get("SPDXID") != "SPDXRef-DOCUMENT"
            or not isinstance(packages, list) or not packages
            or any(not isinstance(item, dict) or not isinstance(item.get("name"), str)
                   or not item["name"] for item in packages)):
        raise ValueError(f"Invalid SPDX package evidence: {package}")
    component = package.split("_", 1)[0].removeprefix("NeoDSE-")
    if not any(item.get("name") == f"neodse-{component}"
               and isinstance(item.get("versionInfo"), str) and item["versionInfo"]
               for item in packages):
        raise ValueError(f"SPDX omits the expected NeoDSE component: {package}")
    # Staging includes the original archive alongside its extracted payload.
    # Bind the dependency evidence to that exact archive, not just its component.
    files = sbom.get("files")
    if not isinstance(files, list):
        raise ValueError(f"SPDX omits the package archive: {package}")
    archives = [item for item in files
                if isinstance(item, dict) and isinstance(item.get("fileName"), str)
                and Path(item["fileName"]).name == package]
    if len(archives) != 1:
        raise ValueError(f"SPDX must identify one matching package archive: {package}")
    checksums = archives[0].get("checksums")
    if not isinstance(checksums, list) or not any(
            isinstance(item, dict) and item.get("algorithm") == "SHA256"
            and item.get("checksumValue") == package_digest for item in checksums):
        raise ValueError(f"SPDX package archive checksum differs: {package}")
    # Standard Syft source metadata survives Grype's SPDX import. Give every
    # archive its own identity so reports from another package cannot be mixed in.
    identity = f"sha256:{package_digest}"
    if sbom.get("name") != identity:
        raise ValueError(f"SPDX source differs from the package archive: {package}")
    report = read_evidence(directory / f"{package}.vulnerabilities.json")
    descriptor = report.get("descriptor")
    matches = report.get("matches")
    ignored = report.get("ignoredMatches", [])
    if (not isinstance(descriptor, dict) or descriptor.get("name") != "grype"
            or not isinstance(matches, list) or not isinstance(ignored, list)):
        raise ValueError(f"Invalid Grype vulnerability evidence: {package}")
    source = report.get("source")
    if (not isinstance(source, dict) or source.get("type") != "directory"
            or source.get("target") != identity):
        raise ValueError(f"Grype source differs from the package archive: {package}")
    database = descriptor.get("db")
    status = database.get("status") if isinstance(database, dict) else None
    configuration = descriptor.get("configuration")
    version = descriptor.get("version")
    if (not isinstance(version, str) or re.fullmatch(r"\d+\.\d+\.\d+", version) is None
            or not isinstance(status, dict) or status.get("valid") is not True
            or not isinstance(configuration, dict)):
        raise ValueError(f"Missing valid scanner/database evidence: {package}")
    # Path exclusions remove packages before matching, so those findings never
    # reach either result list. Require evidence of a complete, unfiltered scan.
    if (configuration.get("only-fixed") is not False
            or configuration.get("only-notfixed") is not False
            or configuration.get("ignore-wontfix") != ""
            or configuration.get("exclude") != []):
        raise ValueError(f"Filtered or incomplete vulnerability scan: {package}")
    target = package.rsplit("_", 2)[1]
    expected_distro = {"debian13": ("debian", "13"),
                       "ubuntu26.04": ("ubuntu", "26.04"),
                       "el9": ("rockylinux", "9"),
                       "el10": ("rockylinux", "10")}[target]
    distribution = report.get("distro")
    if (not isinstance(distribution, dict)
            or (distribution.get("name"), distribution.get("version")) != expected_distro):
        raise ValueError(f"Vulnerability scan distribution differs from the package target: {package}")
    # Grype's normal database freshness limit is five days. Recheck at publication,
    # including after an environment approval delay; timestamps need explicit zones.
    now = datetime.now(timezone.utc)
    for field in (descriptor.get("timestamp"), status.get("built")):
        if not isinstance(field, str):
            raise ValueError(f"Missing scanner/database timestamp: {package}")
        timestamp = datetime.fromisoformat(field)
        if (timestamp.utcoffset() is None or timestamp < now - timedelta(days=5)
                or timestamp > now + timedelta(minutes=5)):
            raise ValueError(f"Stale or invalid scanner/database timestamp: {package}")
    # Ignore rules and VEX decisions move findings out of matches. They do not
    # authorize exceptions to the release's high/critical vulnerability gate.
    for match in matches + ignored:
        vulnerability = match.get("vulnerability") if isinstance(match, dict) else None
        severity = vulnerability.get("severity") if isinstance(vulnerability, dict) else None
        if severity not in ("Unknown", "Negligible", "Low", "Medium", "High", "Critical"):
            raise ValueError(f"Invalid vulnerability severity: {package}")
        if severity in ("High", "Critical"):
            raise ValueError(f"Unresolved {severity.lower()} vulnerability: {package}")


def verify_directory(directory, manifest, version):
    """Validate every expected artifact, refusing extras and symbolic links."""
    packages = package_names(version)
    manifest_name = "SHA256SUMS"
    # Reports remain mandatory CI evidence; the public manifest covers downloads only.
    published = {name + suffix for name in packages for suffix in ("", ".sha256")}
    expected = {name + suffix for name in packages
                for suffix in ("", ".sha256", ".spdx.json", ".vulnerabilities.json")}
    contents = list(directory.iterdir())
    if any(path.is_symlink() or not path.is_file() for path in contents):
        raise ValueError("Release assets must be regular files without symbolic links")
    if {path.name for path in contents} != expected | ({manifest_name} if manifest else set()):
        raise ValueError("Release assets differ from the supported ten-package matrix")
    hashes = {name: digest(directory / name) for name in expected}
    for package in packages:
        verify_checksums(directory / f"{package}.sha256", {package}, hashes)
        verify_evidence(directory, package, hashes[package])
    if manifest:
        verify_checksums(directory / manifest_name, published, hashes)
    print(f"Verified {len(expected) + int(manifest)} assets for all {len(packages)} packages")


def release_version(value):
    """Accept a filename-safe SemVer without a tag prefix or numeric leading zeros."""
    number = r"(?:0|[1-9][0-9]*)"
    prerelease = r"(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    pattern = rf"{number}\.{number}\.{number}(?:-{prerelease}(?:\.{prerelease})*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    if len(value) > 128 or re.fullmatch(pattern, value) is None:
        raise argparse.ArgumentTypeError("version must be a valid SemVer without the v tag prefix")
    return value


def main():
    """Expose matrix inspection, local evidence and uploaded asset validation to CI."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", nargs="?", type=Path)
    parser.add_argument("--version", required=True, type=release_version, help="application version, without the v tag prefix")
    parser.add_argument("--manifest", action="store_true", help="require SHA256SUMS covering only published packages and checksums")
    parser.add_argument("--list-packages", action="store_true")
    parser.add_argument("--published-assets", action="store_true", help="validate GitHub release assets JSON from standard input")
    args = parser.parse_args()
    if args.list_packages:
        if args.directory is not None or args.manifest or args.published_assets:
            parser.error("--list-packages cannot be combined with asset validation")
        print("\n".join(package_names(args.version)))
        return
    if args.published_assets and (args.directory is not None or args.manifest):
        parser.error("--published-assets cannot be combined with local asset validation")
    if args.directory is None and not args.published_assets:
        parser.error("an asset directory is required")
    try:
        if args.published_assets:
            verify_published_assets(json.load(sys.stdin), args.version)
        else:
            verify_directory(args.directory, args.manifest, args.version)
    except (OSError, UnicodeError, ValueError) as error:
        raise SystemExit(f"Release evidence rejected: {error}") from error


if __name__ == "__main__":
    main()
