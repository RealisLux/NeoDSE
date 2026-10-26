#!/usr/bin/env python3
# File purpose: Reports Go test failures and rejects skips or incomplete release-validation results.
# Copyright (c) 2026 RealisLux
# SPDX-License-Identifier: MIT
# Project: https://github.com/RealisLux/NeoDSE

"""Report Go test failures and reject unexpected skips or incomplete results."""

import argparse
import json
import sys


class PackageOutput:
    """Keep quiet successful packages and bounded context before the first failure."""

    # Preserve both startup context and the latest assertions or panic stack.
    LIMIT = 128 * 1024

    def __init__(self):
        self.head = ""
        self.tail = ""
        self.omitted = 0
        self.visible = False

    def append(self, output):
        """Buffer output until failure, then stream it without replaying it."""
        if self.visible:
            print(output, end="", flush=True)
            return
        remaining = self.LIMIT // 2 - len(self.head)
        self.head += output[:remaining]
        self.tail += output[remaining:]
        if len(self.tail) > self.LIMIT // 2:
            self.omitted += len(self.tail) - self.LIMIT // 2
            self.tail = self.tail[-self.LIMIT // 2:]

    def reveal(self, package):
        """Print retained context once, including an explicit truncation notice."""
        if self.visible:
            return
        self.visible = True
        if self.head or self.tail:
            print(f"--- Go test output: {package} ---", flush=True)
            context = self.head
            if self.omitted:
                context += f"\n... {self.omitted} output characters omitted ...\n"
            context += self.tail
            print(context, end="" if context.endswith("\n") else "\n", flush=True)
        self.head = self.tail = ""


def main():
    """Consume go test -json while permitting only explicitly deferred integration tests."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-skip", action="append", default=[], metavar="PACKAGE:TEST")
    parser.add_argument("--require-test", action="append", default=[], metavar="PACKAGE:TEST")
    args = parser.parse_args()
    allowed, required = set(), set()
    for option, values, destination in (
            ("--allow-skip", args.allow_skip, allowed),
            ("--require-test", args.require_test, required)):
        for value in values:
            package, separator, test = value.rpartition(":")
            if not separator or not package or not test:
                parser.error(f"{option} requires PACKAGE:TEST")
            destination.add((package, test))
    started = set()
    completed = set()
    passed = set()
    outputs = {}
    failed = False

    def reveal_output(packages=None):
        for package, output in outputs.items():
            if packages is None or package in packages:
                output.reveal(package)

    try:
        for line in sys.stdin:
            event = json.loads(line)
            if not isinstance(event, dict):
                raise ValueError("invalid Go test event")
            action = event.get("Action")
            # go test -json also emits build events, identified by ImportPath.
            # Compiler diagnostics must remain visible even before tests start.
            if action in ("build-output", "build-fail"):
                if not isinstance(event.get("ImportPath"), str):
                    raise ValueError("invalid Go build event")
                if action == "build-output":
                    if not isinstance(event.get("Output"), str):
                        raise ValueError("invalid Go build output")
                    print(event["Output"], end="", flush=True)
                else:
                    failed = True
                    print(f"FAIL {event['ImportPath']} (build)", flush=True)
                continue
            if not isinstance(event.get("Package"), str):
                raise ValueError("invalid Go test event")
            package, test = event["Package"], event.get("Test")
            output = outputs.setdefault(package, PackageOutput())
            if action == "output":
                if not isinstance(event.get("Output"), str):
                    raise ValueError("invalid Go test output")
                output.append(event["Output"])
            if action == "start" and test is None:
                started.add(package)
            if action == "pass" and test is not None:
                passed.add((package, test))
            if action == "skip" and test is not None:
                expected = (package, test) in allowed
                if not expected or (package, test) in required:
                    output.reveal(package)
                print(f"{'DEFERRED' if expected else 'UNEXPECTED'} SKIP {package}/{test}", flush=True)
                failed |= not expected
            if action == "fail":
                failed = True
                output.reveal(package)
                if test is not None:
                    print(f"FAIL {package}/{test}", flush=True)
            if action in ("pass", "fail", "skip") and test is None:
                completed.add(package)
                print(f"{action.upper()} {package}", flush=True)
    except (ValueError, TypeError) as error:
        reveal_output()
        invalid_output = PackageOutput()
        invalid_output.append(line)
        invalid_output.reveal("invalid event")
        raise SystemExit(f"Invalid test result stream: {error}") from error
    if not started or started != completed:
        reveal_output(None if not started else set(outputs) - completed)
        raise SystemExit("Incomplete Go test result stream")
    if missing := required - passed:
        reveal_output({package for package, _ in missing})
        raise SystemExit(f"Required Go tests did not pass: {sorted(missing)}")
    if failed:
        raise SystemExit("Required Go tests failed or skipped")


if __name__ == "__main__":
    main()
