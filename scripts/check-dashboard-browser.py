#!/usr/bin/env python3
# File purpose: Runs dashboard DOM acceptance checks in an ephemeral WebKit browser.
# Copyright (c) 2026 RealisLux
# SPDX-License-Identifier: MIT
# Project: https://github.com/RealisLux/NeoDSE

"""Run dashboard DOM acceptance checks in an ephemeral WebKit browser."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time


def exercise(base_url, source, output):
    import gi
    gi.require_version("Gtk", "4.0")
    gi.require_version("WebKit", "6.0")
    from gi.repository import Gtk, WebKit, GLib

    Gtk.init()
    loop = GLib.MainLoop()
    results = []
    manager = WebKit.UserContentManager()
    manager.register_script_message_handler("test_result", None)

    def received(_manager, value):
        results.append(json.loads(value.to_string()))
        loop.quit()

    manager.connect("script-message-received::test_result", received)
    manager.add_script(WebKit.UserScript.new(
        source, WebKit.UserContentInjectedFrames.TOP_FRAME,
        WebKit.UserScriptInjectionTime.START, None, None))
    view = WebKit.WebView(user_content_manager=manager,
                         network_session=WebKit.NetworkSession.new_ephemeral())
    window = Gtk.Window()
    window.set_default_size(1280, 900)
    window.set_child(view)
    window.present()
    view.load_uri(base_url)

    def expired():
        results.append({"failures": ["browser test deadline exceeded"]})
        loop.quit()
        return GLib.SOURCE_REMOVE

    timeout = GLib.timeout_add_seconds(120, expired)
    try:
        loop.run()
    finally:
        if results and results[0].get("completed"):
            GLib.source_remove(timeout)
        view.terminate_web_process()
        window.destroy()
    (output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps(results, indent=2), flush=True)
    return bool(results) and results[0].get("completed") and not results[0]["failures"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--url", required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    root = Path(__file__).resolve().parent.parent
    source = (root / "internal/dashboard/browser-check.js").read_text()
    with tempfile.TemporaryDirectory(prefix="neodse-dashboard-") as runtime:
        os.environ["XDG_RUNTIME_DIR"] = runtime
        os.environ["WAYLAND_DISPLAY"] = "dashboard-test"
        with (args.output / "weston.log").open("w") as log:
            weston = subprocess.Popen(
                ["weston", "--backend=headless-backend.so", "--socket=dashboard-test",
                 "--idle-time=0"], stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 10
                while not (Path(runtime) / "dashboard-test").exists():
                    if weston.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError("headless compositor failed to start")
                    time.sleep(0.05)
                return 0 if exercise(args.url, source, args.output) else 1
            finally:
                weston.terminate()
                try:
                    weston.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    weston.kill()
                    weston.wait()


if __name__ == "__main__":
    raise SystemExit(main())
