#!/usr/bin/env python3
# File purpose: Exercises real GTK/WebKit IPC and shutdown under headless Wayland.
# Copyright (c) 2026 RealisLux
# SPDX-License-Identifier: MIT
# Project: https://github.com/RealisLux/NeoDSE

"""Exercise real GTK/WebKit IPC and shutdown under headless Wayland."""

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import pwd
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import parse_qs, urlsplit


def wait_socket(path, process):
    """Wait for a service socket while also detecting early process failure."""
    deadline = time.monotonic() + 15
    while not path.exists():
        if process.poll() is not None or time.monotonic() >= deadline:
            raise RuntimeError(f"startup failed for {path}; inspect the process log")
        time.sleep(0.05)


def connect(path):
    """Open one bounded-time connection to the renderer IPC socket."""
    peer = socket.socket(socket.AF_UNIX)
    peer.settimeout(12)
    peer.connect(str(path))
    return peer


def request(path, payload):
    """Send one IPC command and decode its bounded JSON response."""
    with connect(path) as peer:
        peer.sendall(payload)
        peer.shutdown(socket.SHUT_WR)
        response = bytearray()
        while chunk := peer.recv(65536):
            response.extend(chunk)
            if len(response) > 1024 * 1024:
                raise RuntimeError("IPC response exceeds limit")
    return json.loads(response)


def check_unauthorized(path):
    """Verify that the renderer rejects a peer with an unauthorized UID."""
    account = pwd.getpwnam("nobody")
    # Give the test peer directory/socket group access so the rejection proves
    # SO_PEERCRED enforcement, rather than failing at filesystem permissions.
    def drop_uid():
        """Enter the unprivileged identity immediately before exec."""
        os.setgroups([])
        os.setgid(path.parent.stat().st_gid)
        os.setuid(account.pw_uid)

    code = """
import socket, sys
with socket.socket(socket.AF_UNIX) as peer:
    peer.settimeout(3)
    peer.connect(sys.argv[1])
    try:
        peer.sendall(b'{"cmd":"status","message":"must be rejected"}\\n')
        peer.shutdown(socket.SHUT_WR)
        assert peer.recv(1024) == b'', 'unauthorized peer received an IPC response'
    except (BrokenPipeError, ConnectionResetError):
        pass
"""
    subprocess.run([sys.executable, "-c", code, str(path)], preexec_fn=drop_uid,
                   check=True, timeout=5)


def check_runtime_permissions():
    """Verify IPC group access cannot replace Weston configuration or sockets."""
    configuration = Path(__file__).resolve().parent.parent / "config/neodse.conf"
    entries = [line.split() for line in configuration.read_text().splitlines()
               if line.startswith("d /run/neodse ")]
    assert len(entries) == 1, "missing unique IPC runtime directory policy"
    mode = int(entries[0][2], 8)
    account = pwd.getpwnam("nobody")
    with tempfile.TemporaryDirectory(prefix="neodse-ipc-permissions-") as directory:
        parent = Path(directory)
        parent.chmod(0o755)
        shared = parent / "neodse"
        shared.mkdir()
        shared.chmod(mode)
        compositor_configuration = shared / "weston.ini"
        compositor_configuration.write_text("[vnc]\nrefresh-rate=10\n")
        compositor_configuration.chmod(0o600)
        path = shared / "ui.sock"
        with socket.socket(socket.AF_UNIX) as server:
            server.bind(str(path))
            path.chmod(0o660)
            server.listen(1)

            def drop_uid():
                """Model an agent with IPC group membership and a separate UID."""
                os.setgroups([])
                os.setgid(shared.stat().st_gid)
                os.setuid(account.pw_uid)

            code = """
from pathlib import Path
import socket, sys
directory = Path(sys.argv[1])
with socket.socket(socket.AF_UNIX) as peer:
    peer.settimeout(3)
    peer.connect(str(directory / 'ui.sock'))
for name in ('weston.ini', 'ui.sock'):
    try:
        (directory / name).unlink()
    except PermissionError:
        pass
    else:
        raise AssertionError(f'IPC group replaced {name}')
try:
    (directory / 'injected.ini').write_text('[core]\\nmodules=untrusted.so\\n')
except PermissionError:
    pass
else:
    raise AssertionError('IPC group created compositor configuration')
"""
            subprocess.run([sys.executable, "-c", code, str(shared)],
                           preexec_fn=drop_uid, check=True, timeout=5)
            with server.accept()[0]:
                pass
        path.unlink()
    print("IPC runtime permissions: group connection allowed; configuration and "
          "socket replacement denied", flush=True)


def stop(process):
    """Stop a test process, escalating to SIGKILL only after a timeout."""
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def pause_web_processes(parent):
    """Pause every WebKit child process and return their pidfds."""
    pending = [parent]
    seen = set()
    paused = []
    while pending:
        pid = pending.pop()
        if pid in seen:
            continue
        seen.add(pid)
        for task in Path(f"/proc/{pid}/task").glob("*"):
            try:
                pending.extend(int(child) for child in (task / "children").read_text().split())
            except FileNotFoundError:
                pass
        try:
            executable = Path(f"/proc/{pid}/exe").resolve(strict=True).name
            if executable == "WebKitWebProcess":
                handle = os.pidfd_open(pid)
                signal.pidfd_send_signal(handle, signal.SIGSTOP)
                paused.append(handle)
        except (ProcessLookupError, FileNotFoundError):
            pass
    return paused


def wait_and_pause_web_processes(process):
    """Wait for asynchronous WebKit startup before testing stalled-child shutdown."""
    deadline = time.monotonic() + 15
    while process.poll() is None and time.monotonic() < deadline:
        paused = pause_web_processes(process.pid)
        if paused:
            return paused
        time.sleep(0.05)
    raise RuntimeError("no renderer WebKit child found for the stalled-renderer check")


def check_playlist_retry(ipc_path, process, log_path):
    """Verify that synchronizing playback preserves failed-document recovery."""
    recovered = threading.Event()
    restore = threading.Event()

    class ProxyFixture(BaseHTTPRequestHandler):
        """Serve a temporary proxy failure, then a successful playlist document."""

        def do_GET(self):
            """Record the successful retry only after playback synchronization."""
            healthy = restore.is_set()
            body = b"<html><body>Recovered playlist</body></html>"
            self.send_response(200 if healthy else 503)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            if healthy and self.path == "http://playlist.example.test/":
                recovered.set()

        def log_message(self, _format, *args):
            """Keep fixture requests out of release diagnostics."""

    with ThreadingHTTPServer(("127.0.0.1", 0), ProxyFixture) as proxy:
        worker = threading.Thread(target=proxy.serve_forever, daemon=True)
        worker.start()
        try:
            for command in (
                {"cmd": "proxy_config", "url": f"http://127.0.0.1:{proxy.server_port}"},
                {"cmd": "playlist", "urls": ["http://playlist.example.test/"], "start_at": 0},
            ):
                response = request(ipc_path, json.dumps(command).encode() + b"\n")
                assert response["status"] == "accepted", response
            deadline = time.monotonic() + 15
            while "Playlist view loaded index=0" not in log_path.read_text():
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("initial proxy failure document did not load")
                time.sleep(0.05)
            response = request(ipc_path, json.dumps({"cmd": "playback",
                               "start_at": int(time.time())}).encode() + b"\n")
            assert response["status"] == "accepted", response
            restore.set()
            assert recovered.wait(15), "playback synchronization cancelled the page retry"
        finally:
            proxy.shutdown()
            worker.join(timeout=5)


def check_browser_dialog_policy(ipc_path):
    """Verify remote JavaScript cannot strand the kiosk in interactive dialogs."""
    completed = threading.Event()
    authentication_challenged = threading.Event()
    authentication_completed = threading.Event()
    replacement = threading.Event()
    results = []
    authentication_results = []

    class ProxyFixture(BaseHTTPRequestHandler):
        """Record real WebKit dialog results and subsequent playlist navigation."""

        def do_GET(self):
            """Serve dialog-triggering content through the renderer's explicit proxy."""
            target = urlsplit(self.path)
            if target.path == "/dialogs":
                body = b"""<!doctype html><html><body><script>
window.print();
alert("Unattended alert");
const confirmed = confirm("Unattended confirmation");
const prompted = prompt("Unattended prompt", "must not be accepted");
window.onbeforeunload = () => "The controller must be able to replace this page";
fetch("/dialog-result?confirmed=" + confirmed + "&cancelled=" + (prompted === null));
fetch("/auth-required").then(response => response.status).catch(() => "cancelled")
  .then(status => fetch("/auth-result?status=" + status));
</script></body></html>"""
            else:
                body = b"<!doctype html><html><body>Browser policy check</body></html>"
            self.send_response(401 if target.path == "/auth-required" else 200)
            if target.path == "/auth-required":
                assert "Authorization" not in self.headers, "website received unintended credentials"
                self.send_header("WWW-Authenticate", 'Basic realm="Unattended login"')
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            if target.path == "/dialog-result":
                results.append(parse_qs(target.query))
                completed.set()
            elif target.path == "/auth-result":
                authentication_results.append(parse_qs(target.query).get("status"))
                authentication_completed.set()
            elif target.path == "/auth-required":
                authentication_challenged.set()
            elif target.path == "/replacement":
                replacement.set()

        def log_message(self, _format, *args):
            """Keep fixture requests out of release diagnostics."""

    with ThreadingHTTPServer(("127.0.0.1", 0), ProxyFixture) as proxy:
        worker = threading.Thread(target=proxy.serve_forever, daemon=True)
        worker.start()
        try:
            for command in (
                {"cmd": "proxy_config", "url": f"http://127.0.0.1:{proxy.server_port}"},
                {"cmd": "playlist", "urls": ["http://policy.example.test/dialogs"], "start_at": 0},
            ):
                response = request(ipc_path, json.dumps(command).encode() + b"\n")
                assert response["status"] == "accepted", response
            assert completed.wait(10), "remote JavaScript remained blocked by an interactive dialog"
            assert results == [{"confirmed": ["false"], "cancelled": ["true"]}], results
            assert authentication_challenged.wait(10), "website authentication challenge was not exercised"
            assert authentication_completed.wait(10), "website login challenge opened an interactive dialog"
            assert authentication_results[0] in (["401"], ["cancelled"]), authentication_results
            response = request(ipc_path, json.dumps({
                "cmd": "playlist", "urls": ["http://policy.example.test/replacement"],
                "start_at": 0,
            }).encode() + b"\n")
            assert response["status"] == "accepted", response
            assert replacement.wait(10), "remote content prevented controller playlist replacement"
        finally:
            proxy.shutdown()
            worker.join(timeout=5)


def check_playlist_reload(ipc_path):
    """Verify reload refreshes cached resources in visible and hidden playlist views."""
    condition = threading.Condition()
    generation = 1
    loaded = {}
    pages = [f"/page-{index}" for index in range(3)]

    class ProxyFixture(BaseHTTPRequestHandler):
        """Serve cacheable scripts whose version changes after initial page loads."""

        def do_GET(self):
            """Report the script version actually executed in each playlist view."""
            target = urlsplit(self.path)
            if target.path in pages:
                body = (f'<!doctype html><html><body><script src="{target.path}.js">'
                        '</script></body></html>').encode()
                content_type = "text/html"
            elif target.path.endswith(".js"):
                page = target.path.removesuffix(".js")
                with condition:
                    version = generation
                body = (f'fetch("/loaded?page={page}&version={version}", '
                        '{cache: "no-store"});').encode()
                content_type = "application/javascript"
            else:
                body = b"ok"
                content_type = "text/plain"
            self.send_response(200)
            self.send_header("Cache-Control", "public, max-age=3600"
                             if target.path.endswith(".js") else "no-store")
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            if target.path == "/loaded":
                query = parse_qs(target.query)
                with condition:
                    loaded[query["page"][0]] = int(query["version"][0])
                    condition.notify_all()

        def log_message(self, _format, *args):
            """Keep fixture requests out of release diagnostics."""

    with ThreadingHTTPServer(("127.0.0.1", 0), ProxyFixture) as proxy:
        worker = threading.Thread(target=proxy.serve_forever, daemon=True)
        worker.start()
        try:
            for command in (
                {"cmd": "proxy_config", "url": f"http://127.0.0.1:{proxy.server_port}"},
                {"cmd": "playlist", "urls": [f"http://reload.example.test{page}" for page in pages],
                 "interval": 86400, "start_at": 0},
            ):
                response = request(ipc_path, json.dumps(command).encode() + b"\n")
                assert response["status"] == "accepted", response
            with condition:
                assert condition.wait_for(lambda: all(loaded.get(page) == 1 for page in pages),
                                          timeout=15), f"initial playlist did not load: {loaded}"
                generation = 2
            response = request(ipc_path, b'{"cmd":"reload"}\n')
            assert response["status"] == "accepted", response
            with condition:
                assert condition.wait_for(lambda: all(loaded.get(page) == 2 for page in pages),
                                          timeout=15), f"reload left stale playlist content: {loaded}"
        finally:
            proxy.shutdown()
            worker.join(timeout=5)


def check_browser_process_recovery(ipc_path, process):
    """Verify a crashed WebKit child recovers without restarting its GTK parent."""
    loaded = threading.Event()
    recovered = threading.Event()
    crashed = threading.Event()

    class ProxyFixture(BaseHTTPRequestHandler):
        """Confirm that the document's JavaScript runs before and after a crash."""

        def do_GET(self):
            """Serve one document and record its post-load JavaScript request."""
            target = urlsplit(self.path)
            body = (b"<!doctype html><html><body>Process recovery"
                    b"<script>fetch('/loaded');</script></body></html>"
                    if target.path == "/" else b"ok")
            self.send_response(200)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            if target.path == "/loaded":
                (recovered if crashed.is_set() else loaded).set()

        def log_message(self, _format, *args):
            """Keep fixture requests out of release diagnostics."""

    with ThreadingHTTPServer(("127.0.0.1", 0), ProxyFixture) as proxy:
        worker = threading.Thread(target=proxy.serve_forever, daemon=True)
        worker.start()
        try:
            for command in (
                {"cmd": "proxy_config", "url": f"http://127.0.0.1:{proxy.server_port}"},
                {"cmd": "playlist", "urls": ["http://recovery.example.test/"], "start_at": 0},
            ):
                response = request(ipc_path, json.dumps(command).encode() + b"\n")
                assert response["status"] == "accepted", response
            assert loaded.wait(15), "initial document JavaScript did not load"
            handles = wait_and_pause_web_processes(process)
            crashed.set()
            for handle in handles:
                try:
                    signal.pidfd_send_signal(handle, signal.SIGKILL)
                finally:
                    os.close(handle)
            assert recovered.wait(20), "crashed WebKit child did not restore the document"
            assert process.poll() is None, "WebKit recovery restarted the GTK parent"
        finally:
            proxy.shutdown()
            worker.join(timeout=5)


def check_renderer(binary, env, ipc_path, output):
    """Exercise one renderer binary through its authenticated IPC lifecycle."""
    with (output / (binary.name + ".log")).open("w") as log:
        process = subprocess.Popen([str(binary)], env=env, stdout=log,
                                   stderr=subprocess.STDOUT)
        try:
            wait_socket(ipc_path, process)
            response = request(ipc_path,
                               b'{"cmd":"status","stage":"waiting_for_playlist",'
                               b'"severity":"success","message":"IPC smoke test"}\n')
            assert response["status"] == "accepted", response
            for command in (
                {"cmd": "proxy_config", "url": "http://127.0.0.1:3129"},
                {"cmd": "proxy_auth", "agent_id": "display-test", "token": "ab" * 32},
                {"cmd": "banner", "message": "IPC smoke test", "severity": "info",
                 "duration_seconds": 1},
            ):
                response = request(ipc_path, json.dumps(command).encode() + b"\n")
                assert response["status"] == "accepted", response
            response = request(ipc_path, b'{"cmd":"status"}\n{}\n')
            assert response["status"] == "rejected", response
            check_unauthorized(ipc_path)
            check_playlist_retry(ipc_path, process, output / (binary.name + ".log"))
            check_browser_dialog_policy(ipc_path)
            check_playlist_reload(ipc_path)
            check_browser_process_recovery(ipc_path, process)
            # Shutdown must still work while WebKit is unresponsive.
            paused = wait_and_pause_web_processes(process)
            try:
                process.send_signal(signal.SIGTERM)
                assert process.wait(timeout=10) == 0, "renderer failed during shutdown"
            finally:
                for handle in paused:
                    try:
                        signal.pidfd_send_signal(handle, signal.SIGCONT)
                    except ProcessLookupError:
                        pass
                    finally:
                        os.close(handle)
            assert not ipc_path.exists(), "renderer left its IPC socket behind"
            print(f"{binary.name}: authenticated IPC, malformed framing, unauthorized UID, "
                  "playlist recovery after synchronization, unattended browser dialogs, "
                  "fresh content across all playlist views, "
                  "WebKit child crash recovery, and shutdown passed",
                  flush=True)
        finally:
            stop(process)


def main():
    """Run lifecycle checks against all requested renderer binaries."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("binaries", nargs="+", type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("run on an isolated test host as root to exercise IPC UID rejection")
    check_runtime_permissions()
    args.output.mkdir(parents=True, exist_ok=True)
    base = Path("/run/neodse")
    created = not base.exists()
    base.mkdir(mode=0o750, exist_ok=True)
    ipc_path = base / f"lifecycle-{os.getpid()}.sock"
    try:
        with tempfile.TemporaryDirectory(prefix="neodse-wayland-") as runtime:
            env = dict(os.environ, XDG_RUNTIME_DIR=runtime, WAYLAND_DISPLAY="wayland-test",
                       NEODSE_UI_SOCKET=str(ipc_path),
                       ASAN_OPTIONS="detect_leaks=0:halt_on_error=1",
                       UBSAN_OPTIONS="halt_on_error=1")
            with (args.output / "weston.log").open("w") as log:
                weston = subprocess.Popen(["weston", "--backend=headless-backend.so",
                                           "--socket=wayland-test", "--idle-time=0"],
                                          env=env, stdout=log, stderr=subprocess.STDOUT)
                try:
                    wait_socket(Path(runtime) / "wayland-test", weston)
                    for binary in args.binaries:
                        check_renderer(binary.resolve(), env, ipc_path, args.output)
                finally:
                    stop(weston)
    finally:
        ipc_path.unlink(missing_ok=True)
        if created:
            base.rmdir()


if __name__ == "__main__":
    main()
