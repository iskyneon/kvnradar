#!/usr/bin/env python3
"""End-to-end KVNRadar smoke test, entirely local and without production data.

Builds the Go agent, runs the real Central and an ephemeral HTTPS fixture,
verifies durable pending events, delivery after restart, and SQLite persistence.
Run: python3 tests/smoke.py
Requires: Go >= 1.23 and openssl.
"""
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[1]
PAYLOAD = b"KVNRTEST" * 8192  # 65536 bytes
EXPECTED = {
    "fixture_full--http_content": ("OK_FULL", 65536),
    "fixture_short--http_content": ("SHORT_RESPONSE", 16384),
    "fixture_reset--http_content": ("PARTIAL_TRANSFER", 16384),
}


class Fixture(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        if self.path == "/reset":
            self.send_response(200)
            self.send_header("Content-Length", "65536")
            self.end_headers()
            self.wfile.write(PAYLOAD[:16384])
            self.wfile.flush()
            self.close_connection = True
            return
        data = PAYLOAD[:16384] if self.path == "/short" else PAYLOAD
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def poll(predicate, label, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(0.1)
    raise AssertionError("Timed out: " + label)


def stop(proc):
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=4)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=4)


def pending_state(path):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def db_results(db):
    if not db.exists():
        return {}
    try:
        with sqlite3.connect(db, timeout=2) as connection:
            rows = connection.execute(
                "SELECT target,status,bytes FROM measurements WHERE agent='smoke-agent'"
            ).fetchall()
        return {target: (status, bytes_count) for target, status, bytes_count in rows}
    except sqlite3.OperationalError:
        return {}


def run():
    for exe in ("go", "openssl"):
        if not shutil.which(exe):
            raise RuntimeError(f"Missing required command: {exe}")
    with tempfile.TemporaryDirectory(prefix="kvnradar-smoke-") as temp:
        work = Path(temp)
        binary = work / "kvnradar-agent"
        subprocess.run(["go", "build", "-o", str(binary), "."], cwd=ROOT / "agent", check=True)
        cert, key = work / "fixture.crt", work / "fixture.key"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert), "-days", "1",
            "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost",
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        fixture = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert), str(key))
        fixture.socket = context.wrap_socket(fixture.socket, server_side=True)
        thread = threading.Thread(target=fixture.serve_forever, daemon=True)
        thread.start()
        central = agent = None
        try:
            fixture_port = fixture.server_address[1]
            targets = {
                "version": 1,
                "targets": [
                    {"id": name, "type": "http", "host": "127.0.0.1",
                     "url": f"https://127.0.0.1:{fixture_port}/{path}",
                     "port": fixture_port, "min_bytes": 65536,
                     "interval_sec": 300, "timeout_sec": 5}
                    for name, path in (("fixture_full", "full"),
                                       ("fixture_short", "short"),
                                       ("fixture_reset", "reset"))
                ],
            }
            (work / "targets.json").write_text(json.dumps(targets), encoding="utf-8")
            (work / "agents.json").write_text(json.dumps({"smoke-agent": "local-test-token"}), encoding="utf-8")
            port = free_port()
            db = work / "watch.sqlite3"
            env = {**os.environ, "DB_PATH": str(db), "WATCH_CONFIG": str(work / "targets.json"),
                   "AGENTS_FILE": str(work / "agents.json"), "PORT": str(port),
                   "CENTRAL_BLOCKLIST_INTERVAL": "86400", "BLOCKLIST_UPDATE_SECONDS": "86400",
                   "BLOCKLIST_RESOLVE_DNS": "0", "COMPASS_BASE_URL": "", "TELEGRAM_TOKEN": "",
                   "SMTP_HOST": ""}
            central_log = (work / "central.log").open("w", encoding="utf-8")
            agent_log = (work / "agent.log").open("w", encoding="utf-8")
            try:
                central = subprocess.Popen([sys.executable, str(ROOT / "central/server.py")],
                                           env=env, stdout=central_log, stderr=subprocess.STDOUT)
                def healthy():
                    if central.poll() is not None:
                        raise AssertionError("Central exited early")
                    try:
                        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=0.5) as response:
                            return response.status == 200
                    except OSError:
                        return False
                poll(healthy, "Central /health")
                conf = {"agent": "smoke-agent", "token": "local-test-token",
                        "server": f"http://127.0.0.1:{port}",
                        "state_dir": str(work / "state"), "sync_seconds": 60}
                config_file = work / "agent.json"
                config_file.write_text(json.dumps(conf), encoding="utf-8")
                agent_env = {**env, "SSL_CERT_FILE": str(cert)}
                agent = subprocess.Popen([str(binary), str(config_file)], env=agent_env,
                                         stdout=agent_log, stderr=subprocess.STDOUT)
                state_file = work / "state" / "state.json"
                def have_pending():
                    if agent.poll() is not None:
                        raise AssertionError("Agent exited before creating pending events")
                    state = pending_state(state_file)
                    return state if state and len(state.get("pending", [])) == 3 else None
                state = poll(have_pending, "3 durable pending events")
                actual = {ev["target"]: (ev["status"], ev["bytes"]) for ev in state["pending"]}
                assert actual == EXPECTED, f"Probe classification mismatch: {actual!r}"
                assert db_results(db) == {}, "Events delivered before next sync"
                stop(agent)
                agent = None
                # Persisted pending events must survive process termination and replay.
                assert len(pending_state(state_file)["pending"]) == 3
                agent = subprocess.Popen([str(binary), str(config_file)], env=agent_env,
                                         stdout=agent_log, stderr=subprocess.STDOUT)
                results = poll(lambda: db_results(db) if len(db_results(db)) == 3 else None,
                               "3 events persisted by Central")
                assert results == EXPECTED, f"SQLite results mismatch: {results!r}"
                poll(lambda: pending_state(state_file) is not None and
                     len(pending_state(state_file).get("pending", [])) == 0,
                     "Central acknowledgments removed local pending events")
                print("SMOKE OK: full / short / interrupted HTTPS responses")
                print("SMOKE OK: persisted pending events, process restart, Central ACK, SQLite")
            except Exception:
                central_log.flush()
                agent_log.flush()
                print("--- Central log ---", file=sys.stderr)
                print((work / "central.log").read_text(encoding="utf-8")[-4000:], file=sys.stderr)
                print("--- Agent log ---", file=sys.stderr)
                print((work / "agent.log").read_text(encoding="utf-8")[-4000:], file=sys.stderr)
                raise
            finally:
                stop(agent)
                stop(central)
                central_log.close()
                agent_log.close()
        finally:
            fixture.shutdown()
            fixture.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    run()
