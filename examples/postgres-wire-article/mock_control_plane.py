#!/usr/bin/env python3
"""Minimal signed rule-sync server for the prepared-refresh reproducer."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


class State:
    def __init__(self, fixture_dir: Path, status_file: Path) -> None:
        self.fixture_dir = fixture_dir
        self.status_file = status_file
        self.lock = threading.Lock()
        self.name = "allow"
        self.served = {"allow": 0, "deny": 0}
        self._persist()

    def _persist(self) -> None:
        data = json.dumps({"state": self.name, "served": self.served}, sort_keys=True).encode()
        self.status_file.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix="control-status-", dir=self.status_file.parent)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.status_file)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    def select(self, name: str) -> None:
        if name not in self.served:
            raise ValueError(name)
        with self.lock:
            self.name = name
            self._persist()

    def bundle(self) -> tuple[bytes, str]:
        with self.lock:
            name = self.name
            body = (self.fixture_dir / f"{name}.json").read_bytes()
            signature = (self.fixture_dir / f"{name}.header").read_text().strip()
            self.served[name] += 1
            self._persist()
            return body, signature

    def snapshot(self) -> bytes:
        with self.lock:
            return json.dumps({"state": self.name, "served": self.served}, sort_keys=True).encode()


class Handler(BaseHTTPRequestHandler):
    server_version = "VerictoArticleFixture/1"

    @property
    def state(self) -> State:
        return self.server.state  # type: ignore[attr-defined]

    def log_message(self, format: str, *args: object) -> None:
        return

    def reply(self, status: int, body: bytes, content_type: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/v1/sync/rules":
            body, signature = self.state.bundle()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Vericto-Bundle-Signature", signature)
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/status":
            self.reply(200, self.state.snapshot())
            return
        self.reply(404, b'{"error":"not found"}')

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path in {"/state/allow", "/state/deny"}:
            name = path.rsplit("/", 1)[1]
            self.state.select(name)
            self.reply(200, self.state.snapshot())
            return
        self.reply(404, b'{"error":"not found"}')


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixtures", required=True, type=Path)
    parser.add_argument("--status-file", required=True, type=Path)
    parser.add_argument("--port-file", required=True, type=Path)
    args = parser.parse_args()
    state = State(args.fixtures, args.status_file)
    server = ThreadingHTTPServer(("0.0.0.0", 0), Handler)
    server.state = state  # type: ignore[attr-defined]
    args.port_file.write_text(str(server.server_port))
    try:
        server.serve_forever(poll_interval=0.1)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
