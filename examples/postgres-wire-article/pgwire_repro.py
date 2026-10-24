#!/usr/bin/env python3
"""Assertion-based PostgreSQL v3 wire reproducer using only Python stdlib."""

from __future__ import annotations

import argparse
import base64
import fnmatch
import hashlib
import hmac
import json
import os
import secrets
import select
import socket
import ssl
import struct
import sys
import time
import traceback
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

SSL_REQUEST = 80877103
CANCEL_REQUEST = 80877102


class ProtocolError(RuntimeError):
    pass


class PgError(RuntimeError):
    def __init__(self, fields: dict[str, str]):
        self.fields = fields
        self.sqlstate = fields.get("C", "")
        self.message = fields.get("M", "PostgreSQL error")
        super().__init__(f"{self.sqlstate}: {self.message}")


@dataclass
class Message:
    tag: bytes
    body: bytes


@dataclass
class Result:
    messages: list[Message]
    status: str

    @property
    def errors(self) -> list[PgError]:
        return [PgError(parse_error(m.body)) for m in self.messages if m.tag == b"E"]

    @property
    def rows(self) -> list[list[str | None]]:
        return [parse_data_row(m.body) for m in self.messages if m.tag == b"D"]


def exact(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    left = size
    while left:
        data = sock.recv(left)
        if not data:
            raise ProtocolError(f"connection closed with {left} bytes left in frame")
        chunks.append(data)
        left -= len(data)
    return b"".join(chunks)


def recv_message(sock: socket.socket) -> Message:
    tag = exact(sock, 1)
    raw_len = exact(sock, 4)
    length = struct.unpack("!I", raw_len)[0]
    if length < 4 or length > 128 * 1024 * 1024:
        raise ProtocolError(f"invalid backend frame length {length}")
    return Message(tag, exact(sock, length - 4))


def frame(tag: bytes, body: bytes = b"") -> bytes:
    return tag + struct.pack("!I", len(body) + 4) + body


def cstring(value: str) -> bytes:
    return value.encode("utf-8") + b"\0"


def parse_error(body: bytes) -> dict[str, str]:
    fields: dict[str, str] = {}
    pos = 0
    while pos < len(body) and body[pos] != 0:
        key = chr(body[pos])
        end = body.find(b"\0", pos + 1)
        if end < 0:
            raise ProtocolError("unterminated ErrorResponse field")
        fields[key] = body[pos + 1 : end].decode("utf-8", "replace")
        pos = end + 1
    return fields


def parse_data_row(body: bytes) -> list[str | None]:
    if len(body) < 2:
        raise ProtocolError("short DataRow")
    count = struct.unpack("!H", body[:2])[0]
    pos = 2
    values: list[str | None] = []
    for _ in range(count):
        if pos + 4 > len(body):
            raise ProtocolError("short DataRow column length")
        length = struct.unpack("!i", body[pos : pos + 4])[0]
        pos += 4
        if length == -1:
            values.append(None)
        else:
            if length < 0 or pos + length > len(body):
                raise ProtocolError("invalid DataRow column length")
            values.append(body[pos : pos + length].decode("utf-8", "replace"))
            pos += length
    if pos != len(body):
        raise ProtocolError("trailing DataRow bytes")
    return values


def scram_escape(value: str) -> str:
    return value.replace("=", "=3D").replace(",", "=2C")


def scram_fields(value: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in value.split(","):
        if "=" not in item:
            raise ProtocolError(f"malformed SCRAM attribute {item!r}")
        key, val = item.split("=", 1)
        result[key] = val
    return result


class PgConnection:
    def __init__(
        self,
        port: int,
        password: str,
        *,
        tls: bool = False,
        channel_binding: str = "disable",
        application_name: str = "vericto-wire-reproducer",
        timeout: float = 10.0,
    ) -> None:
        self.host = "127.0.0.1"
        self.port = port
        self.password = password
        self.channel_binding = channel_binding
        self.sock = socket.create_connection((self.host, self.port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.peer_certificate: bytes | None = None
        self.backend_pid: int | None = None
        self.backend_secret: int | None = None
        if tls:
            self.sock.sendall(struct.pack("!II", 8, SSL_REQUEST))
            response = exact(self.sock, 1)
            if response != b"S":
                self.sock.close()
                raise ProtocolError(f"proxy refused SSLRequest with {response!r}")
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            self.sock = context.wrap_socket(self.sock, server_hostname="localhost")
            self.sock.settimeout(timeout)
            self.peer_certificate = self.sock.getpeercert(binary_form=True)
        self._startup(application_name)

    def close(self) -> None:
        try:
            self.sock.sendall(frame(b"X"))
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        self.sock.close()

    def __enter__(self) -> PgConnection:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def _startup(self, application_name: str) -> None:
        params = (
            cstring("user")
            + cstring("postgres")
            + cstring("database")
            + cstring("postgres")
            + cstring("application_name")
            + cstring(application_name)
            + b"\0"
        )
        packet = struct.pack("!I", 8 + len(params)) + struct.pack("!I", 196608) + params
        self.sock.sendall(packet)
        scram: dict[str, object] | None = None
        while True:
            message = recv_message(self.sock)
            if message.tag == b"R":
                if len(message.body) < 4:
                    raise ProtocolError("short Authentication request")
                auth_type = struct.unpack("!I", message.body[:4])[0]
                if auth_type == 0:
                    continue
                if auth_type == 10:
                    offered = [x.decode() for x in message.body[4:].split(b"\0") if x]
                    plus = "SCRAM-SHA-256-PLUS" in offered
                    if self.channel_binding == "require" and not plus:
                        raise ProtocolError("channel binding required but server did not offer PLUS")
                    mechanism = "SCRAM-SHA-256-PLUS" if plus and self.channel_binding != "disable" else "SCRAM-SHA-256"
                    nonce = base64.b64encode(secrets.token_bytes(18)).decode()
                    bare = f"n={scram_escape('postgres')},r={nonce}"
                    gs2 = "p=tls-server-end-point,," if mechanism.endswith("PLUS") else "n,,"
                    first = (gs2 + bare).encode()
                    self.sock.sendall(frame(b"p", cstring(mechanism) + struct.pack("!I", len(first)) + first))
                    scram = {"mechanism": mechanism, "nonce": nonce, "bare": bare, "gs2": gs2}
                    continue
                if auth_type == 11:
                    if scram is None:
                        raise ProtocolError("SCRAM continuation without initial exchange")
                    server_first = message.body[4:].decode()
                    attrs = scram_fields(server_first)
                    nonce = str(scram["nonce"])
                    if not attrs.get("r", "").startswith(nonce):
                        raise ProtocolError("server SCRAM nonce does not extend client nonce")
                    salt = base64.b64decode(attrs["s"], validate=True)
                    iterations = int(attrs["i"])
                    if not 4096 <= iterations <= 1_000_000:
                        raise ProtocolError(f"unreasonable SCRAM iteration count {iterations}")
                    salted = hashlib.pbkdf2_hmac("sha256", self.password.encode(), salt, iterations)
                    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
                    stored_key = hashlib.sha256(client_key).digest()
                    gs2 = str(scram["gs2"]).encode()
                    if str(scram["mechanism"]).endswith("PLUS"):
                        if self.peer_certificate is None:
                            raise ProtocolError("PLUS selected without a TLS peer certificate")
                        channel_data = hashlib.sha256(self.peer_certificate).digest()
                    else:
                        channel_data = b""
                    final_without = f"c={base64.b64encode(gs2 + channel_data).decode()},r={attrs['r']}"
                    auth_message = f"{scram['bare']},{server_first},{final_without}".encode()
                    client_sig = hmac.new(stored_key, auth_message, hashlib.sha256).digest()
                    proof = bytes(a ^ b for a, b in zip(client_key, client_sig))
                    server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
                    server_sig = hmac.new(server_key, auth_message, hashlib.sha256).digest()
                    scram["server_sig"] = server_sig
                    final = f"{final_without},p={base64.b64encode(proof).decode()}".encode()
                    self.sock.sendall(frame(b"p", final))
                    continue
                if auth_type == 12:
                    if scram is None:
                        raise ProtocolError("SCRAM final without initial exchange")
                    attrs = scram_fields(message.body[4:].decode())
                    if "e" in attrs:
                        raise ProtocolError(f"SCRAM server error: {attrs['e']}")
                    actual = base64.b64decode(attrs.get("v", ""), validate=True)
                    if not hmac.compare_digest(actual, bytes(scram["server_sig"])):
                        raise ProtocolError("SCRAM server signature mismatch")
                    continue
                raise ProtocolError(f"unsupported Authentication request {auth_type}")
            if message.tag == b"E":
                raise PgError(parse_error(message.body))
            if message.tag == b"K":
                if len(message.body) != 8:
                    raise ProtocolError("invalid BackendKeyData")
                self.backend_pid, self.backend_secret = struct.unpack("!II", message.body)
            if message.tag == b"Z":
                return

    def send_query(self, sql: str) -> None:
        self.sock.sendall(frame(b"Q", cstring(sql)))

    def read_result(self) -> Result:
        messages: list[Message] = []
        while True:
            message = recv_message(self.sock)
            messages.append(message)
            if message.tag == b"Z":
                if len(message.body) != 1:
                    raise ProtocolError("invalid ReadyForQuery")
                return Result(messages, message.body.decode())

    def query(self, sql: str) -> Result:
        self.send_query(sql)
        return self.read_result()

    def scalar(self, sql: str) -> str | None:
        result = self.query(sql)
        assert_no_error(result)
        if len(result.rows) != 1 or len(result.rows[0]) != 1:
            raise AssertionError(f"expected one scalar row, got {result.rows!r}")
        return result.rows[0][0]


def assert_no_error(result: Result) -> None:
    if result.errors:
        raise AssertionError(f"unexpected PostgreSQL error: {result.errors[0]}")


def assert_error(result: Result, sqlstate: str, contains: str | None = None) -> PgError:
    if len(result.errors) != 1:
        raise AssertionError(f"expected one {sqlstate} error, got tags {[m.tag.decode('latin1') for m in result.messages]}")
    error = result.errors[0]
    if error.sqlstate != sqlstate:
        raise AssertionError(f"expected SQLSTATE {sqlstate}, got {error}")
    if contains and contains not in error.message:
        raise AssertionError(f"expected {contains!r} in error message {error.message!r}")
    return error


def q(sql: str) -> bytes:
    return frame(b"Q", cstring(sql))


def parse_message(name: str, sql: str) -> bytes:
    return frame(b"P", cstring(name) + cstring(sql) + struct.pack("!H", 0))


def bind_message(portal: str, statement: str, params: list[str] | None = None) -> bytes:
    params = params or []
    body = cstring(portal) + cstring(statement) + struct.pack("!H", 0) + struct.pack("!H", len(params))
    for value in params:
        encoded = value.encode()
        body += struct.pack("!I", len(encoded)) + encoded
    body += struct.pack("!H", 0)
    return frame(b"B", body)


def execute_message(portal: str = "") -> bytes:
    return frame(b"E", cstring(portal) + struct.pack("!I", 0))


def sync_message() -> bytes:
    return frame(b"S")


def flush_message() -> bytes:
    return frame(b"H")


def tags(messages: list[Message]) -> str:
    return "".join(m.tag.decode("latin1") for m in messages)


def env_port(name: str) -> int:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"missing runner environment {name}")
    return int(value)


PASSWORD = os.environ.get("PG_PASSWORD", "")
PG17 = env_port("PG17_PROXY_PORT")
PG17_TLS_DISTINCT = env_port("PG17_TLS_DISTINCT_PORT")
PG17_TLS_SHARED = env_port("PG17_TLS_SHARED_PORT")
PG17_REFRESH = env_port("PG17_REFRESH_PORT")
PG18 = env_port("PG18_PROXY_PORT")
CONTROL_ADMIN_URL = os.environ.get("CONTROL_ADMIN_URL", "")


def conn(port: int = PG17, **kwargs: object) -> PgConnection:
    return PgConnection(port, PASSWORD, **kwargs)


def case_simple_block_allow() -> dict[str, object]:
    with conn() as c:
        assert_no_error(c.query("CREATE TABLE article_simple (id integer PRIMARY KEY, note text)"))
        assert_no_error(c.query("INSERT INTO article_simple (id,note) VALUES (1,'one'),(2,'two')"))
        blocked = c.query("DELETE FROM article_simple")
        assert_error(blocked, "42501", "VERICTO-001")
        if c.scalar("SELECT count(*) FROM article_simple") != "2":
            raise AssertionError("blocked DELETE changed rows")
        assert_no_error(c.query("DELETE FROM article_simple WHERE id = 2"))
        if c.scalar("SELECT count(*) FROM article_simple") != "1":
            raise AssertionError("qualified DELETE did not delete exactly one row")
        return {"blocked_status": blocked.status, "remaining_rows": 1}


def case_stacked_all_or_nothing() -> dict[str, object]:
    with conn() as c:
        assert_no_error(c.query("CREATE TABLE article_stack (id integer PRIMARY KEY)"))
        assert_no_error(c.query("INSERT INTO article_stack (id) VALUES (1),(2)"))
        result = c.query("SELECT 12345; DELETE FROM article_stack")
        assert_error(result, "42501", "VERICTO-001")
        if result.rows:
            raise AssertionError("first stacked SELECT ran before admission failure")
        if c.scalar("SELECT count(*) FROM article_stack") != "2":
            raise AssertionError("stacked DELETE changed rows")
        return {"server_rows_returned": 0, "remaining_rows": 2}


def case_data_modifying_cte() -> dict[str, object]:
    with conn() as c:
        assert_no_error(c.query("CREATE TABLE article_cte (id integer PRIMARY KEY)"))
        assert_no_error(c.query("INSERT INTO article_cte (id) VALUES (1),(2)"))
        result = c.query("WITH gone AS (DELETE FROM article_cte RETURNING id) SELECT count(*) FROM gone")
        error = assert_error(result, "42501", "VERICTO-001")
        if c.scalar("SELECT count(*) FROM article_cte") != "2":
            raise AssertionError("blocked data-modifying CTE changed rows")
        return {"message": error.message}


def case_or_tautology() -> dict[str, object]:
    with conn() as c:
        result = c.query("SELECT id FROM article_cte WHERE id = 1 OR 1=1 LIMIT 50")
        error = assert_error(result, "42501", "VERICTO-090")
        return {"message": error.message}


def case_extended_timing_recovery() -> dict[str, object]:
    with conn() as c:
        c.sock.sendall(parse_message("blocked", "DELETE FROM article_cte"))
        ready, _, _ = select.select([c.sock], [], [], 5.0)
        if not ready:
            raise AssertionError("blocked Parse produced no ErrorResponse before Sync")
        first = recv_message(c.sock)
        if first.tag != b"E":
            raise AssertionError(f"expected ErrorResponse before Sync, got {first.tag!r}")
        error = PgError(parse_error(first.body))
        if error.sqlstate != "42501":
            raise AssertionError(f"unexpected blocked Parse error {error}")
        c.sock.sendall(bind_message("", "blocked") + execute_message() )
        ready, _, _ = select.select([c.sock], [], [], 0.4)
        if ready:
            unexpected = recv_message(c.sock)
            raise AssertionError(f"proxy answered swallowed extended message with {unexpected.tag!r}")
        c.sock.sendall(sync_message())
        z = recv_message(c.sock)
        if z.tag != b"Z" or z.body != b"I":
            raise AssertionError(f"expected ReadyForQuery(I) after Sync, got {z!r}")
        if c.scalar("SELECT 7") != "7":
            raise AssertionError("connection did not recover after blocked extended sequence")
        return {"error_before_sync": True, "ready_after_sync": "I", "recovered": True}


def case_extended_pipeline_rollback() -> dict[str, object]:
    with conn() as c:
        assert_no_error(c.query("CREATE TABLE article_extended_pipeline (id integer PRIMARY KEY)"))
        packet = (
            parse_message("insert_one", "INSERT INTO article_extended_pipeline (id) VALUES (1)")
            + bind_message("insert_portal", "insert_one")
            + execute_message("insert_portal")
            + parse_message("blocked", "DELETE FROM article_extended_pipeline")
            + bind_message("blocked_portal", "blocked")
            + execute_message("blocked_portal")
            + flush_message()
            + sync_message()
        )
        c.sock.sendall(packet)
        result = c.read_result()
        if tags(result.messages) != "12CEZ":
            raise AssertionError(f"unexpected extended pipeline order: {tags(result.messages)}")
        assert_error(result, "42501", "VERICTO-001")
        if c.scalar("SELECT count(*) FROM article_extended_pipeline") != "0":
            raise AssertionError("the server did not roll back the earlier extended write")
        return {"tags": tags(result.messages), "earlier_write_rolled_back": True}


def case_bind_value_blind_spot() -> dict[str, object]:
    with conn() as c:
        assert_no_error(c.query("CREATE TABLE article_bind (id integer PRIMARY KEY)"))
        assert_no_error(c.query("INSERT INTO article_bind (id) VALUES (1),(2),(3)"))
        packet = (
            parse_message("delete_gt", "DELETE FROM article_bind WHERE id > $1")
            + bind_message("p", "delete_gt", ["0"])
            + execute_message("p")
            + sync_message()
        )
        c.sock.sendall(packet)
        result = c.read_result()
        assert_no_error(result)
        for wanted in (b"1", b"2", b"C", b"Z"):
            if wanted not in [m.tag for m in result.messages]:
                raise AssertionError(f"extended response omitted {wanted!r}: {tags(result.messages)}")
        if c.scalar("SELECT count(*) FROM article_bind") != "0":
            raise AssertionError("Bind value did not demonstrate the all-row delete blind spot")
        return {"bind_value": "0", "deleted_rows": 3}


def case_ready_for_query_states() -> dict[str, object]:
    with conn() as c:
        idle = c.query("DELETE FROM article_cte")
        assert_error(idle, "42501")
        if idle.status != "I":
            raise AssertionError(f"idle block reported {idle.status}")
        begin = c.query("BEGIN")
        assert_no_error(begin)
        if begin.status != "T":
            raise AssertionError(f"BEGIN reported {begin.status}")
        in_tx = c.query("DELETE FROM article_cte")
        assert_error(in_tx, "42501")
        if in_tx.status != "T":
            raise AssertionError(f"block in transaction reported {in_tx.status}")
        division = c.query("SELECT 1/0")
        assert_error(division, "22012")
        if division.status != "E":
            raise AssertionError(f"server error reported {division.status}")
        failed = c.query("DELETE FROM article_cte")
        assert_error(failed, "42501")
        if failed.status != "E":
            raise AssertionError(f"local block in failed transaction reported {failed.status}")
        rollback = c.query("ROLLBACK")
        assert_no_error(rollback)
        if rollback.status != "I":
            raise AssertionError(f"ROLLBACK reported {rollback.status}")
        return {"statuses": ["I", "T", "T", "E", "E", "I"]}


def read_cycles(c: PgConnection, count: int) -> list[list[Message]]:
    cycles: list[list[Message]] = []
    current: list[Message] = []
    while len(cycles) < count:
        message = recv_message(c.sock)
        current.append(message)
        if message.tag == b"Z":
            cycles.append(current)
            current = []
    return cycles


def case_pipeline_ordering() -> dict[str, object]:
    with conn() as c:
        c.sock.sendall(
            q("SELECT repeat('x', 32768), count(*) FROM generate_series(1, 50000000)")
            + q("DELETE FROM article_cte")
        )
        slow, blocked = read_cycles(c, 2)
        if not any(m.tag == b"D" and len(m.body) > 16 * 1024 for m in slow):
            raise AssertionError(f"slow cycle had no large DataRow: {tags(slow)}")
        if any(m.tag == b"E" for m in slow):
            raise AssertionError("blocked query reply appeared in slow query cycle")
        block_errors = [PgError(parse_error(m.body)) for m in blocked if m.tag == b"E"]
        if len(block_errors) != 1 or block_errors[0].sqlstate != "42501":
            raise AssertionError(f"second pipeline cycle was not the local block: {tags(blocked)}")

        c.sock.sendall(q("SELECT 1") + q("DELETE FROM article_cte") + q("SELECT 2"))
        first, middle, last = read_cycles(c, 3)
        first_rows = [parse_data_row(m.body) for m in first if m.tag == b"D"]
        last_rows = [parse_data_row(m.body) for m in last if m.tag == b"D"]
        if first_rows != [["1"]] or last_rows != [["2"]]:
            raise AssertionError(f"outer pipeline results out of order: {first_rows!r}, {last_rows!r}")
        middle_errors = [PgError(parse_error(m.body)) for m in middle if m.tag == b"E"]
        if len(middle_errors) != 1 or middle_errors[0].sqlstate != "42501":
            raise AssertionError(f"middle pipeline cycle was not blocked: {tags(middle)}")
        return {
            "slow_then_block_tags": [tags(slow), tags(blocked)],
            "three_cycle_tags": [tags(first), tags(middle), tags(last)],
        }


def case_large_backend_frame() -> dict[str, object]:
    expected = 40_000
    with conn() as c:
        result = c.query(f"SELECT repeat('z', {expected})")
        assert_no_error(result)
        data = [m for m in result.messages if m.tag == b"D"]
        if len(data) != 1 or len(data[0].body) <= 16 * 1024:
            raise AssertionError("backend DataRow did not exceed the relay chunk size")
        row = parse_data_row(data[0].body)
        if row != ["z" * expected]:
            raise AssertionError("large DataRow was split, interleaved, or corrupted")
        return {"data_row_body_bytes": len(data[0].body), "value_bytes": expected}


def case_pg18_virtual_version_skew() -> dict[str, object]:
    with conn(PG18) as c:
        sql = "CREATE TABLE article_virtual (a int, b int GENERATED ALWAYS AS (a * 2) VIRTUAL)"
        result = c.query(sql)
        assert_no_error(result)
        assert_no_error(c.query("INSERT INTO article_virtual (a) VALUES (9)"))
        if c.scalar("SELECT b FROM article_virtual WHERE a = 9") != "18":
            raise AssertionError("PostgreSQL 18 did not create/use the VIRTUAL generated column")
        return {"created_by_postgres_18": True, "generated_value": 18}


def attempt_tls(port: int, binding: str) -> tuple[bool, str]:
    try:
        with conn(port, tls=True, channel_binding=binding) as c:
            value = c.scalar("SELECT 'ok'")
            return value == "ok", "connected"
    except (PgError, ProtocolError, ssl.SSLError, OSError) as error:
        return False, str(error)


def case_tls_channel_binding() -> dict[str, object]:
    matrix: dict[str, dict[str, object]] = {}
    expected = {
        ("distinct", "require"): False,
        ("distinct", "prefer"): False,
        ("distinct", "disable"): True,
        ("shared", "require"): True,
        ("shared", "prefer"): True,
        ("shared", "disable"): True,
    }
    for topology, port in (("distinct", PG17_TLS_DISTINCT), ("shared", PG17_TLS_SHARED)):
        for binding in ("require", "prefer", "disable"):
            ok, detail = attempt_tls(port, binding)
            wanted = expected[(topology, binding)]
            if ok != wanted:
                raise AssertionError(f"TLS {topology}/{binding}: expected connected={wanted}, got {ok}: {detail}")
            matrix[f"{topology}/{binding}"] = {"connected": ok, "detail": detail}
    return matrix


def case_cancel_under_tls() -> dict[str, object]:
    target_sql = "SELECT count(*) FROM generate_series(1, 1000000000)"
    with conn(
        PG17_TLS_DISTINCT,
        tls=True,
        channel_binding="disable",
        application_name="article_cancel_target",
        timeout=12.0,
    ) as target:
        if target.backend_pid is None or target.backend_secret is None:
            raise AssertionError("startup did not expose BackendKeyData")
        target.send_query(target_sql)
        active = False
        deadline = time.monotonic() + 8.0
        while time.monotonic() < deadline:
            with conn(application_name="article_cancel_poller") as poller:
                count = poller.scalar(
                    "SELECT count(*) FROM pg_stat_activity "
                    "WHERE application_name = 'article_cancel_target' "
                    "AND state = 'active' AND query = "
                    "'SELECT count(*) FROM generate_series(1, 1000000000)'"
                )
            if count == "1":
                active = True
                break
            time.sleep(0.1)
        if not active:
            raise AssertionError("long query never became active before cancel deadline")
        cancel = socket.create_connection(("127.0.0.1", PG17_TLS_DISTINCT), timeout=3.0)
        try:
            cancel.sendall(struct.pack("!IIII", 16, CANCEL_REQUEST, target.backend_pid, target.backend_secret))
            cancel.settimeout(3.0)
            closed = cancel.recv(1)
            if closed != b"":
                raise AssertionError("CancelRequest connection unexpectedly returned bytes")
        finally:
            cancel.close()
        result = target.read_result()
        error = assert_error(result, "57014", "canceling statement")
        if result.status != "I":
            raise AssertionError(f"cancelled query left status {result.status}")
        return {"sqlstate": error.sqlstate, "plaintext_cancel_to_tls_proxy": True}


def control_post(state: str) -> dict[str, object]:
    if not CONTROL_ADMIN_URL:
        raise RuntimeError("CONTROL_ADMIN_URL is not configured")
    request = urllib.request.Request(f"{CONTROL_ADMIN_URL}/state/{state}", data=b"", method="POST")
    with urllib.request.urlopen(request, timeout=3.0) as response:
        return json.loads(response.read())


def control_status() -> dict[str, object]:
    if not CONTROL_ADMIN_URL:
        raise RuntimeError("CONTROL_ADMIN_URL is not configured")
    with urllib.request.urlopen(f"{CONTROL_ADMIN_URL}/status", timeout=3.0) as response:
        return json.loads(response.read())


def wait_for_bundle(state: str, previous: int, timeout_seconds: float = 40.0) -> int:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        status = control_status()
        served = status.get("served")
        if isinstance(served, dict):
            count = served.get(state)
            if isinstance(count, int) and count > previous:
                # The HTTP response has been delivered; give the proxy's sync task
                # one scheduler turn to verify and swap the bundle.
                time.sleep(0.2)
                return count
        time.sleep(0.1)
    raise AssertionError(f"proxy did not fetch the {state} bundle within {timeout_seconds}s")


def case_prepared_refresh() -> dict[str, object]:
    initial = control_post("allow")
    served = initial.get("served")
    allow_count = served.get("allow", 0) if isinstance(served, dict) else 0
    if not isinstance(allow_count, int):
        raise AssertionError(f"invalid control-plane status: {initial!r}")
    if allow_count == 0:
        allow_count = wait_for_bundle("allow", 0)

    with conn(PG17_REFRESH) as c:
        assert_no_error(c.query("CREATE TABLE article_refresh (id integer PRIMARY KEY)"))
        c.sock.sendall(
            parse_message("refresh", "SELECT id FROM article_refresh ORDER BY id")
            + flush_message()
        )
        parsed = recv_message(c.sock)
        if parsed.tag != b"1":
            raise AssertionError(f"expected ParseComplete before policy refresh, got {parsed.tag!r}")

        before = control_status()
        before_served = before.get("served")
        deny_before = before_served.get("deny", 0) if isinstance(before_served, dict) else 0
        if not isinstance(deny_before, int):
            raise AssertionError(f"invalid control-plane status: {before!r}")
        control_post("deny")
        deny_count = wait_for_bundle("deny", deny_before)

        c.sock.sendall(bind_message("portal", "refresh") + execute_message("portal") + sync_message())
        result = c.read_result()
        error = assert_error(result, "42501", "VERICTO-087")
        if result.status != "I":
            raise AssertionError(f"prepared refresh block returned ReadyForQuery({result.status})")
        control_post("allow")
        return {
            "parse_completed_before_refresh": True,
            "deny_bundle_fetch_count": deny_count,
            "blocked_at_bind_or_execute": True,
            "sqlstate": error.sqlstate,
        }


def case_copy_behaviors() -> dict[str, object]:
    with conn() as c:
        assert_no_error(c.query("CREATE TABLE article_copy (id integer, note text)"))
        program = c.query("COPY article_copy TO PROGRAM 'cat >/tmp/vericto-program-output'")
        assert_error(program, "42501", "VERICTO-080")

        from_file = c.query("COPY article_copy FROM '/tmp/vericto-copy.csv' WITH (FORMAT csv)")
        assert_no_error(from_file)
        if c.scalar("SELECT count(*) FROM article_copy WHERE id = 101") != "1":
            raise AssertionError("COPY FROM server file was not forwarded")

        to_file = c.query("COPY article_copy TO '/tmp/vericto-copy-output.csv' WITH (FORMAT csv)")
        assert_no_error(to_file)
        content = c.scalar("SELECT pg_read_file('/tmp/vericto-copy-output.csv')")
        if content is None or "101,from_file" not in content:
            raise AssertionError("COPY TO server file did not write expected content")

        c.send_query("COPY article_copy FROM STDIN WITH (FORMAT csv)")
        copy_in = recv_message(c.sock)
        if copy_in.tag != b"G":
            raise AssertionError(f"expected CopyInResponse, got {copy_in.tag!r}")
        c.sock.sendall(frame(b"d", b"202,from_stdin\n") + frame(b"c"))
        incoming: list[Message] = []
        while True:
            message = recv_message(c.sock)
            incoming.append(message)
            if message.tag == b"Z":
                break
        if any(m.tag == b"E" for m in incoming):
            raise AssertionError(f"COPY FROM STDIN failed: {tags(incoming)}")
        if c.scalar("SELECT count(*) FROM article_copy WHERE id = 202") != "1":
            raise AssertionError("COPY FROM STDIN data was not relayed")

        c.send_query("COPY (SELECT id,note FROM article_copy WHERE id = 202) TO STDOUT WITH (FORMAT csv)")
        outgoing: list[Message] = []
        chunks: list[bytes] = []
        while True:
            message = recv_message(c.sock)
            outgoing.append(message)
            if message.tag == b"d":
                chunks.append(message.body)
            if message.tag == b"Z":
                break
        if not outgoing or outgoing[0].tag != b"H":
            raise AssertionError(f"expected CopyOutResponse, got {tags(outgoing)}")
        payload = b"".join(chunks).decode()
        if payload != "202,from_stdin\n":
            raise AssertionError(f"COPY TO STDOUT payload mismatch: {payload!r}")
        return {
            "program_blocked": True,
            "from_server_file_forwarded": True,
            "to_server_file_forwarded": True,
            "stdin_relayed": True,
            "stdout_relayed": True,
        }


Case = tuple[str, Callable[[], dict[str, object]], str]
CASES: list[Case] = [
    ("simple-block-allow", case_simple_block_allow, "Simple Query block/allow and unchanged rows"),
    ("stacked-all-or-nothing", case_stacked_all_or_nothing, "Stacked Query all-or-nothing admission"),
    ("data-modifying-cte", case_data_modifying_cte, "Walker finds DELETE inside WITH"),
    ("or-tautology", case_or_tautology, "AST tautology rule VERICTO-090"),
    ("extended-timing-recovery", case_extended_timing_recovery, "Error before Sync, swallow, recover"),
    ("extended-pipeline-rollback", case_extended_pipeline_rollback, "Earlier extended work rolls back on a later local block"),
    ("bind-value-blind-spot", case_bind_value_blind_spot, "Bind values are not AST inputs"),
    ("ready-for-query-states", case_ready_for_query_states, "Proxy-generated I/T/E state"),
    ("pipeline-ordering", case_pipeline_ordering, "Two- and three-query pipeline ordering"),
    ("large-backend-frame", case_large_backend_frame, "DataRow over 16 KiB stays intact"),
    ("pg18-virtual-version-skew", case_pg18_virtual_version_skew, "PG17 parser flags, PG18 server accepts VIRTUAL"),
    ("tls-channel-binding", case_tls_channel_binding, "Distinct/shared certificate SCRAM matrix"),
    ("cancel-under-tls", case_cancel_under_tls, "Plain CancelRequest accepted by TLS-required proxy"),
    ("copy-behaviors", case_copy_behaviors, "PROGRAM, server files, STDIN and STDOUT"),
    ("prepared-refresh", case_prepared_refresh, "Signed rules refresh blocks an already parsed statement"),
]


def selected(name: str, patterns: list[str]) -> bool:
    return not patterns or any(fnmatch.fnmatch(name, pattern) or pattern in name for pattern in patterns)


def emit(handle: object, record: dict[str, object]) -> None:
    line = json.dumps(record, sort_keys=True, separators=(",", ":"))
    handle.write(line + "\n")  # type: ignore[attr-defined]
    handle.flush()  # type: ignore[attr-defined]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("patterns", nargs="*", help="case names, substrings, or shell-style patterns")
    parser.add_argument("--jsonl", required=True, type=Path, help="machine-readable result file")
    parser.add_argument("--list", action="store_true", help="list cases and exit")
    args = parser.parse_args()
    env_patterns = [x.strip() for x in os.environ.get("CASE_FILTER", "").split(",") if x.strip()]
    patterns = args.patterns + env_patterns
    if args.list:
        for name, _, description in CASES:
            print(f"{name}\t{description}")
        return 0
    chosen = [case for case in CASES if selected(case[0], patterns)]
    if not chosen:
        print(f"error: no cases matched {patterns!r}", file=sys.stderr)
        return 2
    args.jsonl.parent.mkdir(parents=True, exist_ok=True)
    failures = 0
    passed = 0
    started = time.monotonic()
    with args.jsonl.open("w", encoding="utf-8") as output:
        emit(output, {"event": "run_start", "cases": [c[0] for c in chosen], "time_unix": time.time()})
        for name, function, description in chosen:
            print(f"[RUN] {name}: {description}", flush=True)
            case_started = time.monotonic()
            try:
                details = function()
            except Exception as error:  # report all assertion/protocol failures and continue the suite
                failures += 1
                duration = round(time.monotonic() - case_started, 3)
                print(f"[FAIL] {name} ({duration}s): {error}", flush=True)
                emit(
                    output,
                    {
                        "event": "case",
                        "name": name,
                        "status": "FAIL",
                        "duration_seconds": duration,
                        "error_type": type(error).__name__,
                        "error": str(error),
                        "traceback": traceback.format_exc(),
                    },
                )
            else:
                passed += 1
                duration = round(time.monotonic() - case_started, 3)
                print(f"[PASS] {name} ({duration}s)", flush=True)
                emit(
                    output,
                    {
                        "event": "case",
                        "name": name,
                        "status": "PASS",
                        "duration_seconds": duration,
                        "details": details,
                    },
                )
        summary = {
            "event": "run_end",
            "status": "FAIL" if failures else "PASS",
            "passed": passed,
            "failed": failures,
            "duration_seconds": round(time.monotonic() - started, 3),
        }
        emit(output, summary)
    print(
        f"[SUMMARY] passed={passed} failed={failures} jsonl={args.jsonl}",
        flush=True,
    )
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
