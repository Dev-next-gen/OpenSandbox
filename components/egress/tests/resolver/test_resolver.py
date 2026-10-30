# Copyright 2026 The OpenSandbox Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Unit tests for the OSEP-0025 public test resolver stub."""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import socket
import ssl
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any

from resolver import resolver

FIXTURES = Path(__file__).resolve().parent / "fixtures"
CERT = FIXTURES / "test-localhost-cert.pem"
KEY = FIXTURES / "test-localhost-key.pem"

VALID_REQUEST: dict[str, Any] = {
    "subject": "sbx_01HZYEXAMPLE",
    "credential": "spi-signer",
    "binding": "internal-api",
    "destination": {
        "scheme": "https",
        "authority": "api.internal.example.com:443",
        "sni": "api.internal.example.com",
    },
    "request": {
        "method": "GET",
        "host": "api.internal.example.com",
        "path": "/v1/foo",
        "headers": {},
    },
}

RESOLVE_PATH = "/resolve"


def expected_parts() -> dict[str, str]:
    return {
        "subject": VALID_REQUEST["subject"],
        "credential": VALID_REQUEST["credential"],
        "binding": VALID_REQUEST["binding"],
        "authority": VALID_REQUEST["destination"]["authority"],
        "path": VALID_REQUEST["request"]["path"],
    }


def expected_signature(parts: dict[str, str]) -> str:
    source = "|".join(
        (
            parts["subject"],
            parts["credential"],
            parts["binding"],
            parts["authority"],
            parts["path"],
        )
    )
    return hashlib.sha256(source.encode()).hexdigest()


def dumps(document: Any) -> bytes:
    return json.dumps(document).encode()


class _UnixConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float = 10) -> None:
        super().__init__("localhost", timeout=timeout)
        self._socket_path = path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self._socket_path)
        self.sock = sock


class _ResolverProcess:
    """Run one resolver server instance in a background thread.

    Every response carries ``Connection: close`` (mirroring the revision IPC
    discipline: one request per connection), so clients must open a fresh
    connection per request; reusing one trips over the server-side close.
    Handler-side exceptions are recorded on the server instead of being
    swallowed and are asserted here unless they belong to the expected
    client-abort class (``allow_client_aborts``, e.g. the delay test).
    """

    CLIENT_ABORT_ERRORS = ("BrokenPipeError", "ConnectionResetError")

    def __init__(self, server: Any, *, allow_client_aborts: bool = False) -> None:
        self.server = server
        self.allow_client_aborts = allow_client_aborts
        self._thread = threading.Thread(target=server.serve_forever, daemon=True)

    def __enter__(self) -> "_ResolverProcess":
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        records = list(getattr(self.server, "exceptions", []))
        if self.allow_client_aborts:
            records = [
                record
                for record in records
                if not any(name in record for name in self.CLIENT_ABORT_ERRORS)
            ]
        if records:
            raise AssertionError(
                "resolver handler raised unexpectedly:\n" + "\n".join(records)
            )


def build_uds_server(socket_path: str, argv: list[str] | None = None) -> Any:
    options = resolver.parse_args(["--uds", socket_path, *(argv or [])])
    return resolver.build_server(options, transport="uds", expected_token=None)


def build_https_server(port: int, expected_token: str | None) -> Any:
    options = resolver.parse_args(
        [
            "--https", f"127.0.0.1:{port}",
            "--tls-cert", str(CERT),
            "--tls-key", str(KEY),
        ]
    )
    return resolver.build_server(options, transport="https", expected_token=expected_token)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class ResolverUDSTest(unittest.TestCase):
    """UDS transport: dual-mode coverage, happy path, and IPC discipline."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.socket_path = os.path.join(self._tmp.name, "resolver.sock")

    def post(self, body: bytes, headers: dict[str, str] | None = None,
             timeout: float = 10, path: str = RESOLVE_PATH) -> tuple[int, bytes]:
        connection = _UnixConnection(self.socket_path, timeout=timeout)
        try:
            connection.request("POST", path, body=body, headers={
                "Content-Type": "application/json",
                **(headers or {}),
            })
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def test_happy_path_returns_deterministic_signature_and_redactions(self) -> None:
        with _ResolverProcess(build_uds_server(self.socket_path)):
            status, payload = self.post(dumps(VALID_REQUEST))

        self.assertEqual(200, status)
        parts = expected_parts()
        signature = expected_signature(parts)
        document = json.loads(payload)
        self.assertEqual(
            {
                "headers": {
                    "authorization": "Bearer test-spi-signer",
                    "x-test-signature": signature,
                    "x-test-subject": "sbx_01HZYEXAMPLE",
                },
                "redactions": {
                    "authorization": ["Bearer test-spi-signer"],
                    "x-test-signature": [signature],
                    "x-test-subject": ["sbx_01HZYEXAMPLE"],
                },
            },
            document,
        )
        # D15: the subject asserted by the signature stub is the egress
        # sandboxId, mirrored verbatim into x-test-subject.
        self.assertEqual(
            VALID_REQUEST["subject"], document["headers"]["x-test-subject"]
        )

    def test_signature_tracks_sandbox_id_and_destination(self) -> None:
        with _ResolverProcess(build_uds_server(self.socket_path)):
            _, first = self.post(dumps(VALID_REQUEST))
            changed = {**VALID_REQUEST, "subject": "sbx_01HZYOTHER"}
            _, second = self.post(dumps(changed))

        first_headers = json.loads(first)["headers"]
        second_headers = json.loads(second)["headers"]
        self.assertEqual("sbx_01HZYOTHER", second_headers["x-test-subject"])
        self.assertNotEqual(
            first_headers["x-test-signature"], second_headers["x-test-signature"]
        )

    def test_fixed_service_path_rejects_other_paths_with_404(self) -> None:
        # One fresh connection per request: the resolver replies with
        # ``Connection: close`` and closes the socket, so reusing a
        # connection across requests races the server-side close.
        with _ResolverProcess(build_uds_server(self.socket_path)):
            for path in ("/", "/resolve/", "/v1/resolve"):
                status, _ = self.post(dumps(VALID_REQUEST), path=path)
                self.assertEqual(404, status, path)

    def test_uds_mode_ignores_host_header(self) -> None:
        connection = _UnixConnection(self.socket_path)
        with _ResolverProcess(build_uds_server(self.socket_path)):
            connection.request(
                "POST",
                RESOLVE_PATH,
                body=dumps(VALID_REQUEST),
                headers={
                    "Content-Type": "application/json",
                    "Host": "attacker.example.com",
                },
            )
            response = connection.getresponse()
            status = response.status
            response.read()
        connection.close()
        self.assertEqual(200, status)

    def test_uds_mode_does_not_require_authorization(self) -> None:
        with _ResolverProcess(build_uds_server(self.socket_path)):
            status, _ = self.post(
                dumps(VALID_REQUEST), {"Authorization": "Bearer anything"}
            )
        self.assertEqual(200, status)

    def test_socket_permissions_are_owner_and_group_only(self) -> None:
        with _ResolverProcess(build_uds_server(self.socket_path)):
            mode = os.stat(self.socket_path).st_mode & 0o777
        self.assertEqual(0o660, mode)

    def test_protocol_discipline_failures(self) -> None:
        base = dict(VALID_REQUEST)
        duplicate = dumps(VALID_REQUEST).replace(
            b'"subject": "sbx_01HZYEXAMPLE",',
            b'"subject": "sbx_01HZYEXAMPLE", "subject": "sbx_01HZYEXAMPLE",',
            1,
        )
        cases = {
            "duplicate-key": (duplicate, {}),
            "wrong-content-type": (dumps(base), {"Content-Type": "text/plain"}),
            "not-json": (b"{not json", {}),
            "empty-body": (b"", {}),
            "array-body": (b"[]", {}),
            "unknown-field": (dumps({**base, "extra": 1}), {}),
            "missing-destination-key": (dumps(
                {**base, "destination": {"scheme": "https", "authority": "a:443"}}
            ), {}),
            "bad-scheme": (dumps(
                {**base, "destination": {**base["destination"], "scheme": "ftp"}}
            ), {}),
            "empty-subject": (dumps({**base, "subject": ""}), {}),
            "path-not-rooted": (dumps(
                {**base, "request": {**base["request"], "path": "v1/foo"}}
            ), {}),
            "non-string-header-value": (dumps(
                {**base, "request": {**base["request"], "headers": {"x-a": 3}}}
            ), {}),
        }
        with _ResolverProcess(build_uds_server(self.socket_path)):
            for name, (body, extra_headers) in cases.items():
                with self.subTest(name=name):
                    status, payload = self.post(body, extra_headers)
                    self.assertEqual(400, status, payload)

    def test_oversized_body_rejected_with_413(self) -> None:
        with _ResolverProcess(build_uds_server(self.socket_path)):
            status, _ = self.post(b"x" * (resolver.MAX_REQUEST_BYTES + 1))
        self.assertEqual(413, status)

    def test_get_rejected_with_405(self) -> None:
        connection = _UnixConnection(self.socket_path)
        with _ResolverProcess(build_uds_server(self.socket_path)):
            connection.request("GET", RESOLVE_PATH)
            response = connection.getresponse()
            status = response.status
            response.read()
        connection.close()
        self.assertEqual(405, status)


class ResolverHTTPSTest(unittest.TestCase):
    """HTTPS transport: Bearer caller authentication, fail closed."""

    def setUp(self) -> None:
        self._original_auth = os.environ.get(resolver._AUTH_ENV)
        os.environ.pop(resolver._AUTH_ENV, None)
        self.addCleanup(self._restore_auth)
        self.port = free_port()
        self.context = ssl.create_default_context(cafile=str(CERT))

    def _restore_auth(self) -> None:
        if self._original_auth is None:
            os.environ.pop(resolver._AUTH_ENV, None)
        else:
            os.environ[resolver._AUTH_ENV] = self._original_auth

    def post(self, body: bytes, headers: dict[str, str] | None = None,
             timeout: float = 10) -> tuple[int, bytes]:
        connection = http.client.HTTPSConnection(
            "127.0.0.1", self.port, context=self.context, timeout=timeout
        )
        try:
            connection.request("POST", RESOLVE_PATH, body=body, headers={
                "Content-Type": "application/json",
                **(headers or {}),
            })
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def test_happy_path_with_configured_token(self) -> None:
        server = build_https_server(self.port, "caller-secret")
        with _ResolverProcess(server):
            status, _ = self.post(
                dumps(VALID_REQUEST), {"Authorization": "Bearer caller-secret"}
            )
        self.assertEqual(200, status)

    def test_wrong_token_rejected_with_401(self) -> None:
        server = build_https_server(self.port, "caller-secret")
        with _ResolverProcess(server):
            status, _ = self.post(
                dumps(VALID_REQUEST), {"Authorization": "Bearer wrong"}
            )
        self.assertEqual(401, status)

    def test_missing_authorization_rejected_with_401(self) -> None:
        server = build_https_server(self.port, "caller-secret")
        with _ResolverProcess(server):
            status, _ = self.post(dumps(VALID_REQUEST))
        self.assertEqual(401, status)

    def test_unconfigured_origin_fails_closed_with_401(self) -> None:
        server = build_https_server(self.port, None)
        with _ResolverProcess(server):
            authorized, _ = self.post(
                dumps(VALID_REQUEST), {"Authorization": "Bearer anything"}
            )
            anonymous, _ = self.post(dumps(VALID_REQUEST))
        self.assertEqual(401, authorized)
        self.assertEqual(401, anonymous)

    def test_token_lookup_from_egress_auth_environment(self) -> None:
        origin = f"https://127.0.0.1:{self.port}"
        os.environ[resolver._AUTH_ENV] = f"{origin}=env-token,https://other=unused"
        token = resolver.expected_token_for_origin(origin, None)
        self.assertEqual("env-token", token)
        server = build_https_server(self.port, token)
        with _ResolverProcess(server):
            status, _ = self.post(
                dumps(VALID_REQUEST), {"Authorization": "Bearer env-token"}
            )
        self.assertEqual(200, status)

    def test_authorization_override_wins_over_environment(self) -> None:
        os.environ[resolver._AUTH_ENV] = f"https://127.0.0.1:{self.port}=env-token"
        self.assertEqual(
            "override", resolver.expected_token_for_origin("https://x", "override")
        )


class ResolverFaultInjectionTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.socket_path = os.path.join(self._tmp.name, "resolver.sock")

    def _post(self, timeout: float = 10) -> tuple[int, bytes]:
        connection = _UnixConnection(self.socket_path, timeout=timeout)
        try:
            connection.request("POST", RESOLVE_PATH, body=dumps(VALID_REQUEST), headers={
                "Content-Type": "application/json",
            })
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def test_fail_once_refuses_first_resolution_then_serves(self) -> None:
        server = build_uds_server(self.socket_path, ["--fail", "once"])
        with _ResolverProcess(server):
            first, _ = self._post()
            second, _ = self._post()
        self.assertEqual(503, first)
        self.assertEqual(200, second)

    def test_fail_rate_full_always_refuses(self) -> None:
        server = build_uds_server(self.socket_path, ["--fail", "1.0"])
        with _ResolverProcess(server):
            for _ in range(3):
                status, _ = self._post()
                self.assertEqual(503, status)

    def test_incomplete_redactions_returns_single_entry(self) -> None:
        server = build_uds_server(self.socket_path, ["--incomplete-redactions"])
        with _ResolverProcess(server):
            status, payload = self._post()
        document = json.loads(payload)
        self.assertEqual(200, status)
        self.assertEqual(
            {"authorization": ["Bearer test-spi-signer"]}, document["redactions"]
        )
        self.assertEqual(3, len(document["headers"]))

    def test_delay_exceeds_client_timeout(self) -> None:
        server = build_uds_server(self.socket_path, ["--delay", "1000"])
        # The client aborts at 0.2s while the handler is still sleeping, so
        # the handler's eventual write raises a client-abort error that the
        # harness tolerates; anything else still fails the test.
        with _ResolverProcess(server, allow_client_aborts=True):
            started = time.monotonic()
            with self.assertRaises((TimeoutError, OSError)):
                self._post(timeout=0.2)
            self.assertLess(time.monotonic() - started, 1.0)


class ResolveRequestValidationTest(unittest.TestCase):
    def test_parse_accepts_populated_header_map(self) -> None:
        payload = {
            **VALID_REQUEST,
            "request": {
                **VALID_REQUEST["request"],
                "headers": {"accept": "application/json"},
            },
        }
        parts = resolver.parse_resolve_request(payload)
        self.assertEqual("sbx_01HZYEXAMPLE", parts["subject"])

    def test_resolve_response_is_deterministic(self) -> None:
        parts = expected_parts()
        self.assertEqual(
            resolver.resolve_response(parts, False),
            resolver.resolve_response(parts, False),
        )


if __name__ == "__main__":
    unittest.main()
