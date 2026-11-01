"""Regression tests for the production-facing ARTEMIS snapshot service."""

from __future__ import annotations

import hashlib
import json
import threading
from contextlib import contextmanager
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from bot.snapshot_api import CONTRACTS, create_server, snapshot


@contextmanager
def running_server():
    server = create_server(host="127.0.0.1", port=0)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)


def get(base: str, path: str, token: str | None = None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    request = Request(base + path, headers=headers)
    try:
        with urlopen(request, timeout=5) as response:
            return response.status, json.load(response)
    except HTTPError as exc:
        return exc.code, json.load(exc)


def test_anonymous_requests_fail_closed_and_health_is_unavailable(monkeypatch):
    monkeypatch.delenv("ARTEMIS_API_KEY", raising=False)
    with running_server() as base:
        assert get(base, "/healthz")[0] == 503
        assert get(base, "/v1/snapshot")[0] == 503
        assert get(base, "/v1/snapshot", token="made-up")[0] == 503
        assert get(base, "/v1/snapshot?token=guess")[0] == 404


def test_snapshot_requires_correct_strong_bearer_key(monkeypatch):
    key = "a" * 48
    monkeypatch.setenv("ARTEMIS_API_KEY", key)
    with running_server() as base:
        assert get(base, "/healthz")[0] == 200
        assert get(base, "/v1/snapshot")[0] == 401
        assert get(base, "/v1/snapshot", token="b" * 48)[0] == 401
        status, data = get(base, "/v1/snapshot", token=key)
        assert status == 200
        assert data["ok"] is True
        assert data["service"] == "ARTEMIS-2.1"
        assert data["source_audit"]["status"] == "ready"
        assert data["source_audit"]["report"]["summary"]["files_scanned"] > 0
        assert data["source_audit"]["report"]["summary"]["total_auto_fixes_applied"] == 0
        assert data["monitor"]["status"] == "not_configured"
        assert data["monitor"]["last_success_at"] is None
        assert data["monitor"]["recent_contracts"] == []
        assert key not in json.dumps(data)


def test_read_only_snapshot_never_changes_contract_files(monkeypatch):
    monkeypatch.setenv("ARTEMIS_API_KEY", "c" * 48)
    sol = sorted(CONTRACTS.glob("*.sol"))
    assert sol
    before = {str(path): hashlib.sha256(path.read_bytes()).digest() for path in sol}
    result = snapshot()
    assert result["source_audit"]["report"]["summary"]["files_scanned"] == len(sol)
    after = {str(path): hashlib.sha256(path.read_bytes()).digest() for path in sol}
    assert before == after
