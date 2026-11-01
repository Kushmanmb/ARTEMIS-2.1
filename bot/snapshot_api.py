"""Read-only ARTEMIS snapshot API for the authenticated 0XCON Worker.

Only GET /v1/snapshot returns data and only with a strong server-side Bearer key.
No autofixes, source writes, contract transactions, wallet access or background
monitoring are enabled by this process.
"""

from __future__ import annotations

import hmac
import json
import logging
import os
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from bot.auditor import audit_file, build_report

LOG = logging.getLogger("artemis.snapshot")
ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "contracts"
MAX_CONTRACT_FILES = 100


def ready() -> bool:
    """Never accept an unset, placeholder or short authentication secret."""
    key = os.environ.get("ARTEMIS_API_KEY", "")
    return len(key) >= 32 and key not in {"replace-me", "change-me"}


def source_snapshot() -> dict:
    """Audit checked-in Solidity source without auto-fixes or file writes."""
    contracts = sorted(CONTRACTS.glob("*.sol"))
    if not contracts:
        raise RuntimeError("no_source_files")
    if len(contracts) > MAX_CONTRACT_FILES:
        raise RuntimeError("source_file_limit")

    results = {}
    for path in contracts:
        if not path.is_file() or path.is_symlink():
            raise RuntimeError("invalid_source_file")
        findings, fixes = audit_file(path, auto_fix=False)
        if fixes:
            raise RuntimeError("unexpected_source_mutation")
        results[f"contracts/{path.name}"] = (findings, fixes)

    report = build_report(results)
    # Do not serve free-form OWNER_INFO metadata to callers.
    report["meta"] = {"scan_timestamp": datetime.now(timezone.utc).isoformat()}
    return {
        "status": "ready",
        "last_success_at": report["meta"]["scan_timestamp"],
        "mode": "read_only_source_patterns",
        "report": report,
        "limitations": "Static heuristic scan of bundled source files; not a comprehensive audit.",
    }


def snapshot() -> dict:
    """Real scan result, with unconfigured on-chain monitoring clearly labeled."""
    return {
        "ok": True,
        "service": "ARTEMIS-2.1",
        "source_audit": source_snapshot(),
        "monitor": {
            "status": "not_configured",
            "chain": "base",
            "factory": None,
            "last_success_at": None,
            "last_block_processed": None,
            "coverage_start_block": None,
            "behind_blocks": None,
            "contracts_audited": 0,
            "recent_contracts": [],
            "coverage": "No factory event coverage. Verified deployment address required.",
            "storage": "none",
            "limitations": "The read-only snapshot API does not run a blockchain monitor.",
        },
    }


class SnapshotHandler(BaseHTTPRequestHandler):
    server_version = "ARTEMIS-Snapshot"
    sys_version = ""

    def _send(self, status: int, payload: dict) -> None:
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        url = urlsplit(self.path)
        if url.path == "/healthz" and not url.query:
            ok = ready()
            self._send(200 if ok else 503, {"ok": ok, "service": "ARTEMIS-2.1", "mode": "read_only"})
            return
        if url.path != "/v1/snapshot" or url.query:
            self._send(404, {"ok": False, "error": "not_found"})
            return
        if not ready():
            self._send(503, {"ok": False, "error": "service_not_configured"})
            return
        provided = self.headers.get("Authorization", "")
        expected = "Bearer " + os.environ["ARTEMIS_API_KEY"]
        if not hmac.compare_digest(provided, expected):
            self._send(401, {"ok": False, "error": "unauthorized"})
            return
        try:
            self._send(200, snapshot())
        except Exception:
            LOG.exception("Source audit failed")
            self._send(503, {"ok": False, "error": "source_audit_unavailable"})

    def do_POST(self) -> None:  # noqa: N802
        self._send(405, {"ok": False, "error": "method_not_allowed"})

    def do_PUT(self) -> None:  # noqa: N802
        self._send(405, {"ok": False, "error": "method_not_allowed"})

    def do_DELETE(self) -> None:  # noqa: N802
        self._send(405, {"ok": False, "error": "method_not_allowed"})

    def log_message(self, fmt: str, *args: object) -> None:
        # Avoid logging arbitrary URLs or authorization material.
        LOG.info("HTTP request completed")


def create_server(host: str = "0.0.0.0", port: int = 10000) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), SnapshotHandler)
    server.daemon_threads = True
    return server


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    port = int(os.environ.get("PORT", "10000"))
    if port < 1 or port > 65535:
        raise SystemExit("Invalid PORT")
    server = create_server(port=port)
    LOG.info("ARTEMIS read-only snapshot API listening")
    server.serve_forever()


if __name__ == "__main__":
    main()
