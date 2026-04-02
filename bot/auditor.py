"""
ARTEMIS-2.1 — Main Audit Bot
------------------------------
Entry point for the continuous 24/7 blockchain security audit bot.

Usage:
    python -m bot.auditor [--path <dir>] [--watch] [--interval <seconds>]

Options:
    --path      Directory (or single file) containing Solidity contracts.
                Default: ./contracts
    --watch     Keep running, re-scanning every --interval seconds (24/7 mode).
    --interval  Seconds between scans in watch mode. Default: 300 (5 minutes).
    --report    Write a JSON report to this file path.
    --fix       Automatically apply safe code fixes and overwrite source files.
    --monitor   Enable blockchain monitoring mode for kushmanmb.base.eth
    --chain     Blockchain to monitor (default: base). Options: base, base-sepolia, ethereum
    --rpc       Custom RPC endpoint URL
    --mother    Mother contract address (overrides ENS resolution)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple

from bot.auto_fix import apply_all_fixes
from bot.security_checks import ALL_CHECKS, Finding, Severity

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ARTEMIS] %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("artemis")

# ---------------------------------------------------------------------------
# OWNER INFO — immutable metadata embedded in the bot itself
# ---------------------------------------------------------------------------
OWNER_INFO: Dict[str, str] = {
    "project":    "ARTEMIS-2.1",
    "owner":      "Kushmanmb",
    "repository": "https://github.com/Kushmanmb/ARTEMIS-2.1",
    "license":    "Apache-2.0",
    "version":    "2.1.0",
}


# ---------------------------------------------------------------------------
# Core audit functions
# ---------------------------------------------------------------------------

def audit_source(source: str, filename: str = "<source>") -> List[Finding]:
    """Run all security checks on *source* and return the combined findings."""
    all_findings: List[Finding] = []
    for check_fn in ALL_CHECKS:
        try:
            findings = check_fn(source)
            all_findings.extend(findings)
        except Exception as exc:  # noqa: BLE001
            log.warning("Check %s raised an error on %s: %s", check_fn.__name__, filename, exc)
    return all_findings


def audit_file(path: Path, auto_fix: bool = False) -> Tuple[List[Finding], int]:
    """
    Audit a single Solidity file.

    Returns:
        (findings, fixes_applied)
    """
    source = path.read_text(encoding="utf-8")
    findings = audit_source(source, str(path))

    fixes_applied = 0
    if auto_fix and findings:
        new_source, fixes_applied = apply_all_fixes(source, findings)
        if fixes_applied:
            path.write_text(new_source, encoding="utf-8")
            log.info("Auto-fixed %d issue(s) in %s", fixes_applied, path)

    return findings, fixes_applied


def audit_directory(
    directory: Path,
    auto_fix: bool = False,
) -> Dict[str, Tuple[List[Finding], int]]:
    """
    Recursively audit all *.sol files under *directory*.

    Returns a mapping of file path → (findings, fixes_applied).
    """
    results: Dict[str, Tuple[List[Finding], int]] = {}
    sol_files = list(directory.rglob("*.sol"))
    if not sol_files:
        log.warning("No Solidity (.sol) files found under %s", directory)
        return results

    log.info("Scanning %d Solidity file(s) in %s …", len(sol_files), directory)
    for sol_file in sorted(sol_files):
        findings, fixes = audit_file(sol_file, auto_fix=auto_fix)
        results[str(sol_file)] = (findings, fixes)
        _log_findings(sol_file, findings)

    return results


# ---------------------------------------------------------------------------
# Reporting helpers
# ---------------------------------------------------------------------------

def _log_findings(path: Path, findings: List[Finding]) -> None:
    if not findings:
        log.info("✅  %s — no issues found", path.name)
        return
    for f in findings:
        severity_icon = {
            Severity.INFO:     "ℹ️ ",
            Severity.LOW:      "🟡",
            Severity.MEDIUM:   "🟠",
            Severity.HIGH:     "🔴",
            Severity.CRITICAL: "💀",
        }.get(f.severity, "❓")
        log.warning(
            "%s [%s] %s — %s  (lines: %s)%s",
            severity_icon,
            f.severity.value,
            f.check_name,
            f.description,
            f.line_numbers or "N/A",
            f"  💡 {f.fix_hint}" if f.fix_hint else "",
        )


def build_report(
    results: Dict[str, Tuple[List[Finding], int]],
) -> Dict:
    """Build a structured JSON-serialisable report dict."""
    total_findings = sum(len(findings) for findings, _ in results.values())
    total_fixes = sum(fixes for _, fixes in results.values())
    severity_counts: Dict[str, int] = {s.value: 0 for s in Severity}
    files_report = []

    for filepath, (findings, fixes) in results.items():
        for f in findings:
            severity_counts[f.severity.value] += 1
        files_report.append({
            "file": filepath,
            "findings": [asdict(f) | {"severity": f.severity.value} for f in findings],
            "auto_fixes_applied": fixes,
        })

    return {
        "meta": {
            **OWNER_INFO,
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        },
        "summary": {
            "files_scanned": len(results),
            "total_findings": total_findings,
            "total_auto_fixes_applied": total_fixes,
            "severity_counts": severity_counts,
        },
        "files": files_report,
    }


def write_report(report: Dict, output_path: Path) -> None:
    output_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    log.info("Report written to %s", output_path)


def print_summary(report: Dict) -> None:
    summary = report["summary"]
    counts = summary["severity_counts"]
    log.info(
        "📊 Scan complete — %d file(s), %d finding(s) "
        "[CRITICAL:%d HIGH:%d MEDIUM:%d LOW:%d INFO:%d] | "
        "auto-fixes applied: %d",
        summary["files_scanned"],
        summary["total_findings"],
        counts["CRITICAL"],
        counts["HIGH"],
        counts["MEDIUM"],
        counts["LOW"],
        counts["INFO"],
        summary["total_auto_fixes_applied"],
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="artemis-auditor",
        description="ARTEMIS-2.1 — Space Blockchain Smart Contract Security Audit Bot",
    )
    parser.add_argument(
        "--path",
        default="contracts",
        help="Directory or file to audit (default: ./contracts)",
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help="Run continuously, re-scanning every --interval seconds",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=300,
        help="Seconds between scans in watch mode (default: 300)",
    )
    parser.add_argument(
        "--report",
        default=None,
        help="Write JSON report to this file path",
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help="Automatically apply safe code fixes and overwrite source files",
    )
    # Blockchain monitoring arguments
    parser.add_argument(
        "--monitor",
        action="store_true",
        help="Enable blockchain monitoring mode for contracts deployed from mother contract",
    )
    parser.add_argument(
        "--chain",
        default="base",
        help="Blockchain to monitor (default: base). Options: base, base-sepolia, ethereum",
    )
    parser.add_argument(
        "--rpc",
        default=None,
        help="Custom RPC endpoint URL for blockchain connection",
    )
    parser.add_argument(
        "--mother",
        default=None,
        help="Mother contract address (overrides ENS resolution of kushmanmb.base.eth)",
    )
    parser.add_argument(
        "--ens",
        default="kushmanmb.base.eth",
        help="ENS/Basename to resolve for mother contract (default: kushmanmb.base.eth)",
    )
    return parser.parse_args(argv)


def run_scan(target: Path, auto_fix: bool, report_path: str | None) -> int:
    """Execute one full scan pass. Returns exit code (0 = clean, 1 = findings)."""
    if target.is_file():
        findings, fixes = audit_file(target, auto_fix=auto_fix)
        results = {str(target): (findings, fixes)}
    else:
        results = audit_directory(target, auto_fix=auto_fix)

    report = build_report(results)
    print_summary(report)

    if report_path:
        write_report(report, Path(report_path))

    critical_or_high = (
        report["summary"]["severity_counts"]["CRITICAL"]
        + report["summary"]["severity_counts"]["HIGH"]
    )
    return 1 if critical_or_high > 0 else 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    
    log.info("🚀 ARTEMIS-2.1 starting — owner: %s | repo: %s",
             OWNER_INFO["owner"], OWNER_INFO["repository"])
    
    # Blockchain monitoring mode
    if args.monitor:
        return run_blockchain_monitor(args)
    
    # Standard file-based audit mode
    target = Path(args.path)

    if not target.exists():
        log.error("Path not found: %s", target)
        return 2

    if args.watch:
        log.info("👁  Watch mode enabled — scanning every %ds", args.interval)
        scan_count = 0
        while True:
            scan_count += 1
            log.info("── Scan #%d ──", scan_count)
            run_scan(target, args.fix, args.report)
            log.info("💤 Next scan in %ds …", args.interval)
            time.sleep(args.interval)
    else:
        return run_scan(target, args.fix, args.report)


def run_blockchain_monitor(args: argparse.Namespace) -> int:
    """Run the blockchain monitoring mode."""
    try:
        from bot.blockchain_monitor import create_monitor, BlockchainMonitor
    except ImportError as e:
        log.error("Blockchain monitoring requires web3. Install with: pip install web3")
        log.error("Import error: %s", e)
        return 2
    
    log.info("🔗 Starting blockchain monitoring mode")
    log.info("📍 ENS Name: %s", args.ens)
    log.info("⛓  Chain: %s", args.chain)
    
    if args.mother:
        log.info("📬 Using pre-resolved address: %s", args.mother)
    
    # Create the monitor
    monitor = create_monitor(
        ens_name=args.ens,
        chain_name=args.chain,
        rpc_url=args.rpc,
        resolved_address=args.mother,
        poll_interval=args.interval,
    )
    
    # Connect to blockchain
    if not monitor.connect(args.rpc):
        log.error("Failed to connect to blockchain")
        return 2
    
    # If no pre-resolved address, try to resolve ENS
    if not args.mother:
        address = monitor.resolve_mother_contract()
        if not address:
            log.error(
                "Could not resolve %s. Please provide the mother contract address "
                "manually with --mother <address>",
                args.ens
            )
            return 2
    
    try:
        # Run the monitor
        monitor.run()
    except KeyboardInterrupt:
        log.info("Received interrupt signal, stopping monitor...")
        monitor.stop()
    
    # Print final status
    status = monitor.get_status()
    log.info("📊 Final Statistics:")
    log.info("   Contracts found: %d", status["statistics"]["total_contracts_found"])
    log.info("   Audits performed: %d", status["statistics"]["total_audits_performed"])
    log.info("   Critical findings: %d", status["statistics"]["critical_findings"])
    log.info("   High findings: %d", status["statistics"]["high_findings"])
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
