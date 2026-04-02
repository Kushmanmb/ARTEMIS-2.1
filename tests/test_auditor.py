"""
ARTEMIS-2.1 — Test Suite
--------------------------
Unit tests for the security audit bot: security_checks.py, auto_fix.py,
and auditor.py core functions.

Run with:
    python -m pytest tests/ -v
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bot.auditor import audit_source, build_report, OWNER_INFO, run_scan
from bot.auto_fix import apply_fix, apply_all_fixes
from bot.security_checks import (
    Finding,
    Severity,
    check_reentrancy,
    check_integer_overflow,
    check_unprotected_selfdestruct,
    check_tx_origin_auth,
    check_unchecked_call_return,
    check_missing_access_control,
    check_hardcoded_address,
    check_spdx_license,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

CLEAN_CONTRACT = """\
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

contract Clean {
    address public immutable owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function withdraw(uint256 amount) external onlyOwner {
        (bool success, ) = owner.call{value: amount}("");
        require(success, "transfer failed");
    }
}
"""

VULNERABLE_REENTRANCY = """\
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

contract Vulnerable {
    mapping(address => uint256) public balances;

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool success, ) = msg.sender.call{value: amount}("");
        balances[msg.sender] = 0;  // state write AFTER call — reentrancy risk
    }
}
"""

VULNERABLE_OLD_PRAGMA = """\
pragma solidity 0.4.24;

contract OldContract {
    uint256 public counter;
    function inc() public { counter++; }
}
"""

VULNERABLE_SELFDESTRUCT = """\
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

contract Bomb {
    function kill() public {
        selfdestruct(payable(msg.sender));
    }
}
"""

VULNERABLE_TX_ORIGIN = """\
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

contract TxOriginAuth {
    address public owner;
    function transfer(address to, uint256 amount) public {
        require(tx.origin == owner, "not owner");
        // transfer logic
    }
}
"""

VULNERABLE_UNCHECKED_CALL = """\
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

contract UncheckedCall {
    function send(address target, bytes memory data) public {
        target.call(data);
    }
}
"""

NO_SPDX = """\
pragma solidity ^0.8.20;
contract NoLicense {}
"""

HARDCODED_ADDR = """\
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;
contract HardAddr {
    address public treasury = 0xAbCdEf1234567890AbCdEf1234567890AbCdEf12;
}
"""


# ---------------------------------------------------------------------------
# security_checks tests
# ---------------------------------------------------------------------------

class TestCheckSpdxLicense:
    def test_clean_has_no_findings(self):
        assert check_spdx_license(CLEAN_CONTRACT) == []

    def test_missing_spdx_is_detected(self):
        findings = check_spdx_license(NO_SPDX)
        assert len(findings) == 1
        assert findings[0].check_name == "MISSING_SPDX_LICENSE"
        assert findings[0].severity == Severity.INFO
        assert findings[0].auto_fixable is True


class TestCheckReentrancy:
    def test_reentrancy_is_detected(self):
        findings = check_reentrancy(VULNERABLE_REENTRANCY)
        assert any(f.check_name == "REENTRANCY" for f in findings)

    def test_clean_contract_no_reentrancy(self):
        # The clean contract does a state-write BEFORE the call, so no finding
        findings = check_reentrancy(CLEAN_CONTRACT)
        assert findings == []

    def test_finding_severity_is_high(self):
        findings = check_reentrancy(VULNERABLE_REENTRANCY)
        reentrancy = [f for f in findings if f.check_name == "REENTRANCY"]
        assert all(f.severity == Severity.HIGH for f in reentrancy)

    def test_finding_references_line_numbers(self):
        findings = check_reentrancy(VULNERABLE_REENTRANCY)
        reentrancy = [f for f in findings if f.check_name == "REENTRANCY"]
        assert reentrancy
        assert len(reentrancy[0].line_numbers) == 2


class TestCheckIntegerOverflow:
    def test_old_pragma_detected(self):
        findings = check_integer_overflow(VULNERABLE_OLD_PRAGMA)
        assert any(f.check_name == "INTEGER_OVERFLOW" for f in findings)

    def test_new_pragma_clean(self):
        findings = check_integer_overflow(CLEAN_CONTRACT)
        assert findings == []

    def test_finding_is_auto_fixable(self):
        findings = check_integer_overflow(VULNERABLE_OLD_PRAGMA)
        overflow = [f for f in findings if f.check_name == "INTEGER_OVERFLOW"]
        assert all(f.auto_fixable for f in overflow)


class TestCheckSelfdestruct:
    def test_unprotected_selfdestruct_detected(self):
        findings = check_unprotected_selfdestruct(VULNERABLE_SELFDESTRUCT)
        assert any(f.check_name == "UNPROTECTED_SELFDESTRUCT" for f in findings)

    def test_severity_is_critical(self):
        findings = check_unprotected_selfdestruct(VULNERABLE_SELFDESTRUCT)
        sd = [f for f in findings if f.check_name == "UNPROTECTED_SELFDESTRUCT"]
        assert all(f.severity == Severity.CRITICAL for f in sd)

    def test_clean_no_selfdestruct(self):
        assert check_unprotected_selfdestruct(CLEAN_CONTRACT) == []


class TestCheckTxOrigin:
    def test_tx_origin_auth_detected(self):
        findings = check_tx_origin_auth(VULNERABLE_TX_ORIGIN)
        assert any(f.check_name == "TX_ORIGIN_AUTH" for f in findings)

    def test_clean_no_tx_origin(self):
        assert check_tx_origin_auth(CLEAN_CONTRACT) == []

    def test_severity_is_high(self):
        findings = check_tx_origin_auth(VULNERABLE_TX_ORIGIN)
        tx = [f for f in findings if f.check_name == "TX_ORIGIN_AUTH"]
        assert all(f.severity == Severity.HIGH for f in tx)


class TestCheckUncheckedCall:
    def test_unchecked_call_detected(self):
        findings = check_unchecked_call_return(VULNERABLE_UNCHECKED_CALL)
        assert any(f.check_name == "UNCHECKED_CALL_RETURN" for f in findings)

    def test_clean_call_not_flagged(self):
        # Clean contract wraps .call with (bool success, ) = …
        assert check_unchecked_call_return(CLEAN_CONTRACT) == []


class TestCheckHardcodedAddress:
    def test_hardcoded_address_detected(self):
        findings = check_hardcoded_address(HARDCODED_ADDR)
        assert any(f.check_name == "HARDCODED_ADDRESS" for f in findings)

    def test_clean_no_hardcoded(self):
        assert check_hardcoded_address(CLEAN_CONTRACT) == []


# ---------------------------------------------------------------------------
# auto_fix tests
# ---------------------------------------------------------------------------

class TestAutoFix:
    def test_fix_spdx(self):
        new_source, changed = apply_fix(NO_SPDX, Finding(
            check_name="MISSING_SPDX_LICENSE",
            severity=Severity.INFO,
            description="",
            auto_fixable=True,
        ))
        assert changed
        assert new_source.startswith("// SPDX-License-Identifier:")

    def test_fix_spdx_idempotent(self):
        source_with_spdx = "// SPDX-License-Identifier: MIT\n" + NO_SPDX
        new_source, changed = apply_fix(source_with_spdx, Finding(
            check_name="MISSING_SPDX_LICENSE",
            severity=Severity.INFO,
            description="",
            auto_fixable=True,
        ))
        assert not changed

    def test_fix_tx_origin(self):
        finding = Finding(
            check_name="TX_ORIGIN_AUTH",
            severity=Severity.HIGH,
            description="",
            auto_fixable=True,
        )
        new_source, changed = apply_fix(VULNERABLE_TX_ORIGIN, finding)
        assert changed
        assert "tx.origin" not in new_source
        assert "msg.sender" in new_source

    def test_fix_pragma_upgrade(self):
        finding = Finding(
            check_name="INTEGER_OVERFLOW",
            severity=Severity.HIGH,
            description="",
            auto_fixable=True,
        )
        new_source, changed = apply_fix(VULNERABLE_OLD_PRAGMA, finding)
        assert changed
        assert "pragma solidity ^0.8.20;" in new_source

    def test_no_fix_for_non_fixable(self):
        finding = Finding(
            check_name="MISSING_ACCESS_CONTROL",
            severity=Severity.MEDIUM,
            description="",
            auto_fixable=False,
        )
        new_source, changed = apply_fix(CLEAN_CONTRACT, finding)
        assert not changed
        assert new_source == CLEAN_CONTRACT

    def test_apply_all_fixes(self):
        source = NO_SPDX + "\n" + VULNERABLE_TX_ORIGIN.replace(
            "// SPDX-License-Identifier: Apache-2.0\n", ""
        )
        findings = [
            Finding(check_name="MISSING_SPDX_LICENSE", severity=Severity.INFO,
                    description="", auto_fixable=True),
            Finding(check_name="TX_ORIGIN_AUTH", severity=Severity.HIGH,
                    description="", auto_fixable=True),
        ]
        new_source, count = apply_all_fixes(source, findings)
        assert count == 2
        assert "SPDX-License-Identifier" in new_source
        assert "tx.origin" not in new_source


# ---------------------------------------------------------------------------
# auditor.py integration tests
# ---------------------------------------------------------------------------

class TestAuditSource:
    def test_clean_contract_minimal_findings(self):
        findings = audit_source(CLEAN_CONTRACT, "clean.sol")
        # Clean contract should have no HIGH/CRITICAL findings
        bad = [f for f in findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        assert bad == []

    def test_vulnerable_reentrancy_detected(self):
        findings = audit_source(VULNERABLE_REENTRANCY, "vuln.sol")
        assert any(f.check_name == "REENTRANCY" for f in findings)

    def test_old_pragma_detected(self):
        findings = audit_source(VULNERABLE_OLD_PRAGMA, "old.sol")
        assert any(f.check_name == "INTEGER_OVERFLOW" for f in findings)


class TestBuildReport:
    def _make_results(self, findings_by_file):
        return {k: (v, 0) for k, v in findings_by_file.items()}

    def test_report_has_owner_info(self):
        report = build_report(self._make_results({"test.sol": []}))
        assert report["meta"]["owners"] == OWNER_INFO["owners"]
        assert report["meta"]["project"] == OWNER_INFO["project"]
        assert report["meta"]["repository"] == OWNER_INFO["repository"]

    def test_report_summary_counts(self):
        findings = [
            Finding("REENTRANCY", Severity.HIGH, "desc", auto_fixable=True),
            Finding("MISSING_SPDX_LICENSE", Severity.INFO, "desc", auto_fixable=True),
        ]
        report = build_report(self._make_results({"test.sol": findings}))
        assert report["summary"]["total_findings"] == 2
        assert report["summary"]["severity_counts"]["HIGH"] == 1
        assert report["summary"]["severity_counts"]["INFO"] == 1

    def test_report_is_json_serialisable(self):
        findings = [Finding("REENTRANCY", Severity.HIGH, "d", [1, 2], True, "hint")]
        report = build_report(self._make_results({"f.sol": findings}))
        serialised = json.dumps(report)
        assert "ARTEMIS" in serialised

    def test_empty_scan_report(self):
        report = build_report({})
        assert report["summary"]["files_scanned"] == 0
        assert report["summary"]["total_findings"] == 0


class TestRunScan:
    def test_scan_clean_contract_returns_0(self, tmp_path):
        sol = tmp_path / "clean.sol"
        sol.write_text(CLEAN_CONTRACT, encoding="utf-8")
        exit_code = run_scan(sol, auto_fix=False, report_path=None)
        assert exit_code == 0

    def test_scan_high_severity_returns_1(self, tmp_path):
        sol = tmp_path / "reentrancy.sol"
        sol.write_text(VULNERABLE_REENTRANCY, encoding="utf-8")
        exit_code = run_scan(sol, auto_fix=False, report_path=None)
        assert exit_code == 1

    def test_scan_directory(self, tmp_path):
        (tmp_path / "a.sol").write_text(CLEAN_CONTRACT, encoding="utf-8")
        (tmp_path / "b.sol").write_text(VULNERABLE_REENTRANCY, encoding="utf-8")
        exit_code = run_scan(tmp_path, auto_fix=False, report_path=None)
        assert exit_code == 1

    def test_scan_writes_report(self, tmp_path):
        sol = tmp_path / "clean.sol"
        sol.write_text(CLEAN_CONTRACT, encoding="utf-8")
        report_file = tmp_path / "report.json"
        run_scan(sol, auto_fix=False, report_path=str(report_file))
        assert report_file.exists()
        data = json.loads(report_file.read_text())
        assert "meta" in data
        assert "summary" in data

    def test_auto_fix_modifies_file(self, tmp_path):
        sol = tmp_path / "old.sol"
        sol.write_text(VULNERABLE_OLD_PRAGMA, encoding="utf-8")
        run_scan(sol, auto_fix=True, report_path=None)
        updated = sol.read_text()
        assert "^0.8.20" in updated
