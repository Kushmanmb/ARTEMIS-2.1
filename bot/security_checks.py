"""
ARTEMIS-2.1 — Security Check Patterns
--------------------------------------
Each check is a callable that accepts raw Solidity source (str) and returns a
list of Finding namedtuples describing any detected issues.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Finding:
    check_name: str
    severity: Severity
    description: str
    line_numbers: List[int] = field(default_factory=list)
    auto_fixable: bool = False
    fix_hint: str = ""


# ---------------------------------------------------------------------------
# Individual check functions
# ---------------------------------------------------------------------------

def check_reentrancy(source: str) -> List[Finding]:
    """Detect external calls followed by state-variable writes (classic reentrancy)."""
    findings: List[Finding] = []
    lines = source.splitlines()
    call_pattern = re.compile(
        r'\.(call|send|transfer)\s*[({]', re.IGNORECASE
    )
    state_write_pattern = re.compile(r'\b\w+\s*[\[\(]?[^\)]*[\]\)]?\s*=\s*[^=]')

    for i, line in enumerate(lines, start=1):
        if call_pattern.search(line):
            # Look ahead for a state write within the next 5 lines
            lookahead = lines[i: min(i + 5, len(lines))]
            for j, ahead_line in enumerate(lookahead, start=i + 1):
                if state_write_pattern.search(ahead_line) and '==' not in ahead_line:
                    findings.append(Finding(
                        check_name="REENTRANCY",
                        severity=Severity.HIGH,
                        description=(
                            f"Potential reentrancy: external call on line {i} followed "
                            f"by state write on line {j}. Use checks-effects-interactions pattern."
                        ),
                        line_numbers=[i, j],
                        auto_fixable=True,
                        fix_hint=(
                            "Move all state updates BEFORE the external call, "
                            "or use a ReentrancyGuard modifier."
                        ),
                    ))
                    break
    return findings


def check_integer_overflow(source: str) -> List[Finding]:
    """Warn about unchecked arithmetic in Solidity < 0.8.0 contracts."""
    findings: List[Finding] = []
    pragma_match = re.search(r'pragma\s+solidity\s+([^;]+);', source)
    if not pragma_match:
        return findings

    version_str = pragma_match.group(1).strip()
    # If the pragma specifies a version below 0.8.0 warn about overflow
    old_version = re.search(r'0\.[0-7]\.', version_str)
    if old_version:
        unsafe_ops = re.finditer(r'(\w+)\s*(\+\+|--|\+=|-=|\*=)', source)
        seen_lines: set = set()
        lines = source.splitlines()
        for m in unsafe_ops:
            # find line number
            line_num = source[: m.start()].count('\n') + 1
            if line_num not in seen_lines:
                seen_lines.add(line_num)
                findings.append(Finding(
                    check_name="INTEGER_OVERFLOW",
                    severity=Severity.HIGH,
                    description=(
                        f"Integer overflow/underflow risk on line {line_num} "
                        f"(Solidity {version_str}). Use SafeMath or upgrade to ^0.8.0."
                    ),
                    line_numbers=[line_num],
                    auto_fixable=True,
                    fix_hint="Upgrade pragma to ^0.8.0 or wrap arithmetic with SafeMath.",
                ))
    return findings


def check_unprotected_selfdestruct(source: str) -> List[Finding]:
    """Detect selfdestruct calls that are not gated by an owner/auth check."""
    findings: List[Finding] = []
    lines = source.splitlines()
    sd_pattern = re.compile(r'\bselfdestruct\b|\bsuicide\b', re.IGNORECASE)
    auth_patterns = [
        re.compile(r'\bonlyOwner\b'),
        re.compile(r'\brequire\s*\(\s*msg\.sender\s*=='),
        re.compile(r'\bonlyAdmin\b'),
        re.compile(r'\bonlyRole\b'),
    ]

    for i, line in enumerate(lines, start=1):
        if sd_pattern.search(line):
            # Look back 10 lines for an auth check
            context_start = max(0, i - 11)
            context = '\n'.join(lines[context_start: i])
            guarded = any(p.search(context) for p in auth_patterns)
            if not guarded:
                findings.append(Finding(
                    check_name="UNPROTECTED_SELFDESTRUCT",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Unprotected selfdestruct on line {i}. "
                        "Any caller could destroy the contract."
                    ),
                    line_numbers=[i],
                    auto_fixable=True,
                    fix_hint="Add an onlyOwner (or equivalent) modifier before selfdestruct.",
                ))
    return findings


def check_tx_origin_auth(source: str) -> List[Finding]:
    """Flag use of tx.origin for authentication."""
    findings: List[Finding] = []
    lines = source.splitlines()
    pattern = re.compile(r'\btx\.origin\b')

    for i, line in enumerate(lines, start=1):
        if pattern.search(line) and ('==' in line or '!=' in line):
            findings.append(Finding(
                check_name="TX_ORIGIN_AUTH",
                severity=Severity.HIGH,
                description=(
                    f"tx.origin used for authentication on line {i}. "
                    "Susceptible to phishing / contract-relay attacks."
                ),
                line_numbers=[i],
                auto_fixable=True,
                fix_hint="Replace tx.origin with msg.sender for authorization checks.",
            ))
    return findings


def check_unchecked_call_return(source: str) -> List[Finding]:
    """Detect low-level .call() whose return value is not checked."""
    findings: List[Finding] = []
    lines = source.splitlines()
    raw_call = re.compile(r'\.call\s*[({]', re.IGNORECASE)
    checked = re.compile(r'(bool\s+\w+\s*,|require\s*\(|if\s*\()')

    for i, line in enumerate(lines, start=1):
        if raw_call.search(line) and not checked.search(line):
            findings.append(Finding(
                check_name="UNCHECKED_CALL_RETURN",
                severity=Severity.MEDIUM,
                description=(
                    f"Return value of .call() not checked on line {i}. "
                    "Silent failures can leave the contract in an inconsistent state."
                ),
                line_numbers=[i],
                auto_fixable=True,
                fix_hint=(
                    "Capture the return value: `(bool success, ) = addr.call{...}(data);` "
                    "then `require(success, 'call failed');`."
                ),
            ))
    return findings


def check_missing_access_control(source: str) -> List[Finding]:
    """Warn about public/external state-mutating functions that lack any access control."""
    findings: List[Finding] = []
    lines = source.splitlines()
    # Only match functions that are NOT view/pure (i.e., they can modify state)
    fn_pattern = re.compile(
        r'\bfunction\s+(\w+)\s*\([^)]*\)\s*(?:public|external)\b'
    )
    readonly_pattern = re.compile(r'\b(view|pure)\b')
    access_patterns = [
        re.compile(r'\bonlyOwner\b'),
        re.compile(r'\bonlyAdmin\b'),
        re.compile(r'\bonlyRole\b'),
        re.compile(r'\brequire\s*\(\s*msg\.sender\s*=='),
        re.compile(r'\bwhenNotPaused\b'),
    ]

    for i, line in enumerate(lines, start=1):
        m = fn_pattern.search(line)
        if m:
            fn_name = m.group(1)
            if fn_name in ('constructor',):
                continue
            # Gather the full function signature (may span a few lines)
            sig_lines = lines[i - 1: min(len(lines), i + 3)]
            sig_text = '\n'.join(sig_lines)
            # Skip view/pure functions — they cannot modify state
            if readonly_pattern.search(sig_text):
                continue
            # Check surrounding 3 lines for access modifier
            context_lines = lines[max(0, i - 1): min(len(lines), i + 2)]
            context = '\n'.join(context_lines)
            has_access = any(p.search(context) for p in access_patterns)
            # Only flag if there's a body (has '{')
            body_search = lines[i - 1: min(len(lines), i + 5)]
            has_body = any('{' in bl for bl in body_search)
            if not has_access and has_body:
                findings.append(Finding(
                    check_name="MISSING_ACCESS_CONTROL",
                    severity=Severity.MEDIUM,
                    description=(
                        f"Function `{fn_name}` on line {i} appears to have no access control. "
                        "Any caller can invoke it."
                    ),
                    line_numbers=[i],
                    auto_fixable=False,
                    fix_hint=(
                        f"Add an appropriate modifier (e.g. onlyOwner) to `{fn_name}` "
                        "or add a require(msg.sender == owner) check."
                    ),
                ))
    return findings


def check_hardcoded_address(source: str) -> List[Finding]:
    """Detect hardcoded Ethereum addresses (potential admin key exposure)."""
    findings: List[Finding] = []
    lines = source.splitlines()
    addr_pattern = re.compile(r'\b0x[0-9a-fA-F]{40}\b')
    # Ignore addresses in comments
    comment_pattern = re.compile(r'^\s*//')

    for i, line in enumerate(lines, start=1):
        if comment_pattern.match(line):
            continue
        if addr_pattern.search(line):
            findings.append(Finding(
                check_name="HARDCODED_ADDRESS",
                severity=Severity.LOW,
                description=(
                    f"Hardcoded address on line {i}. "
                    "Consider using a configurable or immutable variable instead."
                ),
                line_numbers=[i],
                auto_fixable=False,
                fix_hint="Store the address as a constructor parameter or immutable variable.",
            ))
    return findings


def check_spdx_license(source: str) -> List[Finding]:
    """Ensure SPDX license identifier is present (best practice / compiler warning)."""
    if 'SPDX-License-Identifier' not in source:
        return [Finding(
            check_name="MISSING_SPDX_LICENSE",
            severity=Severity.INFO,
            description="No SPDX-License-Identifier found. Add one to suppress compiler warnings.",
            auto_fixable=True,
            fix_hint="Add `// SPDX-License-Identifier: Apache-2.0` at the top of the file.",
        )]
    return []


# ---------------------------------------------------------------------------
# Registry — all checks that run by default
# ---------------------------------------------------------------------------

ALL_CHECKS = [
    check_reentrancy,
    check_integer_overflow,
    check_unprotected_selfdestruct,
    check_tx_origin_auth,
    check_unchecked_call_return,
    check_missing_access_control,
    check_hardcoded_address,
    check_spdx_license,
]
