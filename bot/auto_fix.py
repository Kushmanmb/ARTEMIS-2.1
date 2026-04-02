"""
ARTEMIS-2.1 — Auto-Fix Module
------------------------------
Applies safe, targeted source-code patches for auto_fixable findings produced
by security_checks.py.  Each fixer receives the source string and the Finding
that triggered it, and returns the (possibly modified) source string plus a
boolean indicating whether a change was actually made.
"""

from __future__ import annotations

import re
from typing import Callable, Dict, Tuple

from bot.security_checks import Finding


FixerFn = Callable[[str, Finding], Tuple[str, bool]]


def _fix_spdx_license(source: str, finding: Finding) -> Tuple[str, bool]:
    """Prepend SPDX-License-Identifier if missing."""
    if 'SPDX-License-Identifier' in source:
        return source, False
    header = '// SPDX-License-Identifier: Apache-2.0\n'
    return header + source, True


def _fix_tx_origin_auth(source: str, finding: Finding) -> Tuple[str, bool]:
    """Replace tx.origin == … / tx.origin != … with msg.sender equivalents."""
    new_source = re.sub(r'\btx\.origin\b', 'msg.sender', source)
    changed = new_source != source
    return new_source, changed


def _fix_unchecked_call_return(source: str, finding: Finding) -> Tuple[str, bool]:
    """
    Wrap bare `.call{...}(...)` expressions with a success-check pattern.
    Only replaces the first instance per finding (conservative approach).
    """
    # Match patterns like: `addr.call{value: v}(data);`
    # that are NOT already prefixed with `(bool ...) =` or `require(`
    pattern = re.compile(
        r'^([ \t]*)(\w[\w.]*\.call(?:\{[^}]*\})?\([^)]*\))\s*;',
        re.MULTILINE,
    )

    def replace_call(m: re.Match) -> str:
        indent = m.group(1)
        call_expr = m.group(2)
        return (
            f'{indent}(bool _artemisSuccess, ) = {call_expr};\n'
            f'{indent}require(_artemisSuccess, "ARTEMIS: low-level call failed");'
        )

    new_source = pattern.sub(replace_call, source, count=1)
    changed = new_source != source
    return new_source, changed


def _fix_integer_overflow_pragma(source: str, finding: Finding) -> Tuple[str, bool]:
    """Upgrade old pragma version to ^0.8.20 to gain built-in overflow checks."""
    new_source = re.sub(
        r'pragma\s+solidity\s+[^;]+;',
        'pragma solidity ^0.8.20;',
        source,
        count=1,
    )
    changed = new_source != source
    return new_source, changed


def _fix_unprotected_selfdestruct(source: str, finding: Finding) -> Tuple[str, bool]:
    """Add onlyOwner modifier to a function containing selfdestruct."""
    # Find the function signature line that precedes the selfdestruct
    lines = source.splitlines()
    if not finding.line_numbers:
        return source, False

    sd_line_idx = finding.line_numbers[0] - 1  # 0-based
    # Walk backward to find the enclosing function header
    fn_pattern = re.compile(r'\bfunction\s+\w+')
    for i in range(sd_line_idx, -1, -1):
        if fn_pattern.search(lines[i]):
            # Add onlyOwner if not already present
            if 'onlyOwner' not in lines[i]:
                # Insert modifier before the opening brace or at end of line
                lines[i] = re.sub(
                    r'(\)\s*)(public|external)',
                    r'\1\2 onlyOwner',
                    lines[i],
                )
            break
    new_source = '\n'.join(lines)
    changed = new_source != source
    return new_source, changed


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_FIXERS: Dict[str, FixerFn] = {
    'MISSING_SPDX_LICENSE':     _fix_spdx_license,
    'TX_ORIGIN_AUTH':            _fix_tx_origin_auth,
    'UNCHECKED_CALL_RETURN':     _fix_unchecked_call_return,
    'INTEGER_OVERFLOW':          _fix_integer_overflow_pragma,
    'UNPROTECTED_SELFDESTRUCT':  _fix_unprotected_selfdestruct,
}


def apply_fix(source: str, finding: Finding) -> Tuple[str, bool]:
    """
    Attempt to apply an automated fix for *finding* to *source*.

    Returns:
        (new_source, was_changed)  — new_source equals source when no fix exists
        or when the fixer determined no change was required.
    """
    if not finding.auto_fixable:
        return source, False
    fixer = _FIXERS.get(finding.check_name)
    if fixer is None:
        return source, False
    return fixer(source, finding)


def apply_all_fixes(source: str, findings: list[Finding]) -> Tuple[str, int]:
    """
    Apply all auto-fixable findings to *source* in sequence.

    Returns:
        (final_source, number_of_fixes_applied)
    """
    fixes_applied = 0
    for finding in findings:
        source, changed = apply_fix(source, finding)
        if changed:
            fixes_applied += 1
    return source, fixes_applied
