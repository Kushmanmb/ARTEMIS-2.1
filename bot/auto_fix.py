"""Conservative remediation proposals for ARTEMIS findings.

Only source-independent metadata fixes belong here. Security logic changes such
as authorization, call handling, arithmetic, and reentrancy require a human
review because a text substitution cannot establish intended contract behavior.
"""

from __future__ import annotations

import re

from bot.security_checks import Finding


def apply_fix(
    source: str, finding: Finding, spdx_license: str | None = None
) -> tuple[str, bool]:
    """Return a proposed source edit only for an explicitly licensed SPDX header.

    The result is a proposal; callers must create a reviewable patch. This
    function never writes files and deliberately refuses security-logic fixes.
    """
    if not finding.auto_fixable or finding.check_name != "MISSING_SPDX_LICENSE":
        return source, False
    if "SPDX-License-Identifier" in source:
        return source, False
    if not spdx_license or not re.fullmatch(r"[A-Za-z0-9.+-]+", spdx_license):
        return source, False
    return f"// SPDX-License-Identifier: {spdx_license}\n" + source, True


def apply_all_fixes(
    source: str,
    findings: list[Finding],
    spdx_license: str | None = None,
) -> tuple[str, int]:
    """Build a source proposal from the explicitly supported safe fixers."""
    proposed = source
    fixes_proposed = 0
    for finding in findings:
        proposed, changed = apply_fix(proposed, finding, spdx_license)
        if changed:
            fixes_proposed += 1
    return proposed, fixes_proposed
