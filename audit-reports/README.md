# ARTEMIS-2.1 Security Audit Reports

This directory contains security audit tools and reports for the ARTEMIS-2.1 project.

## Overview

The security audit system scans both NPM (JavaScript/TypeScript) and Python dependencies for known vulnerabilities, generates human-readable reports, and creates visual representations of the vulnerability landscape.

## Contents

- **generate_audit_report.py** - Python script that runs audits and generates reports
- **AUDIT_REPORT.txt** - Human-readable detailed audit report
- **vulnerability_chart.png** - Bar chart showing vulnerabilities by severity
- **dependency_chain.png** - Visualization of vulnerability dependency chains

## Usage

### Generate Audit Report

```bash
# Run from the repository root
python audit-reports/generate_audit_report.py

# Or using npm script
npm run audit:report
```

### Quick Audit Commands

```bash
# Check NPM vulnerabilities
npm audit

# Auto-fix non-breaking vulnerabilities
npm audit fix

# Check Python vulnerabilities
pip-audit -r requirements.txt
```

## Current Security Status

| Category | Status |
|----------|--------|
| Critical Severity | ✅ 0 |
| High Severity | ⚠️ 1 (transitive, requires breaking change) |
| Moderate Severity | ⚠️ 14 |
| Low Severity | ⚠️ 20 |
| Python Packages | ✅ No vulnerabilities |

### Mitigations Applied

The following vulnerabilities have been mitigated via package overrides in `package.json`:

- **serialize-javascript** - RCE vulnerability fixed via override to >=7.0.5
- **cookie** - Out of bounds character handling fixed via override to >=0.7.0
- **lodash** - Prototype pollution fixed via override to >=4.18.0

### Remaining Vulnerabilities

#### High Severity (1)

| Package | Issue | Status |
|---------|-------|--------|
| undici | HTTP Request Smuggling, Memory Issues | Requires Hardhat v3 (breaking change) |

#### Moderate/Low Severity

The remaining moderate/low severity vulnerabilities are in transitive dependencies and would require breaking changes to fix:

1. **bn.js** - Infinite loop with crafted input (moderate)
2. **elliptic** - Cryptographic implementation concern (low)
3. **tmp** - Symlink directory write (low)
4. **@ethersproject/*** - Various low-severity issues in ethers.js v5

These will be resolved when the Hardhat v3 ecosystem becomes stable and compatible with all tooling.

## Automated CI/CD Audit

The `.github/workflows/audit.yml` workflow runs security audits:
- On every push and pull request
- Every 6 hours via scheduled cron job
- Manually via workflow dispatch

The workflow will fail if any CRITICAL or HIGH severity vulnerabilities are found.

## Updating Dependencies

When addressing vulnerabilities, use this approach:

1. **Check for updates**: `npm outdated`
2. **Review changelogs** for breaking changes
3. **Update package.json** with new versions
4. **Test thoroughly** before committing
5. **Use overrides** for transitive dependencies that can't be updated directly

## Security Policy

For security concerns, please review the project's security policies and report vulnerabilities through the appropriate channels.
