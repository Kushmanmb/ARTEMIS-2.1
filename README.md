# ARTEMIS-2.1

**A**utonomous **R**eal-**T**ime **E**thereum **M**onitor & **I**mmutable **S**ecurity

> Space Blockchain smart contract bot — 24/7 continuous security audit, auto-fix, and immutable owner provenance.

---

## Features

| Capability | Details |
|---|---|
| 🔒 Continuous Audit | Scans every Solidity contract for known vulnerability patterns |
| 🛠 Auto-Fix | Automatically patches safe, well-understood issues (reentrancy ordering, tx.origin, unchecked calls, old pragma, missing SPDX) |
| 💀 24/7 CI Coverage | GitHub Actions workflow runs on every push, PR, and on a 6-hour cron schedule |
| 📜 Immutable Owner Info | `ARTEMIS.sol` stores owner address, name, and deploy timestamp as `immutable` values — cannot be changed post-deploy |
| 🗂 On-Chain Audit Log | Findings can be recorded on-chain via `reportFinding()` so the audit trail is tamper-proof |
| ⏸ Circuit Breaker | `pause()` / `unpause()` halts sensitive operations the moment an incident is detected |

---

## Repository layout

```
ARTEMIS-2.1/
├── contracts/
│   └── ARTEMIS.sol          # On-chain security registry & circuit breaker
├── bot/
│   ├── auditor.py           # Main audit bot (CLI entry-point)
│   ├── security_checks.py   # Vulnerability detection patterns
│   └── auto_fix.py          # Automated source-code patching
├── tests/
│   └── test_auditor.py      # Unit & integration tests
├── .github/
│   └── workflows/
│       └── audit.yml        # 24/7 CI audit workflow
└── requirements.txt
```

---

## Quick start

```bash
# Install dependencies
pip install -r requirements.txt

# Audit the contracts/ directory once
python -m bot.auditor

# Audit with auto-fix enabled
python -m bot.auditor --fix

# Watch mode — re-scan every 5 minutes (24/7)
python -m bot.auditor --watch --interval 300

# Audit a specific file and save a JSON report
python -m bot.auditor --path contracts/ARTEMIS.sol --report report.json

# Run tests
python -m pytest tests/ -v
```

---

## Security checks

| Check | Severity | Auto-Fix |
|---|---|---|
| `REENTRANCY` | HIGH | ✅ (fix hint) |
| `INTEGER_OVERFLOW` | HIGH | ✅ (pragma upgrade) |
| `UNPROTECTED_SELFDESTRUCT` | CRITICAL | ✅ (adds modifier) |
| `TX_ORIGIN_AUTH` | HIGH | ✅ (replace with msg.sender) |
| `UNCHECKED_CALL_RETURN` | MEDIUM | ✅ (wrap with require) |
| `MISSING_ACCESS_CONTROL` | MEDIUM | ❌ (manual review needed) |
| `HARDCODED_ADDRESS` | LOW | ❌ (manual review needed) |
| `MISSING_SPDX_LICENSE` | INFO | ✅ (prepend header) |

---

## Immutable owner info

The `ARTEMIS.sol` contract writes `owner`, `ownerName`, `projectName`, and `deployedAt`
as `immutable` storage at construction time.  These values are burned into the bytecode
and **cannot be modified** by any transaction — providing verifiable, tamper-proof
provenance for the smart contract owner.

---

## License

Apache-2.0 — see [LICENSE](LICENSE).
Space Blockchain smart contract bot  
# ![image](https://github.com/user-attachments/assets/8c5a66cc-711a-4e1e-bd6f-b3d42320de68)
