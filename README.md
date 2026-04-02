# ARTEMIS-2.1

**A**utonomous **R**eal-**T**ime **E**thereum **M**onitor & **I**mmutable **S**ecurity

> Space Blockchain smart contract bot — 24/7 continuous security audit, auto-fix, immutable owner provenance, and blockchain monitoring for contracts deployed from kushmanmb.base.eth.

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
| 🔗 Blockchain Monitor | Real-time monitoring of contracts deployed from kushmanmb.base.eth mother contract |
| 🚨 Security Alerts | Automatic alerts for vulnerabilities in deployed child contracts |
| 🌐 Mainnet Ready | Deploy to Ethereum mainnet/testnets with built-in deployment workflow |

---

## Repository layout

```
ARTEMIS-2.1/
├── contracts/
│   └── ARTEMIS.sol            # On-chain security registry & circuit breaker
├── bot/
│   ├── auditor.py             # Main audit bot (CLI entry-point)
│   ├── security_checks.py     # Vulnerability detection patterns
│   ├── auto_fix.py            # Automated source-code patching
│   ├── blockchain_monitor.py  # Base chain monitoring for kushmanmb.base.eth
│   └── config.py              # Chain and monitoring configuration
│   ├── auditor.py           # Main audit bot (CLI entry-point)
│   ├── security_checks.py   # Vulnerability detection patterns
│   ├── auto_fix.py          # Automated source-code patching
│   └── network.py           # Ethereum network integration
├── scripts/
│   └── deploy.py            # Contract deployment script
├── deployments/
│   ├── mainnet.json         # Ethereum mainnet deployment record
│   └── sepolia.json         # Sepolia testnet deployment record
├── tests/
│   ├── test_auditor.py        # Unit & integration tests
│   └── test_blockchain_monitor.py  # Blockchain monitoring tests
├── .github/
│   ├── labels.yml           # GitHub label definitions
│   ├── labeler.yml          # Auto-labeling configuration
│   └── workflows/
│       └── audit.yml          # 24/7 CI audit workflow
│       ├── audit.yml        # 24/7 CI audit workflow
│       └── deploy.yml       # Mainnet deployment workflow
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

## Blockchain Monitoring (kushmanmb.base.eth)

Monitor and secure all contracts deployed from the mother contract of `kushmanmb.base.eth`:

```bash
# Start blockchain monitoring (Base chain by default)
python -m bot.auditor --monitor

# Monitor with custom RPC endpoint
python -m bot.auditor --monitor --rpc https://your-rpc-endpoint.com

# Monitor with known mother contract address (skip ENS resolution)
python -m bot.auditor --monitor --mother 0xYourMotherContractAddress

# Monitor on a different chain
python -m bot.auditor --monitor --chain ethereum

# Monitor with custom polling interval (in seconds)
python -m bot.auditor --monitor --interval 30
```

### Monitoring Features

| Feature | Description |
|---|---|
| 🔍 ENS/Basenames Resolution | Automatically resolves `kushmanmb.base.eth` to the mother contract address |
| 📡 Real-time Monitoring | Polls the blockchain for new contract deployments |
| 🔬 Bytecode Analysis | Analyzes deployed bytecode for dangerous patterns (SELFDESTRUCT, DELEGATECALL, etc.) |
| 📊 Source Code Audit | If source is available, runs full security checks |
| 🚨 Alert System | Generates alerts for HIGH and CRITICAL severity findings |
| ⏸ Auto-Pause | Automatically pauses monitoring when critical issues are detected |

### Supported Chains

| Chain | Chain ID | RPC Endpoint |
|---|---|---|
| Base Mainnet | 8453 | https://mainnet.base.org |
| Base Sepolia | 84532 | https://sepolia.base.org |
| Ethereum Mainnet | 1 | https://eth.llamarpc.com |

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

### Bytecode Analysis (Blockchain Monitor)

| Check | Severity | Description |
|---|---|---|
| `BYTECODE_SELFDESTRUCT` | CRITICAL | Contract contains SELFDESTRUCT opcode |
| `BYTECODE_DELEGATECALL` | HIGH | Contract uses DELEGATECALL |
| `BYTECODE_CALLCODE` | HIGH | Contract uses deprecated CALLCODE |
| `BYTECODE_CREATE2` | MEDIUM | Contract uses CREATE2 |
| `KNOWN_MALICIOUS_BYTECODE` | CRITICAL | Bytecode matches known malicious pattern |
| `SUSPICIOUS_SHORT_BYTECODE` | LOW | Unusually short bytecode (proxy/stub) |

---

## Immutable owner info

The `ARTEMIS.sol` contract writes `owner`, `ownerName`, `projectName`, and `deployedAt`
as `immutable` storage at construction time.  These values are burned into the bytecode
and **cannot be modified** by any transaction — providing verifiable, tamper-proof
provenance for the smart contract owner.

---

## Caching

ARTEMIS uses two levels of caching:

1. **CI Pip Cache** — Dependencies cached via `actions/cache` for faster CI builds
2. **RPC Response Cache** — SQLite cache at `.cache/rpc_cache.db` for Etherscan responses

Clear the RPC cache:
```python
from bot.network import RPCCache
cache = RPCCache()
deleted = cache.clear_old(max_age_seconds=0)  # Clear all
```

---

## License

Apache-2.0 — see [LICENSE](LICENSE).
Space Blockchain smart contract bot  
# ![image](https://github.com/user-attachments/assets/8c5a66cc-711a-4e1e-bd6f-b3d42320de68)
