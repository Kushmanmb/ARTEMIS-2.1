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
| 🌐 Mainnet Ready | Deploy to Ethereum mainnet/testnets with built-in deployment workflow |

---

## Repository layout

```
ARTEMIS-2.1/
├── contracts/
│   └── ARTEMIS.sol          # On-chain security registry & circuit breaker
├── bot/
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
│   └── test_auditor.py      # Unit & integration tests
├── .github/
│   ├── labels.yml           # GitHub label definitions
│   ├── labeler.yml          # Auto-labeling configuration
│   └── workflows/
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

## Network Integration

ARTEMIS-2.1 supports fetching and auditing contracts directly from Ethereum networks.

### Supported Networks

| Network | Chain ID | Status |
|---------|----------|--------|
| Ethereum Mainnet | 1 | ✅ Supported |
| Sepolia Testnet | 11155111 | ✅ Supported |
| Goerli Testnet | 5 | ✅ Supported |

### Fetching Verified Contracts

```python
from bot.network import EthereumClient

# Initialize client (uses WEB3_RPC_URL env var or default public RPC)
client = EthereumClient(network="ethereum")

# Fetch verified source from Etherscan
source = client.fetch_contract_for_audit("0x...")
if source:
    from bot.auditor import audit_source
    findings = audit_source(source, "remote_contract.sol")
```

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `WEB3_RPC_URL` | Ethereum RPC endpoint (Infura/Alchemy) | For network features |
| `ETHERSCAN_API_KEY` | Etherscan API key for fetching verified source | Optional (rate limited without) |
| `DEPLOYER_PRIVATE_KEY` | Private key for contract deployment | For deployment only |

---

## Deployment

### Deploy to Testnet (Sepolia)

```bash
# Set environment variables
export WEB3_RPC_URL="https://sepolia.infura.io/v3/YOUR_KEY"
export DEPLOYER_PRIVATE_KEY="your_private_key_hex"

# Dry run (compile only)
python scripts/deploy.py --network sepolia --dry-run

# Deploy
python scripts/deploy.py --network sepolia \
    --owner-name "YourName" \
    --project-name "ARTEMIS-2.1"
```

### Deploy to Mainnet

```bash
# ⚠️ MAINNET - Real funds required!
export WEB3_RPC_URL="https://mainnet.infura.io/v3/YOUR_KEY"
export DEPLOYER_PRIVATE_KEY="your_private_key_hex"

python scripts/deploy.py --network ethereum \
    --owner-name "Kushmanmb" \
    --project-name "ARTEMIS-2.1"
```

### GitHub Actions Deployment

Use the **Deploy to Network** workflow (`workflow_dispatch`) to deploy from CI:

1. Go to **Actions** → **ARTEMIS-2.1 Deploy to Network**
2. Click **Run workflow**
3. Select network, enter constructor arguments
4. Enable **dry_run** for testing, disable for actual deployment

Required repository secrets:
- `WEB3_RPC_URL` — RPC endpoint
- `DEPLOYER_PRIVATE_KEY` — Deployer wallet private key
- `ETHERSCAN_API_KEY` — (Optional) For contract verification

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
