#!/usr/bin/env python3
"""
ARTEMIS-2.1 — Mainnet Deployment Script
-----------------------------------------
Deploys the ARTEMIS.sol smart contract to Ethereum mainnet or testnets.

Requirements:
    - DEPLOYER_PRIVATE_KEY: Private key of the deployer wallet
    - WEB3_RPC_URL: Ethereum RPC endpoint (Infura/Alchemy)
    - ETHERSCAN_API_KEY: (Optional) For contract verification

Usage:
    # Deploy to mainnet (requires confirmation)
    python scripts/deploy.py --network ethereum --owner-name "Kushmanmb" --project-name "ARTEMIS-2.1"
    
    # Deploy to testnet
    python scripts/deploy.py --network sepolia --owner-name "Test" --project-name "ARTEMIS-Test"
    
    # Verify existing deployment
    python scripts/deploy.py --network ethereum --verify --address 0x...

Environment Variables:
    DEPLOYER_PRIVATE_KEY  - Private key (hex, with or without 0x prefix)
    WEB3_RPC_URL          - RPC endpoint URL
    ETHERSCAN_API_KEY     - Etherscan API key for verification
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Attempt imports with graceful fallback
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

try:
    from web3 import Web3
    from eth_account import Account
    HAS_WEB3 = True
except ImportError:
    HAS_WEB3 = False

try:
    import solcx
    HAS_SOLCX = True
except ImportError:
    HAS_SOLCX = False

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [DEPLOY] %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("artemis.deploy")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).parent.parent
CONTRACT_PATH = PROJECT_ROOT / "contracts" / "ARTEMIS.sol"
DEPLOYMENTS_DIR = PROJECT_ROOT / "deployments"

NETWORKS = {
    "ethereum": {
        "chain_id": 1,
        "name": "Ethereum Mainnet",
        "explorer": "https://etherscan.io",
        "is_mainnet": True,
    },
    "sepolia": {
        "chain_id": 11155111,
        "name": "Sepolia Testnet",
        "explorer": "https://sepolia.etherscan.io",
        "is_mainnet": False,
    },
    "goerli": {
        "chain_id": 5,
        "name": "Goerli Testnet",
        "explorer": "https://goerli.etherscan.io",
        "is_mainnet": False,
    },
}

# Solidity compiler version matching pragma in ARTEMIS.sol
SOLC_VERSION = "0.8.20"


# ---------------------------------------------------------------------------
# Compiler
# ---------------------------------------------------------------------------

def install_solc() -> None:
    """Install the required Solidity compiler version."""
    if not HAS_SOLCX:
        raise ImportError("py-solc-x required. Install with: pip install py-solc-x")
    
    if SOLC_VERSION not in [str(v) for v in solcx.get_installed_solc_versions()]:
        log.info("Installing solc %s...", SOLC_VERSION)
        solcx.install_solc(SOLC_VERSION)
    solcx.set_solc_version(SOLC_VERSION)


def compile_contract() -> dict:
    """
    Compile ARTEMIS.sol and return the compiled contract data.
    
    Returns:
        Dict with 'abi' and 'bytecode' keys
    """
    if not HAS_SOLCX:
        raise ImportError("py-solc-x required for compilation")
    
    install_solc()
    
    source = CONTRACT_PATH.read_text(encoding="utf-8")
    
    compiled = solcx.compile_source(
        source,
        output_values=["abi", "bin"],
        solc_version=SOLC_VERSION,
    )
    
    # Get the main contract (key format: "<source>:ContractName")
    contract_key = None
    for key in compiled.keys():
        if ":ARTEMIS" in key:
            contract_key = key
            break
    
    if not contract_key:
        raise ValueError("ARTEMIS contract not found in compiled output")
    
    return {
        "abi": compiled[contract_key]["abi"],
        "bytecode": compiled[contract_key]["bin"],
    }


# ---------------------------------------------------------------------------
# Deployment
# ---------------------------------------------------------------------------

def deploy_contract(
    w3: Web3,
    account: Account,
    abi: list,
    bytecode: str,
    owner_name: str,
    project_name: str,
    gas_price_gwei: float | None = None,
) -> dict:
    """
    Deploy the ARTEMIS contract.
    
    Args:
        w3: Web3 instance
        account: Deployer account
        abi: Contract ABI
        bytecode: Contract bytecode
        owner_name: Owner name for constructor
        project_name: Project name for constructor
        gas_price_gwei: Optional gas price in Gwei
    
    Returns:
        Dict with deployment info
    """
    contract = w3.eth.contract(abi=abi, bytecode=bytecode)
    
    # Build constructor transaction
    constructor_txn = contract.constructor(owner_name, project_name)
    
    # Estimate gas
    gas_estimate = constructor_txn.estimate_gas({"from": account.address})
    gas_limit = int(gas_estimate * 1.2)  # 20% buffer
    
    # Get gas price
    if gas_price_gwei:
        gas_price = w3.to_wei(gas_price_gwei, "gwei")
    else:
        gas_price = w3.eth.gas_price
    
    # Get nonce
    nonce = w3.eth.get_transaction_count(account.address)
    
    # Build transaction
    txn = constructor_txn.build_transaction({
        "from": account.address,
        "gas": gas_limit,
        "gasPrice": gas_price,
        "nonce": nonce,
        "chainId": w3.eth.chain_id,
    })
    
    # Sign and send
    signed_txn = account.sign_transaction(txn)
    tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)
    
    log.info("Transaction sent: %s", tx_hash.hex())
    log.info("Waiting for confirmation...")
    
    # Wait for receipt
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
    
    if receipt.status != 1:
        raise RuntimeError(f"Deployment failed. Receipt: {receipt}")
    
    contract_address = receipt.contractAddress
    
    return {
        "address": contract_address,
        "tx_hash": tx_hash.hex(),
        "block_number": receipt.blockNumber,
        "gas_used": receipt.gasUsed,
        "deployer": account.address,
    }


def save_deployment(
    network: str,
    deployment_info: dict,
    owner_name: str,
    project_name: str,
    abi: list,
) -> Path:
    """
    Save deployment information to a JSON file.
    
    Returns:
        Path to the saved file
    """
    DEPLOYMENTS_DIR.mkdir(parents=True, exist_ok=True)
    
    output = {
        "network": network,
        "chain_id": NETWORKS[network]["chain_id"],
        "contract_address": deployment_info["address"],
        "tx_hash": deployment_info["tx_hash"],
        "block_number": deployment_info["block_number"],
        "gas_used": deployment_info["gas_used"],
        "deployer": deployment_info["deployer"],
        "constructor_args": {
            "ownerName": owner_name,
            "projectName": project_name,
        },
        "deployed_at": datetime.now(timezone.utc).isoformat(),
        "solc_version": SOLC_VERSION,
        "abi": abi,
    }
    
    output_path = DEPLOYMENTS_DIR / f"{network}.json"
    output_path.write_text(json.dumps(output, indent=2), encoding="utf-8")
    
    log.info("Deployment saved to %s", output_path)
    return output_path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Deploy ARTEMIS.sol to Ethereum networks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--network",
        choices=list(NETWORKS.keys()),
        default="sepolia",
        help="Target network (default: sepolia)",
    )
    parser.add_argument(
        "--owner-name",
        default="Kushmanmb",
        help="Owner name for contract constructor",
    )
    parser.add_argument(
        "--project-name",
        default="ARTEMIS-2.1",
        help="Project name for contract constructor",
    )
    parser.add_argument(
        "--gas-price",
        type=float,
        default=None,
        help="Gas price in Gwei (default: auto from network)",
    )
    parser.add_argument(
        "--rpc-url",
        default=None,
        help="RPC URL (default: from WEB3_RPC_URL env var)",
    )
    parser.add_argument(
        "--private-key",
        default=None,
        help="Deployer private key (default: from DEPLOYER_PRIVATE_KEY env var)",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify contract on Etherscan after deployment",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Compile and estimate gas without deploying",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    
    # Check dependencies
    if not HAS_WEB3:
        log.error("web3 package required. Install with: pip install web3 eth-account")
        return 1
    
    if not HAS_SOLCX:
        log.error("py-solc-x required. Install with: pip install py-solc-x")
        return 1
    
    # Get credentials
    rpc_url = args.rpc_url or os.environ.get("WEB3_RPC_URL")
    private_key = args.private_key or os.environ.get("DEPLOYER_PRIVATE_KEY")
    
    if not rpc_url:
        log.error("RPC URL required. Set WEB3_RPC_URL or use --rpc-url")
        return 1
    
    if not private_key and not args.dry_run:
        log.error("Private key required. Set DEPLOYER_PRIVATE_KEY or use --private-key")
        return 1
    
    # Network info
    network_info = NETWORKS[args.network]
    log.info("Target network: %s (%s)", network_info["name"], args.network)
    
    # Mainnet warning
    if network_info["is_mainnet"] and not args.dry_run:
        log.warning("⚠️  MAINNET DEPLOYMENT — Real funds will be spent!")
        confirm = input("Type 'DEPLOY' to confirm mainnet deployment: ")
        if confirm != "DEPLOY":
            log.info("Deployment cancelled.")
            return 0
    
    # Connect to network
    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        log.error("Failed to connect to %s", rpc_url)
        return 1
    
    chain_id = w3.eth.chain_id
    if chain_id != network_info["chain_id"]:
        log.error(
            "Chain ID mismatch: expected %d (%s), got %d",
            network_info["chain_id"],
            args.network,
            chain_id,
        )
        return 1
    
    log.info("Connected to chain ID %d, block %d", chain_id, w3.eth.block_number)
    
    # Compile contract
    log.info("Compiling ARTEMIS.sol...")
    try:
        compiled = compile_contract()
    except Exception as e:
        log.error("Compilation failed: %s", e)
        return 1
    
    log.info("Compilation successful. Bytecode size: %d bytes", len(compiled["bytecode"]) // 2)
    
    if args.dry_run:
        log.info("Dry run complete. No deployment made.")
        return 0
    
    # Load account with validation
    if private_key.startswith("0x"):
        private_key = private_key[2:]
    
    # Validate private key format (should be 64 hex characters)
    if len(private_key) != 64 or not all(c in "0123456789abcdefABCDEF" for c in private_key):
        log.error("Invalid private key format. Expected 64 hex characters (with or without 0x prefix)")
        return 1
    
    try:
        account = Account.from_key(private_key)
    except Exception as e:
        log.error("Failed to load account from private key: %s", e)
        return 1
    
    balance = w3.eth.get_balance(account.address)
    log.info("Deployer: %s (balance: %s ETH)", 
             account.address, 
             w3.from_wei(balance, "ether"))
    
    if balance == 0:
        log.error("Deployer account has no ETH for gas")
        return 1
    
    # Deploy
    log.info("Deploying ARTEMIS contract...")
    log.info("  Owner Name: %s", args.owner_name)
    log.info("  Project Name: %s", args.project_name)
    
    try:
        deployment = deploy_contract(
            w3=w3,
            account=account,
            abi=compiled["abi"],
            bytecode=compiled["bytecode"],
            owner_name=args.owner_name,
            project_name=args.project_name,
            gas_price_gwei=args.gas_price,
        )
    except Exception as e:
        log.error("Deployment failed: %s", e)
        return 1
    
    log.info("✅ Contract deployed successfully!")
    log.info("  Address: %s", deployment["address"])
    log.info("  TX Hash: %s", deployment["tx_hash"])
    log.info("  Block: %d", deployment["block_number"])
    log.info("  Gas Used: %d", deployment["gas_used"])
    log.info("  Explorer: %s/address/%s", 
             network_info["explorer"], 
             deployment["address"])
    
    # Save deployment info
    save_deployment(
        network=args.network,
        deployment_info=deployment,
        owner_name=args.owner_name,
        project_name=args.project_name,
        abi=compiled["abi"],
    )
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
