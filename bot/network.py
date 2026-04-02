"""
ARTEMIS-2.1 — Ethereum Network Module
--------------------------------------
Provides integration with Ethereum mainnet and testnets via Web3.py.
Fetches verified contract source code from Etherscan for auditing.

Usage:
    from bot.network import EthereumClient
    
    client = EthereumClient(rpc_url="https://mainnet.infura.io/v3/YOUR_KEY")
    source = client.fetch_verified_source("0x...")
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Any

try:
    from web3 import Web3
    from web3.exceptions import Web3Exception
    HAS_WEB3 = True
except ImportError:
    HAS_WEB3 = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

log = logging.getLogger("artemis.network")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SUPPORTED_NETWORKS = {
    "ethereum": {
        "chain_id": 1,
        "name": "Ethereum Mainnet",
        "etherscan_api": "https://api.etherscan.io/api",
        "default_rpc": "https://eth.llamarpc.com",
    },
    "sepolia": {
        "chain_id": 11155111,
        "name": "Sepolia Testnet",
        "etherscan_api": "https://api-sepolia.etherscan.io/api",
        "default_rpc": "https://rpc.sepolia.org",
    },
    "goerli": {
        "chain_id": 5,
        "name": "Goerli Testnet",
        "etherscan_api": "https://api-goerli.etherscan.io/api",
        "default_rpc": "https://rpc.ankr.com/eth_goerli",
    },
}


# ---------------------------------------------------------------------------
# Cache for RPC responses
# ---------------------------------------------------------------------------

class RPCCache:
    """
    SQLite-backed cache for RPC responses to avoid redundant network calls.
    Keyed by (network, contract_address, block_number).
    """
    
    def __init__(self, cache_dir: Path | str = ".cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.cache_dir / "rpc_cache.db"
        self._init_db()
    
    def _init_db(self) -> None:
        """Initialize the SQLite cache database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS rpc_cache (
                    cache_key TEXT PRIMARY KEY,
                    data TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_created_at ON rpc_cache(created_at)
            """)
            conn.commit()
    
    def get(self, key: str) -> Optional[Dict]:
        """Retrieve cached data by key."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT data FROM rpc_cache WHERE cache_key = ?", (key,)
            )
            row = cursor.fetchone()
            if row:
                return json.loads(row[0])
        return None
    
    def set(self, key: str, data: Dict) -> None:
        """Store data in cache."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO rpc_cache (cache_key, data, created_at)
                VALUES (?, ?, ?)
                """,
                (key, json.dumps(data), int(time.time()))
            )
            conn.commit()
    
    def clear_old(self, max_age_seconds: int = 86400) -> int:
        """Remove cache entries older than max_age_seconds. Returns count deleted."""
        cutoff = int(time.time()) - max_age_seconds
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "DELETE FROM rpc_cache WHERE created_at < ?", (cutoff,)
            )
            conn.commit()
            return cursor.rowcount


# ---------------------------------------------------------------------------
# Contract Data
# ---------------------------------------------------------------------------

@dataclass
class ContractInfo:
    """Information about a deployed contract."""
    address: str
    network: str
    name: Optional[str] = None
    source_code: Optional[str] = None
    abi: Optional[List[Dict]] = None
    compiler_version: Optional[str] = None
    is_verified: bool = False
    bytecode: Optional[str] = None


# ---------------------------------------------------------------------------
# Ethereum Client
# ---------------------------------------------------------------------------

class EthereumClient:
    """
    Client for interacting with Ethereum networks.
    Supports fetching contract bytecode, verified source from Etherscan,
    and basic contract interactions.
    """
    
    def __init__(
        self,
        network: str = "ethereum",
        rpc_url: Optional[str] = None,
        etherscan_api_key: Optional[str] = None,
        cache: Optional[RPCCache] = None,
    ):
        if not HAS_WEB3:
            raise ImportError(
                "web3 package is required. Install with: pip install web3"
            )
        
        if network not in SUPPORTED_NETWORKS:
            raise ValueError(
                f"Unsupported network: {network}. "
                f"Supported: {list(SUPPORTED_NETWORKS.keys())}"
            )
        
        self.network = network
        self.network_config = SUPPORTED_NETWORKS[network]
        
        # Use provided RPC URL, env var, or default
        self.rpc_url = (
            rpc_url
            or os.environ.get("WEB3_RPC_URL")
            or self.network_config["default_rpc"]
        )
        
        self.etherscan_api_key = (
            etherscan_api_key
            or os.environ.get("ETHERSCAN_API_KEY")
            or ""
        )
        
        self.cache = cache or RPCCache()
        
        # Initialize Web3
        self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
        
        if not self.w3.is_connected():
            log.warning("Could not connect to RPC endpoint: %s", self.rpc_url)
    
    def is_connected(self) -> bool:
        """Check if connected to the network."""
        return self.w3.is_connected()
    
    def get_chain_id(self) -> int:
        """Get the chain ID of the connected network."""
        return self.w3.eth.chain_id
    
    def get_block_number(self) -> int:
        """Get the current block number."""
        return self.w3.eth.block_number
    
    def get_contract_bytecode(self, address: str) -> Optional[str]:
        """
        Fetch the deployed bytecode of a contract.
        
        Args:
            address: Contract address (checksummed or not)
        
        Returns:
            Hex string of bytecode, or None if not a contract
        """
        cache_key = f"{self.network}:bytecode:{address.lower()}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached.get("bytecode")
        
        try:
            checksum_addr = Web3.to_checksum_address(address)
            code = self.w3.eth.get_code(checksum_addr)
            bytecode = code.hex() if code else None
            
            if bytecode and bytecode != "0x":
                self.cache.set(cache_key, {"bytecode": bytecode})
                return bytecode
            return None
            
        except Web3Exception as e:
            log.error("Failed to fetch bytecode for %s: %s", address, e)
            return None
    
    def fetch_verified_source(self, address: str) -> Optional[ContractInfo]:
        """
        Fetch verified source code from Etherscan.
        
        Args:
            address: Contract address
        
        Returns:
            ContractInfo with source code if verified, None otherwise
        """
        if not HAS_REQUESTS:
            log.error("requests package required for Etherscan API")
            return None
        
        cache_key = f"{self.network}:source:{address.lower()}"
        cached = self.cache.get(cache_key)
        if cached:
            return ContractInfo(**cached)
        
        api_url = self.network_config["etherscan_api"]
        params = {
            "module": "contract",
            "action": "getsourcecode",
            "address": address,
            "apikey": self.etherscan_api_key,
        }
        
        try:
            response = requests.get(api_url, params=params, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            if data.get("status") != "1" or not data.get("result"):
                log.warning("No verified source found for %s", address)
                return None
            
            result = data["result"][0]
            
            # Check if contract is verified
            source_code = result.get("SourceCode", "")
            if not source_code:
                return None
            
            # Parse ABI
            abi = None
            abi_str = result.get("ABI", "")
            if abi_str and abi_str != "Contract source code not verified":
                try:
                    abi = json.loads(abi_str)
                except json.JSONDecodeError:
                    pass
            
            info = ContractInfo(
                address=address,
                network=self.network,
                name=result.get("ContractName"),
                source_code=source_code,
                abi=abi,
                compiler_version=result.get("CompilerVersion"),
                is_verified=True,
            )
            
            # Cache the result
            self.cache.set(cache_key, {
                "address": info.address,
                "network": info.network,
                "name": info.name,
                "source_code": info.source_code,
                "abi": info.abi,
                "compiler_version": info.compiler_version,
                "is_verified": info.is_verified,
            })
            
            return info
            
        except requests.RequestException as e:
            log.error("Etherscan API request failed: %s", e)
            return None
    
    def fetch_contract_for_audit(self, address: str) -> Optional[str]:
        """
        Fetch contract source code for auditing.
        
        First tries to get verified source from Etherscan.
        Falls back to returning bytecode info if not verified.
        
        Args:
            address: Contract address
        
        Returns:
            Solidity source code string, or None if unavailable
        """
        # Try verified source first
        info = self.fetch_verified_source(address)
        if info and info.source_code:
            log.info(
                "Fetched verified source for %s (%s) from %s",
                info.name or "Unknown",
                address[:10] + "...",
                self.network
            )
            return info.source_code
        
        # If not verified, we can only get bytecode
        bytecode = self.get_contract_bytecode(address)
        if bytecode:
            log.warning(
                "Contract %s is not verified. Only bytecode available. "
                "Source code audit not possible.",
                address
            )
            return None
        
        log.error("No contract found at address %s", address)
        return None


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def get_client(
    network: str = "ethereum",
    rpc_url: Optional[str] = None,
) -> EthereumClient:
    """
    Factory function to create an Ethereum client.
    
    Args:
        network: Network name (ethereum, sepolia, goerli)
        rpc_url: Optional custom RPC URL
    
    Returns:
        Configured EthereumClient instance
    """
    return EthereumClient(network=network, rpc_url=rpc_url)


def validate_address(address: str) -> bool:
    """Check if a string is a valid Ethereum address."""
    if not HAS_WEB3:
        # Basic check without web3
        return (
            isinstance(address, str)
            and address.startswith("0x")
            and len(address) == 42
            and all(c in "0123456789abcdefABCDEF" for c in address[2:])
        )
    return Web3.is_address(address)


def checksum_address(address: str) -> str:
    """Convert address to checksummed format."""
    if not HAS_WEB3:
        raise ImportError("web3 package required for checksum")
    return Web3.to_checksum_address(address)
