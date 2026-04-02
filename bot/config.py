"""
ARTEMIS-2.1 — Configuration Module
-----------------------------------
Central configuration for the blockchain monitoring and security audit system.
Contains mother contract settings, chain configuration, and ENS resolution data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class ChainConfig:
    """Configuration for a blockchain network."""
    chain_id: int
    name: str
    rpc_url: str
    explorer_url: str
    ens_registry: Optional[str] = None  # ENS registry address if supported


@dataclass
class OwnerConfig:
    """Configuration for an authorized owner."""
    ens_name: str
    permissions: List[str]  # e.g. ["write"]
    resolved_address: Optional[str] = None


@dataclass
class MotherContractConfig:
    """Configuration for the mother contract to monitor."""
    ens_name: str
    chain: ChainConfig
    resolved_address: Optional[str] = None
    monitored_events: List[str] = field(default_factory=list)
    alert_threshold_severity: str = "MEDIUM"


# ---------------------------------------------------------------------------
# Chain Configurations
# ---------------------------------------------------------------------------

BASE_MAINNET = ChainConfig(
    chain_id=8453,
    name="Base Mainnet",
    rpc_url="https://mainnet.base.org",
    explorer_url="https://basescan.org",
    ens_registry=None,  # Base uses Basenames (different from ENS)
)

BASE_SEPOLIA = ChainConfig(
    chain_id=84532,
    name="Base Sepolia",
    rpc_url="https://sepolia.base.org",
    explorer_url="https://sepolia.basescan.org",
    ens_registry=None,
)

ETHEREUM_MAINNET = ChainConfig(
    chain_id=1,
    name="Ethereum Mainnet",
    rpc_url="https://eth.llamarpc.com",
    explorer_url="https://etherscan.io",
    ens_registry="0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e",
)

# Registry of all supported chains
CHAINS: Dict[str, ChainConfig] = {
    "base": BASE_MAINNET,
    "base-mainnet": BASE_MAINNET,
    "base-sepolia": BASE_SEPOLIA,
    "ethereum": ETHEREUM_MAINNET,
    "eth": ETHEREUM_MAINNET,
}


# ---------------------------------------------------------------------------
# Authorized Owners — kushmanmb.eth and yaketh.eth (both with write access)
# ---------------------------------------------------------------------------

AUTHORIZED_OWNERS: List[OwnerConfig] = [
    OwnerConfig(
        ens_name="kushmanmb.eth",
        permissions=["write"],
    ),
    OwnerConfig(
        ens_name="yaketh.eth",
        permissions=["write"],
    ),
]


def get_owner_ens_names() -> List[str]:
    """Return the ENS names of all authorized owners."""
    return [o.ens_name for o in AUTHORIZED_OWNERS]


def is_write_authorized(ens_name: str) -> bool:
    """Return True if the given ENS name has write permission."""
    return any(
        o.ens_name == ens_name and "write" in o.permissions
        for o in AUTHORIZED_OWNERS
    )


# ---------------------------------------------------------------------------
# Default Mother Contract Configuration - kushmanmb.base.eth
# ---------------------------------------------------------------------------

DEFAULT_MOTHER_CONTRACT = MotherContractConfig(
    ens_name="kushmanmb.base.eth",
    chain=BASE_MAINNET,
    monitored_events=[
        "ContractDeployed",      # When a new child contract is deployed
        "ContractCreated",       # Alternative event name
        "NewContract",           # Another common pattern
        "ChildDeployed",         # Factory pattern
    ],
    alert_threshold_severity="MEDIUM",
)


# ---------------------------------------------------------------------------
# Monitoring Configuration
# ---------------------------------------------------------------------------

@dataclass
class MonitorConfig:
    """Configuration for the blockchain monitoring service."""
    poll_interval: int = 15  # seconds between blockchain polls
    block_confirmations: int = 3  # blocks to wait before processing
    max_contracts_per_scan: int = 50  # max contracts to audit per polling cycle
    auto_pause_on_critical: bool = True  # pause monitoring on critical findings
    retry_attempts: int = 3  # number of retries for failed RPC calls
    retry_delay: int = 5  # seconds between retries
    enable_alerts: bool = True
    alert_webhook_url: Optional[str] = None  # webhook for alerts


DEFAULT_MONITOR_CONFIG = MonitorConfig()


# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

def get_chain_config(chain_name: str) -> ChainConfig:
    """Get chain configuration by name."""
    chain = CHAINS.get(chain_name.lower())
    if chain is None:
        available = ", ".join(CHAINS.keys())
        raise ValueError(f"Unknown chain '{chain_name}'. Available: {available}")
    return chain


def create_mother_contract_config(
    ens_name: str = "kushmanmb.base.eth",
    chain_name: str = "base",
    resolved_address: Optional[str] = None,
) -> MotherContractConfig:
    """Create a mother contract configuration."""
    chain = get_chain_config(chain_name)
    return MotherContractConfig(
        ens_name=ens_name,
        chain=chain,
        resolved_address=resolved_address,
        monitored_events=DEFAULT_MOTHER_CONTRACT.monitored_events.copy(),
        alert_threshold_severity=DEFAULT_MOTHER_CONTRACT.alert_threshold_severity,
    )
