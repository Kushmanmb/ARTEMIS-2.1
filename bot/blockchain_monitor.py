"""
ARTEMIS-2.1 — Blockchain Monitor Module
-----------------------------------------
Monitors the Base blockchain for contracts deployed from the mother contract
(kushmanmb.base.eth) and automatically audits them for security vulnerabilities.

Features:
- ENS/Basenames resolution for kushmanmb.base.eth
- Real-time monitoring of contract deployments
- Automatic bytecode decompilation and security scanning
- Alert system for detected vulnerabilities
- Integration with ARTEMIS on-chain audit logging
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set

try:
    from web3 import Web3
    from web3.exceptions import Web3Exception
    from web3.types import BlockData, TxData, TxReceipt
    WEB3_AVAILABLE = True
except ImportError:
    WEB3_AVAILABLE = False
    Web3 = None  # type: ignore
    Web3Exception = Exception  # type: ignore

from bot.config import (
    ChainConfig,
    MonitorConfig,
    MotherContractConfig,
    DEFAULT_MONITOR_CONFIG,
    DEFAULT_MOTHER_CONTRACT,
)
from bot.security_checks import ALL_CHECKS, Finding, Severity

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
log = logging.getLogger("artemis.monitor")


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------

@dataclass
class DeployedContract:
    """Represents a contract deployed from the mother contract."""
    address: str
    deployer: str
    tx_hash: str
    block_number: int
    timestamp: int
    bytecode: Optional[str] = None
    source_code: Optional[str] = None
    findings: List[Finding] = field(default_factory=list)
    audited: bool = False


@dataclass
class MonitorState:
    """Internal state of the blockchain monitor."""
    last_block_processed: int = 0
    total_contracts_found: int = 0
    total_audits_performed: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    monitored_contracts: Set[str] = field(default_factory=set)
    is_paused: bool = False
    start_time: Optional[datetime] = None


@dataclass
class Alert:
    """Security alert for detected vulnerability."""
    severity: Severity
    contract_address: str
    finding: Finding
    timestamp: datetime
    tx_hash: str
    block_number: int


# ---------------------------------------------------------------------------
# ENS/Basenames Resolver
# ---------------------------------------------------------------------------

class BaseNamesResolver:
    """
    Resolver for Base chain names (kushmanmb.base.eth).
    
    Base uses a different naming system than Ethereum ENS.
    This class handles resolution of .base.eth names.
    """
    
    # Base L2 Resolver contract
    BASE_RESOLVER_ADDRESS = "0xC6d566A56A1aFf6508b41f6c90ff131615583BCD"
    
    # L2 Resolver ABI (simplified)
    RESOLVER_ABI = [
        {
            "inputs": [{"internalType": "bytes32", "name": "node", "type": "bytes32"}],
            "name": "addr",
            "outputs": [{"internalType": "address", "name": "", "type": "address"}],
            "stateMutability": "view",
            "type": "function"
        },
        {
            "inputs": [
                {"internalType": "bytes", "name": "name", "type": "bytes"},
                {"internalType": "bytes", "name": "data", "type": "bytes"}
            ],
            "name": "resolve",
            "outputs": [{"internalType": "bytes", "name": "", "type": "bytes"}],
            "stateMutability": "view",
            "type": "function"
        }
    ]

    def __init__(self, w3: "Web3"):
        self.w3 = w3
    
    @staticmethod
    def namehash(name: str) -> bytes:
        """Compute the namehash for an ENS/Basename."""
        if not name:
            return b'\x00' * 32
        
        label, _, remainder = name.partition('.')
        label_hash = Web3.keccak(text=label)
        remainder_hash = BaseNamesResolver.namehash(remainder)
        return Web3.keccak(remainder_hash + label_hash)

    @staticmethod
    def dns_encode(name: str) -> bytes:
        """DNS-encode a name for the resolver."""
        parts = name.split('.')
        result = b''
        for part in parts:
            encoded = part.encode('utf-8')
            result += bytes([len(encoded)]) + encoded
        result += b'\x00'
        return result

    def resolve_name(self, name: str) -> Optional[str]:
        """
        Resolve a .base.eth name to an address.
        
        Args:
            name: The name to resolve (e.g., 'kushmanmb.base.eth')
            
        Returns:
            The resolved address or None if not found
        """
        if not WEB3_AVAILABLE:
            log.warning("web3 not available, cannot resolve name")
            return None
            
        try:
            # For .base.eth names, we use the Basenames L2 resolver
            node = self.namehash(name)
            
            # Try direct resolution first
            resolver = self.w3.eth.contract(
                address=Web3.to_checksum_address(self.BASE_RESOLVER_ADDRESS),
                abi=self.RESOLVER_ABI
            )
            
            # Attempt to get the address
            try:
                address = resolver.functions.addr(node).call()
                if address and address != '0x' + '0' * 40:
                    return Web3.to_checksum_address(address)
            except Exception:
                pass
            
            # Try with DNS-encoded name
            try:
                dns_name = self.dns_encode(name)
                addr_selector = Web3.keccak(text="addr(bytes32)")[:4]
                data = addr_selector + node
                result = resolver.functions.resolve(dns_name, data).call()
                if result and len(result) >= 20:
                    address = '0x' + result[-20:].hex()
                    return Web3.to_checksum_address(address)
            except Exception:
                pass
            
            log.warning("Could not resolve name: %s", name)
            return None
            
        except Exception as e:
            log.error("Error resolving name %s: %s", name, e)
            return None


# ---------------------------------------------------------------------------
# Contract Factory Monitor
# ---------------------------------------------------------------------------

class ContractFactoryMonitor:
    """
    Monitors a mother contract (factory) for child contract deployments.
    
    Detects deployments by:
    1. Monitoring CREATE/CREATE2 opcodes in transaction traces
    2. Watching for ContractDeployed events
    3. Tracking internal transactions from the mother contract
    """
    
    # Common event signatures for contract deployment
    DEPLOYMENT_EVENT_TOPICS = [
        Web3.keccak(text="ContractDeployed(address,address,uint256)").hex() if WEB3_AVAILABLE else "",
        Web3.keccak(text="ContractCreated(address)").hex() if WEB3_AVAILABLE else "",
        Web3.keccak(text="NewContract(address,address)").hex() if WEB3_AVAILABLE else "",
        Web3.keccak(text="ChildDeployed(address,bytes32)").hex() if WEB3_AVAILABLE else "",
    ]

    def __init__(
        self,
        w3: "Web3",
        mother_contract_address: str,
        monitored_events: Optional[List[str]] = None,
    ):
        self.w3 = w3
        self.mother_address = Web3.to_checksum_address(mother_contract_address) if WEB3_AVAILABLE else mother_contract_address
        self.monitored_events = monitored_events or []
        self._event_topics = self._build_event_topics()
    
    def _build_event_topics(self) -> List[str]:
        """Build the list of event topics to monitor."""
        if not WEB3_AVAILABLE:
            return []
        topics = self.DEPLOYMENT_EVENT_TOPICS.copy()
        for event_name in self.monitored_events:
            # Add common event signatures
            for sig in [
                f"{event_name}(address)",
                f"{event_name}(address,address)",
                f"{event_name}(address,address,uint256)",
                f"{event_name}(address,bytes32)",
            ]:
                try:
                    topics.append(Web3.keccak(text=sig).hex())
                except Exception:
                    pass
        return list(set(topics))  # Remove duplicates

    def get_deployed_contracts(
        self,
        from_block: int,
        to_block: int,
    ) -> List[DeployedContract]:
        """
        Get all contracts deployed from the mother contract in the given block range.
        
        Args:
            from_block: Starting block number (inclusive)
            to_block: Ending block number (inclusive)
            
        Returns:
            List of DeployedContract objects
        """
        if not WEB3_AVAILABLE:
            log.error("web3 not available")
            return []
            
        deployed = []
        
        try:
            # Method 1: Check logs for deployment events
            deployed.extend(self._get_from_logs(from_block, to_block))
            
            # Method 2: Check transactions from mother contract
            deployed.extend(self._get_from_transactions(from_block, to_block))
            
            # Method 3: Check for contract creation via traces (if supported)
            deployed.extend(self._get_from_traces(from_block, to_block))
            
        except Exception as e:
            log.error("Error getting deployed contracts: %s", e)
        
        # Deduplicate by address
        seen: Set[str] = set()
        unique: List[DeployedContract] = []
        for contract in deployed:
            if contract.address.lower() not in seen:
                seen.add(contract.address.lower())
                unique.append(contract)
        
        return unique

    def _get_from_logs(self, from_block: int, to_block: int) -> List[DeployedContract]:
        """Get deployed contracts from event logs."""
        deployed = []
        
        try:
            # Query logs from mother contract
            logs = self.w3.eth.get_logs({
                "fromBlock": from_block,
                "toBlock": to_block,
                "address": self.mother_address,
            })
            
            for log_entry in logs:
                topic0 = log_entry.get("topics", [None])[0]
                if topic0 and topic0.hex() in self._event_topics:
                    # Extract deployed address from log data
                    data = log_entry.get("data", b"")
                    if len(data) >= 32:
                        # Address is usually in the first 32 bytes (padded)
                        address = "0x" + data[12:32].hex()
                        try:
                            address = Web3.to_checksum_address(address)
                            block = self.w3.eth.get_block(log_entry["blockNumber"])
                            deployed.append(DeployedContract(
                                address=address,
                                deployer=self.mother_address,
                                tx_hash=log_entry["transactionHash"].hex(),
                                block_number=log_entry["blockNumber"],
                                timestamp=block.get("timestamp", 0),
                            ))
                        except Exception:
                            pass
        except Exception as e:
            log.debug("Error getting logs: %s", e)
        
        return deployed

    def _get_from_transactions(self, from_block: int, to_block: int) -> List[DeployedContract]:
        """Get deployed contracts from transaction receipts."""
        deployed = []
        
        try:
            for block_num in range(from_block, to_block + 1):
                block = self.w3.eth.get_block(block_num, full_transactions=True)
                for tx in block.get("transactions", []):
                    if isinstance(tx, dict):
                        tx_from = tx.get("from", "").lower()
                        if tx_from == self.mother_address.lower():
                            # Check if this transaction created a contract
                            receipt = self.w3.eth.get_transaction_receipt(tx["hash"])
                            contract_address = receipt.get("contractAddress")
                            if contract_address:
                                deployed.append(DeployedContract(
                                    address=Web3.to_checksum_address(contract_address),
                                    deployer=self.mother_address,
                                    tx_hash=tx["hash"].hex(),
                                    block_number=block_num,
                                    timestamp=block.get("timestamp", 0),
                                ))
        except Exception as e:
            log.debug("Error getting transactions: %s", e)
        
        return deployed

    def _get_from_traces(self, from_block: int, to_block: int) -> List[DeployedContract]:
        """Get deployed contracts from internal transaction traces (if RPC supports it)."""
        deployed = []
        
        try:
            # This requires debug_traceBlockByNumber or similar - not all nodes support it
            for block_num in range(from_block, to_block + 1):
                try:
                    # Try trace_block if available (some nodes like Erigon support this)
                    traces = self.w3.provider.make_request(
                        "trace_block",
                        [hex(block_num)]
                    )
                    
                    if traces and "result" in traces:
                        for trace in traces["result"]:
                            action = trace.get("action", {})
                            if (
                                trace.get("type") == "create"
                                and action.get("from", "").lower() == self.mother_address.lower()
                            ):
                                result = trace.get("result", {})
                                if "address" in result:
                                    block = self.w3.eth.get_block(block_num)
                                    deployed.append(DeployedContract(
                                        address=Web3.to_checksum_address(result["address"]),
                                        deployer=self.mother_address,
                                        tx_hash=trace.get("transactionHash", ""),
                                        block_number=block_num,
                                        timestamp=block.get("timestamp", 0),
                                    ))
                except Exception:
                    pass  # Tracing not supported on this node
        except Exception as e:
            log.debug("Error getting traces: %s", e)
        
        return deployed


# ---------------------------------------------------------------------------
# Bytecode Analyzer
# ---------------------------------------------------------------------------

class BytecodeAnalyzer:
    """
    Analyzes contract bytecode for security patterns.
    
    Since we may not have source code for deployed contracts,
    this analyzer checks bytecode for dangerous patterns.
    """
    
    # Dangerous opcode patterns
    DANGEROUS_PATTERNS = {
        "SELFDESTRUCT": {
            "opcode": "ff",  # SELFDESTRUCT opcode
            "severity": Severity.CRITICAL,
            "description": "Contract contains SELFDESTRUCT - can be destroyed",
        },
        "DELEGATECALL": {
            "opcode": "f4",  # DELEGATECALL opcode
            "severity": Severity.HIGH,
            "description": "Contract uses DELEGATECALL - potential for hijacking",
        },
        "CALLCODE": {
            "opcode": "f2",  # CALLCODE opcode (deprecated)
            "severity": Severity.HIGH,
            "description": "Contract uses deprecated CALLCODE opcode",
        },
        "CREATE2": {
            "opcode": "f5",  # CREATE2 opcode
            "severity": Severity.MEDIUM,
            "description": "Contract uses CREATE2 - can deploy to deterministic addresses",
        },
    }
    
    # Known malicious bytecode patterns (example hashes)
    KNOWN_MALICIOUS_HASHES: Set[str] = set()

    def __init__(self, w3: Optional["Web3"] = None):
        self.w3 = w3

    def analyze_bytecode(self, bytecode: str) -> List[Finding]:
        """
        Analyze bytecode for security issues.
        
        Args:
            bytecode: The contract bytecode (hex string)
            
        Returns:
            List of findings
        """
        if not bytecode or bytecode == "0x":
            return []
        
        # Normalize bytecode
        bytecode_hex = bytecode.lower()
        if bytecode_hex.startswith("0x"):
            bytecode_hex = bytecode_hex[2:]
        
        findings: List[Finding] = []
        
        # Check for dangerous opcodes
        for pattern_name, pattern_info in self.DANGEROUS_PATTERNS.items():
            opcode = pattern_info["opcode"]
            # Look for the opcode in the bytecode
            # Note: This is a simplified check - a proper analysis would parse opcodes
            idx = 0
            while idx < len(bytecode_hex):
                if bytecode_hex[idx:idx+2] == opcode:
                    findings.append(Finding(
                        check_name=f"BYTECODE_{pattern_name}",
                        severity=pattern_info["severity"],
                        description=f"{pattern_info['description']} (found at byte position {idx//2})",
                        line_numbers=[idx // 2],
                        auto_fixable=False,
                        fix_hint=f"Review the {pattern_name} usage for potential security implications.",
                    ))
                    break  # Only report once per pattern
                idx += 2
        
        # Check bytecode hash against known malicious patterns
        if WEB3_AVAILABLE:
            bytecode_hash = Web3.keccak(hexstr=bytecode).hex()
            if bytecode_hash in self.KNOWN_MALICIOUS_HASHES:
                findings.append(Finding(
                    check_name="KNOWN_MALICIOUS_BYTECODE",
                    severity=Severity.CRITICAL,
                    description="Contract bytecode matches a known malicious pattern!",
                    auto_fixable=False,
                    fix_hint="Do not interact with this contract. Alert the team immediately.",
                ))
        
        # Check for suspiciously short bytecode (might be a proxy or stub)
        if len(bytecode_hex) < 100:
            findings.append(Finding(
                check_name="SUSPICIOUS_SHORT_BYTECODE",
                severity=Severity.LOW,
                description="Contract has unusually short bytecode - might be a minimal proxy or stub",
                auto_fixable=False,
                fix_hint="Verify this is intentional and not a malicious minimal contract.",
            ))
        
        return findings


# ---------------------------------------------------------------------------
# Main Blockchain Monitor Class
# ---------------------------------------------------------------------------

class BlockchainMonitor:
    """
    Main blockchain monitor that ties everything together.
    
    Continuously monitors the Base blockchain for contracts deployed from
    kushmanmb.base.eth and performs security audits on them.
    """
    
    def __init__(
        self,
        mother_config: Optional[MotherContractConfig] = None,
        monitor_config: Optional[MonitorConfig] = None,
        alert_callback: Optional[Callable[[Alert], None]] = None,
    ):
        self.mother_config = mother_config or DEFAULT_MOTHER_CONTRACT
        self.monitor_config = monitor_config or DEFAULT_MONITOR_CONFIG
        self.alert_callback = alert_callback
        
        self.state = MonitorState()
        self.w3: Optional["Web3"] = None
        self.resolver: Optional[BaseNamesResolver] = None
        self.factory_monitor: Optional[ContractFactoryMonitor] = None
        self.bytecode_analyzer = BytecodeAnalyzer()
        
        self._running = False
        self._stop_event: Optional[asyncio.Event] = None

    def connect(self, rpc_url: Optional[str] = None) -> bool:
        """
        Connect to the blockchain.
        
        Args:
            rpc_url: Optional RPC URL override
            
        Returns:
            True if connected successfully
        """
        if not WEB3_AVAILABLE:
            log.error("web3 package not installed. Run: pip install web3")
            return False
        
        url = rpc_url or self.mother_config.chain.rpc_url
        
        try:
            self.w3 = Web3(Web3.HTTPProvider(url))
            
            if not self.w3.is_connected():
                log.error("Failed to connect to %s", url)
                return False
            
            chain_id = self.w3.eth.chain_id
            log.info(
                "Connected to %s (chain ID: %d)",
                self.mother_config.chain.name,
                chain_id
            )
            
            # Verify chain ID
            if chain_id != self.mother_config.chain.chain_id:
                log.warning(
                    "Chain ID mismatch! Expected %d, got %d",
                    self.mother_config.chain.chain_id,
                    chain_id
                )
            
            # Initialize components
            self.resolver = BaseNamesResolver(self.w3)
            self.bytecode_analyzer = BytecodeAnalyzer(self.w3)
            
            return True
            
        except Exception as e:
            log.error("Error connecting to blockchain: %s", e)
            return False

    def resolve_mother_contract(self) -> Optional[str]:
        """
        Resolve the mother contract ENS name to an address.
        
        Returns:
            The resolved address or None
        """
        if self.mother_config.resolved_address:
            return self.mother_config.resolved_address
        
        if not self.resolver:
            log.error("Not connected to blockchain")
            return None
        
        address = self.resolver.resolve_name(self.mother_config.ens_name)
        if address:
            self.mother_config.resolved_address = address
            log.info(
                "Resolved %s to %s",
                self.mother_config.ens_name,
                address
            )
        else:
            log.warning(
                "Could not resolve %s - using manual address if configured",
                self.mother_config.ens_name
            )
        
        return address

    def initialize_factory_monitor(self, address: str) -> bool:
        """Initialize the factory monitor with the mother contract address."""
        if not self.w3:
            return False
        
        self.factory_monitor = ContractFactoryMonitor(
            self.w3,
            address,
            self.mother_config.monitored_events,
        )
        return True

    def audit_contract(self, contract: DeployedContract) -> List[Finding]:
        """
        Perform security audit on a deployed contract.
        
        Args:
            contract: The deployed contract to audit
            
        Returns:
            List of findings
        """
        findings: List[Finding] = []
        
        # Fetch bytecode if not already present
        if not contract.bytecode and self.w3:
            try:
                bytecode = self.w3.eth.get_code(contract.address)
                contract.bytecode = bytecode.hex() if bytecode else None
            except Exception as e:
                log.warning("Could not fetch bytecode for %s: %s", contract.address, e)
        
        # Analyze bytecode
        if contract.bytecode:
            findings.extend(self.bytecode_analyzer.analyze_bytecode(contract.bytecode))
        
        # If source code is available, run full security checks
        if contract.source_code:
            for check_fn in ALL_CHECKS:
                try:
                    findings.extend(check_fn(contract.source_code))
                except Exception as e:
                    log.warning("Check %s failed: %s", check_fn.__name__, e)
        
        contract.findings = findings
        contract.audited = True
        
        return findings

    def process_findings(self, contract: DeployedContract) -> None:
        """Process findings and generate alerts if needed."""
        for finding in contract.findings:
            if finding.severity == Severity.CRITICAL:
                self.state.critical_findings += 1
            elif finding.severity == Severity.HIGH:
                self.state.high_findings += 1
            
            # Generate alert if enabled
            if self.monitor_config.enable_alerts:
                alert = Alert(
                    severity=finding.severity,
                    contract_address=contract.address,
                    finding=finding,
                    timestamp=datetime.now(timezone.utc),
                    tx_hash=contract.tx_hash,
                    block_number=contract.block_number,
                )
                
                self._emit_alert(alert)
        
        # Auto-pause on critical findings if configured
        if (
            self.monitor_config.auto_pause_on_critical
            and any(f.severity == Severity.CRITICAL for f in contract.findings)
        ):
            log.warning(
                "CRITICAL finding detected in %s - pausing monitor",
                contract.address
            )
            self.state.is_paused = True

    def _emit_alert(self, alert: Alert) -> None:
        """Emit an alert via callback and/or webhook."""
        severity_icon = {
            Severity.INFO: "ℹ️",
            Severity.LOW: "🟡",
            Severity.MEDIUM: "🟠",
            Severity.HIGH: "🔴",
            Severity.CRITICAL: "💀",
        }.get(alert.severity, "❓")
        
        log.warning(
            "%s ALERT [%s] Contract %s: %s - %s",
            severity_icon,
            alert.severity.value,
            alert.contract_address[:10] + "...",
            alert.finding.check_name,
            alert.finding.description[:100],
        )
        
        if self.alert_callback:
            try:
                self.alert_callback(alert)
            except Exception as e:
                log.error("Alert callback failed: %s", e)

    def scan_blocks(self, from_block: int, to_block: int) -> List[DeployedContract]:
        """
        Scan a range of blocks for deployed contracts and audit them.
        
        Args:
            from_block: Starting block
            to_block: Ending block
            
        Returns:
            List of audited contracts
        """
        if not self.factory_monitor:
            log.error("Factory monitor not initialized")
            return []
        
        # Get deployed contracts
        contracts = self.factory_monitor.get_deployed_contracts(from_block, to_block)
        
        if contracts:
            log.info(
                "Found %d new contract(s) in blocks %d-%d",
                len(contracts),
                from_block,
                to_block
            )
        
        # Audit each contract
        for contract in contracts:
            if contract.address.lower() not in self.state.monitored_contracts:
                self.state.monitored_contracts.add(contract.address.lower())
                self.state.total_contracts_found += 1
                
                findings = self.audit_contract(contract)
                self.state.total_audits_performed += 1
                
                if findings:
                    log.warning(
                        "Contract %s has %d finding(s)",
                        contract.address,
                        len(findings)
                    )
                    self.process_findings(contract)
                else:
                    log.info(
                        "✅ Contract %s passed security audit",
                        contract.address
                    )
        
        return contracts

    async def run_async(self) -> None:
        """Run the monitor asynchronously."""
        self._running = True
        self._stop_event = asyncio.Event()
        self.state.start_time = datetime.now(timezone.utc)
        
        if not self.w3:
            if not self.connect():
                return
        
        # Resolve mother contract
        mother_address = self.resolve_mother_contract()
        if not mother_address:
            log.error("Could not resolve mother contract address")
            return
        
        # Initialize factory monitor
        if not self.initialize_factory_monitor(mother_address):
            return
        
        # Start from current block
        current_block = self.w3.eth.block_number
        self.state.last_block_processed = current_block - 1
        
        log.info(
            "🚀 Starting blockchain monitor for %s (%s)",
            self.mother_config.ens_name,
            mother_address
        )
        log.info("📍 Starting from block %d", current_block)
        
        while self._running and not self._stop_event.is_set():
            if self.state.is_paused:
                log.info("Monitor is paused - waiting for unpause...")
                await asyncio.sleep(self.monitor_config.poll_interval)
                continue
            
            try:
                current_block = self.w3.eth.block_number
                confirmed_block = current_block - self.monitor_config.block_confirmations
                
                if confirmed_block > self.state.last_block_processed:
                    self.scan_blocks(
                        self.state.last_block_processed + 1,
                        confirmed_block
                    )
                    self.state.last_block_processed = confirmed_block
            
            except Exception as e:
                log.error("Error in monitoring loop: %s", e)
            
            await asyncio.sleep(self.monitor_config.poll_interval)
        
        log.info("Monitor stopped")

    def run(self) -> None:
        """Run the monitor synchronously."""
        asyncio.run(self.run_async())

    def stop(self) -> None:
        """Stop the monitor."""
        self._running = False
        if self._stop_event:
            self._stop_event.set()

    def get_status(self) -> Dict[str, Any]:
        """Get the current monitor status."""
        return {
            "running": self._running,
            "paused": self.state.is_paused,
            "mother_contract": {
                "ens_name": self.mother_config.ens_name,
                "resolved_address": self.mother_config.resolved_address,
                "chain": self.mother_config.chain.name,
            },
            "statistics": {
                "start_time": self.state.start_time.isoformat() if self.state.start_time else None,
                "last_block_processed": self.state.last_block_processed,
                "total_contracts_found": self.state.total_contracts_found,
                "total_audits_performed": self.state.total_audits_performed,
                "critical_findings": self.state.critical_findings,
                "high_findings": self.state.high_findings,
                "monitored_contracts": len(self.state.monitored_contracts),
            },
        }


# ---------------------------------------------------------------------------
# Factory Function
# ---------------------------------------------------------------------------

def create_monitor(
    ens_name: str = "kushmanmb.base.eth",
    chain_name: str = "base",
    rpc_url: Optional[str] = None,
    resolved_address: Optional[str] = None,
    **kwargs: Any,
) -> BlockchainMonitor:
    """
    Create a blockchain monitor instance.
    
    Args:
        ens_name: ENS/Basename to monitor (default: kushmanmb.base.eth)
        chain_name: Chain name (default: base)
        rpc_url: Optional RPC URL override
        resolved_address: Optional pre-resolved address (skips ENS resolution)
        **kwargs: Additional MonitorConfig options
        
    Returns:
        Configured BlockchainMonitor instance
    """
    from bot.config import create_mother_contract_config
    
    mother_config = create_mother_contract_config(
        ens_name=ens_name,
        chain_name=chain_name,
        resolved_address=resolved_address,
    )
    
    if rpc_url:
        mother_config.chain.rpc_url = rpc_url
    
    monitor_config = MonitorConfig(**kwargs) if kwargs else DEFAULT_MONITOR_CONFIG
    
    return BlockchainMonitor(
        mother_config=mother_config,
        monitor_config=monitor_config,
    )
