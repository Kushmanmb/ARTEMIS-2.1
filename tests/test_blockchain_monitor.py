"""
ARTEMIS-2.1 — Blockchain Monitor Test Suite
--------------------------------------------
Unit tests for the blockchain monitoring functionality:
- Configuration loading
- ENS/Basenames resolution
- Contract factory monitoring
- Bytecode analysis
- Alert system

Run with:
    python -m pytest tests/test_blockchain_monitor.py -v
"""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch, PropertyMock
from dataclasses import asdict

from bot.config import (
    ChainConfig,
    MonitorConfig,
    MotherContractConfig,
    OwnerConfig,
    DEFAULT_MOTHER_CONTRACT,
    DEFAULT_MONITOR_CONFIG,
    AUTHORIZED_OWNERS,
    get_chain_config,
    get_owner_ens_names,
    is_write_authorized,
    create_mother_contract_config,
    BASE_MAINNET,
    BASE_SEPOLIA,
    ETHEREUM_MAINNET,
)

# Try to import blockchain_monitor - it may fail if web3 is not installed
try:
    from bot.blockchain_monitor import (
        BlockchainMonitor,
        BytecodeAnalyzer,
        DeployedContract,
        MonitorState,
        Alert,
        create_monitor,
        WEB3_AVAILABLE,
    )
    BLOCKCHAIN_MONITOR_AVAILABLE = True
except ImportError:
    BLOCKCHAIN_MONITOR_AVAILABLE = False
    WEB3_AVAILABLE = False

from bot.security_checks import Severity, Finding


# ---------------------------------------------------------------------------
# Configuration Tests
# ---------------------------------------------------------------------------

class TestChainConfig:
    def test_base_mainnet_config(self):
        assert BASE_MAINNET.chain_id == 8453
        assert BASE_MAINNET.name == "Base Mainnet"
        assert BASE_MAINNET.rpc_url == "https://mainnet.base.org"
        assert BASE_MAINNET.explorer_url == "https://basescan.org"

    def test_base_sepolia_config(self):
        assert BASE_SEPOLIA.chain_id == 84532
        assert BASE_SEPOLIA.name == "Base Sepolia"
        assert BASE_SEPOLIA.rpc_url == "https://sepolia.base.org"

    def test_ethereum_mainnet_config(self):
        assert ETHEREUM_MAINNET.chain_id == 1
        assert ETHEREUM_MAINNET.name == "Ethereum Mainnet"
        assert ETHEREUM_MAINNET.ens_registry is not None


class TestMotherContractConfig:
    def test_default_config_has_kushmanmb(self):
        assert DEFAULT_MOTHER_CONTRACT.ens_name == "kushmanmb.base.eth"
        assert DEFAULT_MOTHER_CONTRACT.chain.chain_id == 8453  # Base

    def test_default_config_has_monitored_events(self):
        events = DEFAULT_MOTHER_CONTRACT.monitored_events
        assert len(events) > 0
        assert "ContractDeployed" in events

    def test_alert_threshold_default(self):
        assert DEFAULT_MOTHER_CONTRACT.alert_threshold_severity == "MEDIUM"


class TestMonitorConfig:
    def test_default_poll_interval(self):
        assert DEFAULT_MONITOR_CONFIG.poll_interval == 15

    def test_default_confirmations(self):
        assert DEFAULT_MONITOR_CONFIG.block_confirmations == 3

    def test_auto_pause_enabled(self):
        assert DEFAULT_MONITOR_CONFIG.auto_pause_on_critical is True


class TestGetChainConfig:
    def test_get_base_chain(self):
        chain = get_chain_config("base")
        assert chain.chain_id == 8453

    def test_get_base_mainnet_alias(self):
        chain = get_chain_config("base-mainnet")
        assert chain.chain_id == 8453

    def test_get_ethereum_chain(self):
        chain = get_chain_config("ethereum")
        assert chain.chain_id == 1
        
    def test_get_eth_alias(self):
        chain = get_chain_config("eth")
        assert chain.chain_id == 1

    def test_case_insensitive(self):
        chain = get_chain_config("BASE")
        assert chain.chain_id == 8453

    def test_unknown_chain_raises(self):
        with pytest.raises(ValueError, match="Unknown chain"):
            get_chain_config("unknown-chain")


class TestCreateMotherContractConfig:
    def test_create_default_config(self):
        config = create_mother_contract_config()
        assert config.ens_name == "kushmanmb.base.eth"
        assert config.chain.chain_id == 8453

    def test_create_with_custom_ens(self):
        config = create_mother_contract_config(ens_name="custom.base.eth")
        assert config.ens_name == "custom.base.eth"

    def test_create_with_different_chain(self):
        config = create_mother_contract_config(chain_name="ethereum")
        assert config.chain.chain_id == 1

    def test_create_with_resolved_address(self):
        address = "0x1234567890123456789012345678901234567890"
        config = create_mother_contract_config(resolved_address=address)
        assert config.resolved_address == address


# ---------------------------------------------------------------------------
# Authorized Owner Tests
# ---------------------------------------------------------------------------

class TestAuthorizedOwners:
    def test_exactly_two_authorized_owners(self):
        assert len(AUTHORIZED_OWNERS) == 2

    def test_kushmanmb_eth_present(self):
        names = get_owner_ens_names()
        assert "kushmanmb.eth" in names

    def test_yaketh_eth_present(self):
        names = get_owner_ens_names()
        assert "yaketh.eth" in names

    def test_kushmanmb_has_write_permission(self):
        assert is_write_authorized("kushmanmb.eth")

    def test_yaketh_has_write_permission(self):
        assert is_write_authorized("yaketh.eth")

    def test_unknown_ens_not_authorized(self):
        assert not is_write_authorized("unknown.eth")

    def test_all_owners_have_write_permission(self):
        for owner in AUTHORIZED_OWNERS:
            assert "write" in owner.permissions, \
                f"{owner.ens_name} is missing write permission"

    def test_owner_config_structure(self):
        for owner in AUTHORIZED_OWNERS:
            assert owner.ens_name.endswith(".eth")
            assert isinstance(owner.permissions, list)
            assert len(owner.permissions) > 0


# ---------------------------------------------------------------------------
# Blockchain Monitor Tests (only run if web3 is available)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not BLOCKCHAIN_MONITOR_AVAILABLE, reason="web3 not installed")
class TestBytecodeAnalyzer:
    def test_empty_bytecode(self):
        analyzer = BytecodeAnalyzer()
        findings = analyzer.analyze_bytecode("")
        assert findings == []

    def test_null_bytecode(self):
        analyzer = BytecodeAnalyzer()
        findings = analyzer.analyze_bytecode("0x")
        assert findings == []

    def test_detect_selfdestruct(self):
        # ff is SELFDESTRUCT opcode
        bytecode = "0x6080604052ff"
        analyzer = BytecodeAnalyzer()
        findings = analyzer.analyze_bytecode(bytecode)
        selfdestruct_findings = [f for f in findings if "SELFDESTRUCT" in f.check_name]
        assert len(selfdestruct_findings) == 1
        assert selfdestruct_findings[0].severity == Severity.CRITICAL

    def test_detect_delegatecall(self):
        # f4 is DELEGATECALL opcode
        bytecode = "0x6080604052f4"
        analyzer = BytecodeAnalyzer()
        findings = analyzer.analyze_bytecode(bytecode)
        delegatecall_findings = [f for f in findings if "DELEGATECALL" in f.check_name]
        assert len(delegatecall_findings) == 1
        assert delegatecall_findings[0].severity == Severity.HIGH

    def test_short_bytecode_warning(self):
        bytecode = "0x60806040"  # Very short bytecode
        analyzer = BytecodeAnalyzer()
        findings = analyzer.analyze_bytecode(bytecode)
        short_findings = [f for f in findings if "SHORT" in f.check_name]
        assert len(short_findings) == 1
        assert short_findings[0].severity == Severity.LOW

    def test_normal_bytecode_no_short_warning(self):
        # Generate a normal-length bytecode (>= 100 chars in hex)
        bytecode = "0x" + "60" * 100  # 200 hex chars = 100 bytes
        analyzer = BytecodeAnalyzer()
        findings = analyzer.analyze_bytecode(bytecode)
        short_findings = [f for f in findings if "SHORT" in f.check_name]
        assert len(short_findings) == 0


@pytest.mark.skipif(not BLOCKCHAIN_MONITOR_AVAILABLE, reason="web3 not installed")
class TestDeployedContract:
    def test_create_deployed_contract(self):
        contract = DeployedContract(
            address="0x1234567890123456789012345678901234567890",
            deployer="0x0987654321098765432109876543210987654321",
            tx_hash="0xabcdef",
            block_number=12345,
            timestamp=1700000000,
        )
        assert contract.address.startswith("0x")
        assert not contract.audited
        assert contract.findings == []

    def test_deployed_contract_with_findings(self):
        finding = Finding(
            check_name="TEST_FINDING",
            severity=Severity.HIGH,
            description="Test finding",
        )
        contract = DeployedContract(
            address="0x1234567890123456789012345678901234567890",
            deployer="0x0987654321098765432109876543210987654321",
            tx_hash="0xabcdef",
            block_number=12345,
            timestamp=1700000000,
            findings=[finding],
            audited=True,
        )
        assert contract.audited
        assert len(contract.findings) == 1


@pytest.mark.skipif(not BLOCKCHAIN_MONITOR_AVAILABLE, reason="web3 not installed")
class TestMonitorState:
    def test_initial_state(self):
        state = MonitorState()
        assert state.last_block_processed == 0
        assert state.total_contracts_found == 0
        assert state.critical_findings == 0
        assert state.is_paused is False
        assert len(state.monitored_contracts) == 0


@pytest.mark.skipif(not BLOCKCHAIN_MONITOR_AVAILABLE, reason="web3 not installed")
class TestAlert:
    def test_create_alert(self):
        from datetime import datetime, timezone
        
        finding = Finding(
            check_name="CRITICAL_ISSUE",
            severity=Severity.CRITICAL,
            description="Critical security issue detected",
        )
        alert = Alert(
            severity=Severity.CRITICAL,
            contract_address="0x1234567890123456789012345678901234567890",
            finding=finding,
            timestamp=datetime.now(timezone.utc),
            tx_hash="0xabcdef",
            block_number=12345,
        )
        assert alert.severity == Severity.CRITICAL
        assert "1234" in alert.contract_address


@pytest.mark.skipif(not BLOCKCHAIN_MONITOR_AVAILABLE, reason="web3 not installed")
class TestCreateMonitor:
    def test_create_monitor_default(self):
        monitor = create_monitor()
        assert monitor.mother_config.ens_name == "kushmanmb.base.eth"
        assert monitor.mother_config.chain.chain_id == 8453

    def test_create_monitor_with_address(self):
        address = "0x1234567890123456789012345678901234567890"
        monitor = create_monitor(resolved_address=address)
        assert monitor.mother_config.resolved_address == address

    def test_create_monitor_different_chain(self):
        monitor = create_monitor(chain_name="ethereum")
        assert monitor.mother_config.chain.chain_id == 1


@pytest.mark.skipif(not BLOCKCHAIN_MONITOR_AVAILABLE, reason="web3 not installed")
class TestBlockchainMonitor:
    def test_monitor_initial_state(self):
        monitor = BlockchainMonitor()
        assert monitor.state.is_paused is False
        assert monitor.w3 is None

    def test_monitor_get_status(self):
        monitor = BlockchainMonitor()
        status = monitor.get_status()
        assert "running" in status
        assert "paused" in status
        assert "mother_contract" in status
        assert "statistics" in status

    def test_monitor_status_has_mother_contract_info(self):
        monitor = BlockchainMonitor()
        status = monitor.get_status()
        assert status["mother_contract"]["ens_name"] == "kushmanmb.base.eth"
        assert status["mother_contract"]["chain"] == "Base Mainnet"


@pytest.mark.skipif(not BLOCKCHAIN_MONITOR_AVAILABLE, reason="web3 not installed")
class TestBlockchainMonitorAudit:
    def test_audit_contract_with_bytecode(self):
        monitor = BlockchainMonitor()
        
        # Create a contract with dangerous bytecode (contains SELFDESTRUCT)
        contract = DeployedContract(
            address="0x1234567890123456789012345678901234567890",
            deployer="0x0987654321098765432109876543210987654321",
            tx_hash="0xabcdef",
            block_number=12345,
            timestamp=1700000000,
            bytecode="0x6080604052ff",  # Contains SELFDESTRUCT
        )
        
        findings = monitor.audit_contract(contract)
        assert contract.audited is True
        assert len(findings) > 0
        
        # Should detect SELFDESTRUCT
        selfdestruct_findings = [f for f in findings if "SELFDESTRUCT" in f.check_name]
        assert len(selfdestruct_findings) == 1

    def test_audit_contract_clean(self):
        monitor = BlockchainMonitor()
        
        # Create a contract with clean bytecode
        contract = DeployedContract(
            address="0x1234567890123456789012345678901234567890",
            deployer="0x0987654321098765432109876543210987654321",
            tx_hash="0xabcdef",
            block_number=12345,
            timestamp=1700000000,
            bytecode="0x" + "60" * 100,  # Normal bytecode, no dangerous opcodes
        )
        
        findings = monitor.audit_contract(contract)
        assert contract.audited is True
        
        # Should not have critical or high findings
        critical_high = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert len(critical_high) == 0


# ---------------------------------------------------------------------------
# Integration Tests (mocked blockchain connection)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not BLOCKCHAIN_MONITOR_AVAILABLE, reason="web3 not installed")
class TestBlockchainMonitorIntegration:
    def test_connect_failure_returns_false(self):
        """Test that connect returns False when connection fails."""
        monitor = BlockchainMonitor()
        # Use an invalid RPC URL
        result = monitor.connect("http://invalid.example.com:8545")
        assert result is False

    def test_process_findings_updates_state(self):
        """Test that processing findings updates the monitor state."""
        monitor = BlockchainMonitor()
        
        contract = DeployedContract(
            address="0x1234567890123456789012345678901234567890",
            deployer="0x0987654321098765432109876543210987654321",
            tx_hash="0xabcdef",
            block_number=12345,
            timestamp=1700000000,
            findings=[
                Finding(
                    check_name="CRITICAL_ISSUE",
                    severity=Severity.CRITICAL,
                    description="Critical issue",
                ),
                Finding(
                    check_name="HIGH_ISSUE",
                    severity=Severity.HIGH,
                    description="High issue",
                ),
            ],
        )
        
        monitor.process_findings(contract)
        
        assert monitor.state.critical_findings == 1
        assert monitor.state.high_findings == 1

    def test_auto_pause_on_critical(self):
        """Test that monitor auto-pauses on critical findings."""
        config = MonitorConfig(auto_pause_on_critical=True)
        monitor = BlockchainMonitor(monitor_config=config)
        
        contract = DeployedContract(
            address="0x1234567890123456789012345678901234567890",
            deployer="0x0987654321098765432109876543210987654321",
            tx_hash="0xabcdef",
            block_number=12345,
            timestamp=1700000000,
            findings=[
                Finding(
                    check_name="CRITICAL_ISSUE",
                    severity=Severity.CRITICAL,
                    description="Critical issue",
                ),
            ],
        )
        
        monitor.process_findings(contract)
        
        assert monitor.state.is_paused is True

    def test_no_auto_pause_on_high(self):
        """Test that monitor does not auto-pause on high (non-critical) findings."""
        config = MonitorConfig(auto_pause_on_critical=True)
        monitor = BlockchainMonitor(monitor_config=config)
        
        contract = DeployedContract(
            address="0x1234567890123456789012345678901234567890",
            deployer="0x0987654321098765432109876543210987654321",
            tx_hash="0xabcdef",
            block_number=12345,
            timestamp=1700000000,
            findings=[
                Finding(
                    check_name="HIGH_ISSUE",
                    severity=Severity.HIGH,
                    description="High issue",
                ),
            ],
        )
        
        monitor.process_findings(contract)
        
        assert monitor.state.is_paused is False
