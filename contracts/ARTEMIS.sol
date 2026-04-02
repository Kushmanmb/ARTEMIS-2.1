// SPDX-License-Identifier: Apache-2.0
// ARTEMIS-2.1 — Space Blockchain Smart Contract Security Bot
// Immutable owner info is set at deploy time and cannot be changed.
pragma solidity ^0.8.20;

/**
 * @title ARTEMIS
 * @notice Autonomous Real-Time Ethereum Monitor & Immutable Security (ARTEMIS) contract.
 *         Records on-chain audit findings, exposes immutable owner metadata, and
 *         enforces a pause mechanism so compromised state can be frozen 24/7.
 */
contract ARTEMIS {
    // -------------------------------------------------------------------------
    // Immutable owner info — written once at construction, cannot be altered.
    // -------------------------------------------------------------------------
    address public immutable owner;
    string  public immutable ownerName;
    string  public immutable projectName;
    uint256 public immutable deployedAt;

    // -------------------------------------------------------------------------
    // Pause / circuit-breaker
    // -------------------------------------------------------------------------
    bool public paused;

    // -------------------------------------------------------------------------
    // Audit log
    // -------------------------------------------------------------------------
    enum Severity { INFO, LOW, MEDIUM, HIGH, CRITICAL }

    struct AuditEntry {
        uint256 timestamp;
        Severity severity;
        string   checkName;
        string   description;
        bool     autoFixed;
    }

    AuditEntry[] private _auditLog;

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------
    event AuditFinding(
        uint256 indexed timestamp,
        Severity indexed severity,
        string checkName,
        string description,
        bool autoFixed
    );
    event ContractPaused(address indexed by, uint256 timestamp);
    event ContractUnpaused(address indexed by, uint256 timestamp);

    // -------------------------------------------------------------------------
    // Modifiers
    // -------------------------------------------------------------------------
    modifier onlyOwner() {
        require(msg.sender == owner, "ARTEMIS: caller is not owner");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "ARTEMIS: contract is paused");
        _;
    }

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------
    constructor(string memory _ownerName, string memory _projectName) {
        require(bytes(_ownerName).length > 0,   "ARTEMIS: ownerName required");
        require(bytes(_projectName).length > 0, "ARTEMIS: projectName required");
        owner       = msg.sender;
        ownerName   = _ownerName;
        projectName = _projectName;
        deployedAt  = block.timestamp;
    }

    // -------------------------------------------------------------------------
    // Audit reporting (called by off-chain bot or owner)
    // -------------------------------------------------------------------------

    /**
     * @notice Record an audit finding on-chain.
     * @param severity   Severity level of the finding.
     * @param checkName  Short identifier for the security check (e.g. "REENTRANCY").
     * @param description Human-readable description of the finding.
     * @param autoFixed  Whether the off-chain bot has already applied an auto-fix.
     */
    function reportFinding(
        Severity severity,
        string calldata checkName,
        string calldata description,
        bool autoFixed
    ) external onlyOwner whenNotPaused {
        AuditEntry memory entry = AuditEntry({
            timestamp:   block.timestamp,
            severity:    severity,
            checkName:   checkName,
            description: description,
            autoFixed:   autoFixed
        });
        _auditLog.push(entry);
        emit AuditFinding(block.timestamp, severity, checkName, description, autoFixed);
    }

    // -------------------------------------------------------------------------
    // Pause / unpause
    // -------------------------------------------------------------------------

    /// @notice Pause the contract — halts sensitive operations during an incident.
    function pause() external onlyOwner {
        require(!paused, "ARTEMIS: already paused");
        paused = true;
        emit ContractPaused(msg.sender, block.timestamp);
    }

    /// @notice Resume normal operation after an incident is resolved.
    function unpause() external onlyOwner {
        require(paused, "ARTEMIS: not paused");
        paused = false;
        emit ContractUnpaused(msg.sender, block.timestamp);
    }

    // -------------------------------------------------------------------------
    // View helpers
    // -------------------------------------------------------------------------

    /// @notice Total number of audit entries recorded on-chain.
    function auditLogLength() external view returns (uint256) {
        return _auditLog.length;
    }

    /// @notice Retrieve a single audit entry by index.
    function getAuditEntry(uint256 index) external view returns (AuditEntry memory) {
        require(index < _auditLog.length, "ARTEMIS: index out of bounds");
        return _auditLog[index];
    }

    /// @notice Return all entries with severity >= the given threshold.
    function findingsBySeverity(Severity minSeverity)
        external
        view
        returns (AuditEntry[] memory results)
    {
        uint256 count;
        for (uint256 i; i < _auditLog.length; ++i) {
            if (uint8(_auditLog[i].severity) >= uint8(minSeverity)) {
                ++count;
            }
        }
        results = new AuditEntry[](count);
        uint256 j;
        for (uint256 i; i < _auditLog.length; ++i) {
            if (uint8(_auditLog[i].severity) >= uint8(minSeverity)) {
                results[j++] = _auditLog[i];
            }
        }
    }
}
