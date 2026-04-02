// SPDX-License-Identifier: Apache-2.0
// ARTEMIS-2.1 — Space Blockchain Smart Contract Security Bot
// Authorized write-permission owners are set at deploy time.
pragma solidity ^0.8.20;

/**
 * @title ARTEMIS
 * @notice Autonomous Real-Time Ethereum Monitor & Immutable Security (ARTEMIS) contract.
 *         Records on-chain audit findings, exposes immutable owner metadata, and
 *         enforces a pause mechanism so compromised state can be frozen 24/7.
 *
 *         Supports multiple authorized owners, each with write permissions.
 *         Initial owners: kushmanmb.eth and yaketh.eth (resolved at deploy time).
 */
contract ARTEMIS {
    // -------------------------------------------------------------------------
    // Multi-owner authorization — both addresses have write permissions.
    // -------------------------------------------------------------------------

    /// @notice Returns true if the address has write permission.
    mapping(address => bool) public authorizedWriters;

    /// @notice Human-readable ENS label for each authorized address.
    mapping(address => string) public ownerEnsName;

    /// @notice Ordered list of all authorized writer addresses (for enumeration).
    address[] private _writerList;

    // -------------------------------------------------------------------------
    // Immutable project metadata — written once at construction.
    // -------------------------------------------------------------------------
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
    event OwnerAdded(address indexed account, string ensName, uint256 timestamp);
    event OwnerRemoved(address indexed account, uint256 timestamp);

    // -------------------------------------------------------------------------
    // Modifiers
    // -------------------------------------------------------------------------
    modifier onlyOwner() {
        require(authorizedWriters[msg.sender], "ARTEMIS: caller is not an authorized owner");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "ARTEMIS: contract is paused");
        _;
    }

    // -------------------------------------------------------------------------
    // Constructor — accepts two owner addresses for kushmanmb.eth and yaketh.eth
    // -------------------------------------------------------------------------

    /**
     * @param _projectName   Human-readable project name (immutable).
     * @param _owner1        Address resolved from kushmanmb.eth.
     * @param _owner1EnsName ENS name of the first owner (e.g. "kushmanmb.eth").
     * @param _owner2        Address resolved from yaketh.eth.
     * @param _owner2EnsName ENS name of the second owner (e.g. "yaketh.eth").
     */
    constructor(
        string memory _projectName,
        address _owner1,
        string memory _owner1EnsName,
        address _owner2,
        string memory _owner2EnsName
    ) {
        require(bytes(_projectName).length > 0,   "ARTEMIS: projectName required");
        require(_owner1 != address(0),             "ARTEMIS: owner1 is zero address");
        require(_owner2 != address(0),             "ARTEMIS: owner2 is zero address");
        require(_owner1 != _owner2,                "ARTEMIS: owners must be distinct");
        require(bytes(_owner1EnsName).length > 0,  "ARTEMIS: owner1EnsName required");
        require(bytes(_owner2EnsName).length > 0,  "ARTEMIS: owner2EnsName required");

        projectName = _projectName;
        deployedAt  = block.timestamp;

        _addOwner(_owner1, _owner1EnsName);
        _addOwner(_owner2, _owner2EnsName);
    }

    // -------------------------------------------------------------------------
    // Owner management (restricted to existing authorized writers)
    // -------------------------------------------------------------------------

    /**
     * @notice Grant write permission to a new address.
     * @dev    Callable by any existing authorized writer.
     */
    function addOwner(address account, string calldata ensName) external onlyOwner {
        require(account != address(0),         "ARTEMIS: zero address");
        require(!authorizedWriters[account],   "ARTEMIS: already an owner");
        require(bytes(ensName).length > 0,     "ARTEMIS: ensName required");
        _addOwner(account, ensName);
    }

    /**
     * @notice Revoke write permission from an address.
     * @dev    Callable by any existing authorized writer.
     *         At least one owner must remain after removal.
     */
    function removeOwner(address account) external onlyOwner {
        require(authorizedWriters[account],    "ARTEMIS: not an owner");
        require(_writerList.length > 1,        "ARTEMIS: cannot remove last owner");
        _removeOwner(account);
    }

    /// @notice Return the number of authorized writers.
    function ownerCount() external view returns (uint256) {
        return _writerList.length;
    }

    /// @notice Return all authorized writer addresses.
    function getOwners() external view returns (address[] memory) {
        return _writerList;
    }

    // -------------------------------------------------------------------------
    // Audit reporting (called by off-chain bot or any authorized owner)
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

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    function _addOwner(address account, string memory ensName) internal {
        authorizedWriters[account] = true;
        ownerEnsName[account]      = ensName;
        _writerList.push(account);
        emit OwnerAdded(account, ensName, block.timestamp);
    }

    function _removeOwner(address account) internal {
        authorizedWriters[account] = false;
        delete ownerEnsName[account];
        // Swap-and-pop to remove from the list
        uint256 len = _writerList.length;
        for (uint256 i; i < len; ++i) {
            if (_writerList[i] == account) {
                _writerList[i] = _writerList[len - 1];
                _writerList.pop();
                break;
            }
        }
        emit OwnerRemoved(account, block.timestamp);
    }
}

