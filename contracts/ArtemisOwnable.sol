// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title Artemis
 * @dev Space Blockchain smart contract for ARTEMIS 2.1
 */
contract Artemis {
    string public name = "ARTEMIS 2.1";
    address public owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    modifier onlyOwner() {
        require(msg.sender == owner, "Artemis: caller is not the owner");
        _;
    }

    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Artemis: new owner is the zero address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}
