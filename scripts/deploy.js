import { network } from "hardhat";

// Deploys the simple Artemis ownership contract (contracts/ArtemisOwnable.sol).
// The full multi-owner ARTEMIS.sol contract is deployed by scripts/deploy.py.
// Verify afterwards with: npx hardhat verify --network <network> <address>
const { ethers, networkName, networkConfig } = await network.getOrCreate();

console.log("Deploying Artemis contract to", networkName);
const artemis = await ethers.deployContract("Artemis");
await artemis.waitForDeployment();
const address = await artemis.getAddress();
console.log("Artemis deployed to:", address);

if (networkConfig.type === "http") {
  console.log("Waiting for 5 confirmations...");
  await artemis.deploymentTransaction().wait(5);
  console.log(`Verify with: npx hardhat verify --network ${networkName} ${address}`);
}
