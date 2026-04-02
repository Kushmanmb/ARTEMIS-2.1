const hre = require("hardhat");

async function main() {
  console.log("Deploying Artemis contract to", hre.network.name);

  const Artemis = await hre.ethers.getContractFactory("Artemis");
  const artemis = await Artemis.deploy();

  await artemis.waitForDeployment();

  const address = await artemis.getAddress();
  console.log("Artemis deployed to:", address);

  // Wait for a few block confirmations before verifying
  if (hre.network.name !== "hardhat" && hre.network.name !== "localhost") {
    console.log("Waiting for block confirmations...");
    await artemis.deploymentTransaction().wait(5);

    console.log("Verifying contract on Etherscan...");
    await hre.run("verify:verify", {
      address: address,
      constructorArguments: [],
    });
  }
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
