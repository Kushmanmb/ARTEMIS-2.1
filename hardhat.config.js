import { defineConfig, configVariable } from "hardhat/config";
import hardhatToolboxMochaEthers from "@nomicfoundation/hardhat-toolbox-mocha-ethers";
import * as dotenv from "dotenv";

dotenv.config();

// Remote networks are only configured when their RPC URL is present, so local
// compile/test never needs secrets. PRIVATE_KEY is read through Hardhat's
// configVariable() and is never written to disk or logged.
const remote = (name, chainId) =>
  process.env[`${name}_RPC_URL`]
    ? {
        [name.toLowerCase()]: {
          type: "http",
          chainType: "l1",
          chainId,
          url: process.env[`${name}_RPC_URL`],
          accounts: [configVariable("PRIVATE_KEY")],
        },
      }
    : {};

export default defineConfig({
  plugins: [hardhatToolboxMochaEthers],
  solidity: {
    version: "0.8.20",
    settings: {
      optimizer: { enabled: true, runs: 200 },
    },
  },
  networks: {
    hardhat: { type: "edr-simulated", chainType: "l1" },
    ...remote("MAINNET", 1),
    ...remote("SEPOLIA", 11155111),
  },
  verify: {
    etherscan: { apiKey: process.env.ETHERSCAN_API_KEY || "" },
  },
});
