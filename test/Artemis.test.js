const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("Artemis", function () {
  let artemis;
  let owner;
  let addr1;

  beforeEach(async function () {
    [owner, addr1] = await ethers.getSigners();
    const Artemis = await ethers.getContractFactory("Artemis");
    artemis = await Artemis.deploy();
  });

  describe("Deployment", function () {
    it("Should set the correct name", async function () {
      expect(await artemis.name()).to.equal("ARTEMIS 2.1");
    });

    it("Should set the right owner", async function () {
      expect(await artemis.owner()).to.equal(owner.address);
    });
  });

  describe("Ownership", function () {
    it("Should transfer ownership", async function () {
      await artemis.transferOwnership(addr1.address);
      expect(await artemis.owner()).to.equal(addr1.address);
    });

    it("Should fail if non-owner tries to transfer", async function () {
      await expect(
        artemis.connect(addr1).transferOwnership(addr1.address)
      ).to.be.revertedWith("Artemis: caller is not the owner");
    });

    it("Should fail if transferring to zero address", async function () {
      await expect(
        artemis.transferOwnership(ethers.ZeroAddress)
      ).to.be.revertedWith("Artemis: new owner is the zero address");
    });
  });
});
