import { expect } from "chai";
import { network } from "hardhat";

const { ethers } = await network.create();

const Severity = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

describe("ARTEMIS (ARTEMIS.sol)", function () {
  let artemis;
  let owner1;
  let owner2;
  let outsider;

  beforeEach(async function () {
    [owner1, owner2, outsider] = await ethers.getSigners();
    artemis = await ethers.deployContract("ARTEMIS", [
      "ARTEMIS-2.1",
      owner1.address,
      "kushmanmb.eth",
      owner2.address,
      "yaketh.eth",
    ]);
  });

  describe("Deployment", function () {
    it("stores project metadata and both owners", async function () {
      expect(await artemis.projectName()).to.equal("ARTEMIS-2.1");
      expect(await artemis.deployedAt()).to.be.greaterThan(0n);
      expect(await artemis.ownerCount()).to.equal(2n);
      expect(await artemis.getOwners()).to.deep.equal([owner1.address, owner2.address]);
      expect(await artemis.ownerEnsName(owner1.address)).to.equal("kushmanmb.eth");
      expect(await artemis.ownerEnsName(owner2.address)).to.equal("yaketh.eth");
      expect(await artemis.paused()).to.equal(false);
    });

    it("rejects invalid constructor arguments", async function () {
      const factory = await ethers.getContractFactory("ARTEMIS");
      await expect(
        factory.deploy("", owner1.address, "a.eth", owner2.address, "b.eth")
      ).to.be.revertedWith("ARTEMIS: projectName required");
      await expect(
        factory.deploy("X", ethers.ZeroAddress, "a.eth", owner2.address, "b.eth")
      ).to.be.revertedWith("ARTEMIS: owner1 is zero address");
      await expect(
        factory.deploy("X", owner1.address, "a.eth", owner1.address, "b.eth")
      ).to.be.revertedWith("ARTEMIS: owners must be distinct");
      await expect(
        factory.deploy("X", owner1.address, "", owner2.address, "b.eth")
      ).to.be.revertedWith("ARTEMIS: owner1EnsName required");
    });
  });

  describe("Owner management", function () {
    it("lets an owner add and remove owners", async function () {
      await expect(artemis.addOwner(outsider.address, "third.eth")).to.emit(artemis, "OwnerAdded");
      expect(await artemis.authorizedWriters(outsider.address)).to.equal(true);
      expect(await artemis.ownerCount()).to.equal(3n);

      await expect(artemis.connect(owner2).removeOwner(outsider.address)).to.emit(artemis, "OwnerRemoved");
      expect(await artemis.authorizedWriters(outsider.address)).to.equal(false);
      expect(await artemis.ownerEnsName(outsider.address)).to.equal("");
      expect(await artemis.ownerCount()).to.equal(2n);
    });

    it("blocks non-owners and protects the last owner", async function () {
      await expect(
        artemis.connect(outsider).addOwner(outsider.address, "x.eth")
      ).to.be.revertedWith("ARTEMIS: caller is not an authorized owner");
      await expect(artemis.addOwner(owner2.address, "dup.eth")).to.be.revertedWith(
        "ARTEMIS: already an owner"
      );
      await artemis.removeOwner(owner2.address);
      await expect(artemis.removeOwner(owner1.address)).to.be.revertedWith(
        "ARTEMIS: cannot remove last owner"
      );
    });
  });

  describe("Audit log and pause", function () {
    it("records findings and filters by severity", async function () {
      await expect(artemis.reportFinding(Severity.LOW, "TX_ORIGIN", "tx.origin used", false)).to.emit(
        artemis,
        "AuditFinding"
      );
      await artemis.connect(owner2).reportFinding(Severity.CRITICAL, "REENTRANCY", "external call before state", true);

      expect(await artemis.auditLogLength()).to.equal(2n);
      const entry = await artemis.getAuditEntry(1);
      expect(entry.checkName).to.equal("REENTRANCY");
      expect(entry.autoFixed).to.equal(true);

      const high = await artemis.findingsBySeverity(Severity.HIGH);
      expect(high.length).to.equal(1);
      expect(high[0].checkName).to.equal("REENTRANCY");
      await expect(artemis.getAuditEntry(2)).to.be.revertedWith("ARTEMIS: index out of bounds");
    });

    it("rejects findings from outsiders and while paused", async function () {
      await expect(
        artemis.connect(outsider).reportFinding(Severity.INFO, "X", "Y", false)
      ).to.be.revertedWith("ARTEMIS: caller is not an authorized owner");

      await expect(artemis.pause()).to.emit(artemis, "ContractPaused");
      await expect(artemis.reportFinding(Severity.INFO, "X", "Y", false)).to.be.revertedWith(
        "ARTEMIS: contract is paused"
      );
      await expect(artemis.pause()).to.be.revertedWith("ARTEMIS: already paused");
      await expect(artemis.connect(owner2).unpause()).to.emit(artemis, "ContractUnpaused");
      await expect(artemis.unpause()).to.be.revertedWith("ARTEMIS: not paused");
    });
  });
});
