import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import { expect } from "chai";
import { randomBytes } from "crypto";
import { AbiCoder, solidityPacked as encodePacked, keccak256, TypedDataDomain, ZeroAddress } from "ethers";
import { ethers } from "hardhat";

import { PRECISION, ZERO_ADDR } from "@/scripts/utils/constants";
import { Reverter } from "@/test/helpers/reverter";

import {
  ERC1967Proxy__factory,
  ProposalCreationGroth16Verifier,
  ProposalVotingGroth16Verifier,
  ZKMultisigMock,
  ZKMultisigFactory,
} from "@ethers-v6";

import { getPoseidon } from "./helpers";
import { generateParticipants, pointsToArray } from "@/test/helpers/zk-multisig";

describe("ZKMultisigFactory", () => {
  const reverter = new Reverter();

  let alice: SignerWithAddress;

  let creationVerifier: ProposalCreationGroth16Verifier;
  let votingVerifier: ProposalVotingGroth16Verifier;
  let zkMultisig: ZKMultisigMock;
  let zkMultisigFactory: ZKMultisigFactory;

  const encode = (types: ReadonlyArray<string>, values: ReadonlyArray<string | bigint>): string => {
    return AbiCoder.defaultAbiCoder().encode(types, values);
  };

  const randomNumber = () => BigInt("0x" + randomBytes(32).toString("hex"));

  before(async () => {
    [alice] = await ethers.getSigners();

    creationVerifier = await ethers.deployContract("ProposalCreationGroth16Verifier");
    votingVerifier = await ethers.deployContract("ProposalVotingGroth16Verifier");

    zkMultisig = await ethers.deployContract("ZKMultisigMock", {
      libraries: {
        PoseidonUnit1L: await (await getPoseidon(1)).getAddress(),
        PoseidonUnit3L: await (await getPoseidon(3)).getAddress(),
      },
    });

    zkMultisigFactory = await ethers.deployContract("ZKMultisigFactory");

    await zkMultisigFactory.initialize(zkMultisig, creationVerifier, votingVerifier);

    await reverter.snapshot();
  });

  afterEach(reverter.revert);

  describe("initialize", () => {
    it("should set parameters correctly", async () => {
      expect(await zkMultisigFactory.getZKMultisigImplementation()).to.eq(await zkMultisig.getAddress());
      expect(await zkMultisigFactory.getCreationVerifier()).to.eq(await creationVerifier.getAddress());
      expect(await zkMultisigFactory.getVotingVerifier()).to.eq(await votingVerifier.getAddress());
    });

    it("should have correct initial state", async () => {
      expect(await zkMultisigFactory.getZKMultisigsCount()).to.be.eq(0);
      expect(await zkMultisigFactory.getZKMultisigs(0, 1)).to.be.deep.eq([]);
    });

    it("should revert if initialize parameters are incorrect", async () => {
      const factory = await ethers.deployContract("ZKMultisigFactory");

      await expect(factory.initialize(ZeroAddress, creationVerifier, votingVerifier)).to.be.revertedWithCustomError(
        zkMultisigFactory,
        "InvalidImplementationOrVerifier",
      );
      await expect(factory.initialize(zkMultisig, ZeroAddress, votingVerifier)).to.be.revertedWithCustomError(
        zkMultisigFactory,
        "InvalidImplementationOrVerifier",
      );
      await expect(factory.initialize(zkMultisig, creationVerifier, ZeroAddress)).to.be.revertedWithCustomError(
        zkMultisigFactory,
        "InvalidImplementationOrVerifier",
      );
    });

    it("should revert if ctrying to initialize twice", async () => {
      await expect(
        zkMultisigFactory.initialize(zkMultisig, creationVerifier, creationVerifier),
      ).to.be.revertedWithCustomError(zkMultisigFactory, "InvalidInitialization");
    });
  });

  describe("KDF message", () => {
    it("should return correct KDF messages", async () => {
      const domain = {
        name: "ZKMultisigFactory",
        version: "1",
        chainId: (await ethers.provider.getNetwork()).chainId,
        verifyingContract: await zkMultisigFactory.getAddress(),
      } as TypedDataDomain;

      const types = { KDF: [{ name: "zkMultisigAddress", type: "address" }] };

      let values = { zkMultisigAddress: await zkMultisig.getAddress() };
      const msgHash = ethers.TypedDataEncoder.hash(domain, types, values);

      values = { zkMultisigAddress: ZERO_ADDR };
      const defaultMsgHash = ethers.TypedDataEncoder.hash(domain, types, values);

      expect(await zkMultisigFactory.getKDFMSGToSign(await zkMultisig.getAddress())).to.be.eq(msgHash);
      expect(await zkMultisigFactory.getDefaultKDFMSGToSign()).to.be.eq(defaultMsgHash);
    });
  });

  describe("zkMultisig factory", () => {
    it("should correctly calculate address of create2", async () => {
      const salt = randomNumber();

      const multisigAddress = await zkMultisigFactory.computeZKMultisigAddress(alice.address, salt);

      const calculatedAddress = ethers.getCreate2Address(
        await zkMultisigFactory.getAddress(),
        keccak256(encode(["address", "uint256"], [alice.address, salt])),
        keccak256(
          encodePacked(
            ["bytes", "bytes"],
            [ERC1967Proxy__factory.bytecode, encode(["address", "bytes"], [await zkMultisig.getAddress(), "0x"])],
          ),
        ),
      );

      expect(multisigAddress).to.be.eq(calculatedAddress);
    });

    it("should create zkMultisig contract", async () => {
      const salt = randomNumber();
      const multisigAddress = await zkMultisigFactory.computeZKMultisigAddress(alice.address, salt);

      expect(await zkMultisigFactory.isZKMultisig(multisigAddress)).to.be.eq(false);
      expect(await zkMultisigFactory.getZKMultisigsCount()).to.be.eq(0);
      expect(await zkMultisigFactory.getZKMultisigs(0, 1)).to.be.deep.eq([]);

      // add participants
      const [participantsPerm, participantsRot] = generateParticipants(10);

      const quorum = BigInt(80) * PRECISION;

      const tx = zkMultisigFactory.connect(alice).createMultisig(participantsPerm, participantsRot, quorum, salt);

      await expect(tx)
        .to.emit(zkMultisigFactory, "ZKMultisigCreated")
        .withArgs(multisigAddress, pointsToArray(participantsPerm), pointsToArray(participantsRot), quorum);

      expect(await zkMultisigFactory.isZKMultisig(multisigAddress)).to.be.eq(true);
      expect(await zkMultisigFactory.getZKMultisigsCount()).to.be.eq(1);
      expect(await zkMultisigFactory.getZKMultisigs(0, 1)).to.be.deep.eq([multisigAddress]);
    });
  });
});
