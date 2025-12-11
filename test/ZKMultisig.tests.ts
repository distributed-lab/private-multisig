import { expect } from "chai";
import { ZeroAddress } from "ethers";
import { ethers, zkit } from "hardhat";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

import { PRECISION, ZERO_ADDR } from "@/scripts/utils/constants";
import { Reverter } from "@/test/helpers/reverter";

import {
  IZKMultisig,
  ProposalCreationGroth16Verifier,
  VotingGroth16Verifier,
  ZKMultisigMock,
  ZKMultisigFactory,
} from "@ethers-v6";

import { addPoint, mulPointEscalar } from "@zk-kit/baby-jubjub";
import { ProposalCreation } from "@zkit";
import { CartesianMerkleTree, ED256 } from "@/generated-types/ethers/contracts/ZKMultisig";

import { getPoseidon, poseidonHash } from "./helpers";
import APointStruct = ED256.APointStruct;
import ProofStructOutput = CartesianMerkleTree.ProofStructOutput;
import {
  aggregateDecryptionKeyShares,
  aggregatePoints,
  aggregateVotes,
  arrayToPoints,
  createProposal,
  encodePoint,
  generateParticipants,
  getBlinder,
  getCumulativeKeys,
  numberToArray,
  parseNumberToBitsArray,
  pointsToArray,
  randomNumber,
  vote,
} from "@/test/helpers/zk-multisig";

type ProposalContent = IZKMultisig.ProposalContentStruct;

enum ProposalStatus {
  NONE,
  VOTING,
  ACCEPTED,
  REJECTED,
  EXECUTED,
}

describe("ZKMultisig", () => {
  const reverter = new Reverter();

  const MIN_QUORUM = BigInt(80) * PRECISION;

  const proofSize = 40;

  const randomZKParams: IZKMultisig.ZKParamsStruct = {
    a: [randomNumber(), randomNumber()],
    b: [
      [randomNumber(), randomNumber()],
      [randomNumber(), randomNumber()],
    ],
    c: [randomNumber(), randomNumber()],
  };

  let alice: SignerWithAddress;

  let creationVerifier: ProposalCreationGroth16Verifier;
  let votingVerifier: VotingGroth16Verifier;

  let zkMultisig: ZKMultisigMock;
  let zkMultisigFactory: ZKMultisigFactory;

  let initialParticipantsPerm: APointStruct[];
  let initialParticipantsRot: APointStruct[];

  let proposalContent: ProposalContent;

  before(async () => {
    [alice] = await ethers.getSigners();

    creationVerifier = await ethers.deployContract("ProposalCreationGroth16Verifier");
    votingVerifier = await ethers.deployContract("VotingGroth16Verifier");

    const zkMultisigImpl = await ethers.deployContract("ZKMultisigMock", {
      libraries: {
        PoseidonUnit1L: await (await getPoseidon(1)).getAddress(),
        PoseidonUnit3L: await (await getPoseidon(3)).getAddress(),
      },
    });

    zkMultisigFactory = await ethers.deployContract("ZKMultisigFactory");

    await zkMultisigFactory.initialize(
      await zkMultisigImpl.getAddress(),
      await creationVerifier.getAddress(),
      await votingVerifier.getAddress(),
    );

    const salt = randomNumber();
    [initialParticipantsPerm, initialParticipantsRot] = generateParticipants(5);

    // create multisig
    await zkMultisigFactory
      .connect(alice)
      .createMultisig(initialParticipantsPerm, initialParticipantsRot, MIN_QUORUM, salt);
    // get deployed proxy
    const address = await zkMultisigFactory.computeZKMultisigAddress(alice.address, salt);
    // attach proxy address to zkMultisig
    zkMultisig = zkMultisigImpl.attach(address) as ZKMultisigMock;

    // default proposal content
    proposalContent = {
      target: await zkMultisig.getAddress(),
      value: 0,
      data: "0x",
    };

    await reverter.snapshot();
  });

  afterEach(reverter.revert);

  describe("initialize", () => {
    it("should have correct initial state", async () => {
      expect(await zkMultisig.getParticipantsCMTRoot()).to.be.ok;

      expect(await zkMultisig.getParticipantsCount()).to.be.eq(initialParticipantsPerm.length);

      const expectedParticipants = [initialParticipantsPerm, initialParticipantsRot].map((keyArray) => {
        return keyArray.map((pointStruct) => {
          return [pointStruct.x, pointStruct.y];
        });
      });
      expect(await zkMultisig.getParticipants()).to.be.deep.eq(expectedParticipants);

      expect((await zkMultisig.getParticipantsCMTProof(encodePoint(initialParticipantsPerm[0]), proofSize)).existence)
        .to.be.true;
      expect((await zkMultisig.getParticipantsCMTProof(encodePoint(initialParticipantsRot[3], 2), proofSize)).existence)
        .to.be.true;
      expect((await zkMultisig.getParticipantsCMTProof(encodePoint({ x: 10n, y: 100n }), proofSize)).existence).to.be
        .false;

      expect(await zkMultisig.getProposalsCount()).to.be.eq(0);
      expect(await zkMultisig.getProposalsIds(0, 10)).to.be.deep.eq([]);

      expect(await zkMultisig.getQuorumPercentage()).to.be.eq(MIN_QUORUM);

      expect(await zkMultisig.getProposalsCount()).to.be.eq(0);
      expect(await zkMultisig.getCurrentProposalId()).to.be.eq(0);

      const [cumulativePermanentKey, cumulativeRotationKey] = getCumulativeKeys(
        initialParticipantsPerm,
        initialParticipantsRot,
      );
      expect(await zkMultisig.getCumulativePermanentKey()).to.be.deep.eq(cumulativePermanentKey);
      expect(await zkMultisig.getCumulativeRotationKey()).to.be.deep.eq(cumulativeRotationKey);

      expect(await zkMultisig.getCreationVerifier()).to.be.eq(await creationVerifier.getAddress());
      expect(await zkMultisig.getVotingVerifier()).to.be.eq(await votingVerifier.getAddress());
    });

    it("should not allow to initialize twice", async () => {
      await expect(
        zkMultisig.initialize(
          initialParticipantsPerm,
          initialParticipantsRot,
          MIN_QUORUM,
          creationVerifier,
          votingVerifier,
        ),
      ).to.be.revertedWithCustomError(zkMultisig, "InvalidInitialization");
    });

    it("should not allow to call proposals functions directly", async () => {
      const [permanentKeys, rotationKeys] = generateParticipants(3);

      await expect(zkMultisig.addParticipants(permanentKeys, rotationKeys)).to.be.revertedWithCustomError(
        zkMultisig,
        "NotAuthorizedCall",
      );

      await expect(zkMultisig.removeParticipants(permanentKeys)).to.be.revertedWithCustomError(
        zkMultisig,
        "NotAuthorizedCall",
      );

      await expect(zkMultisig.updateQuorumPercentage(MIN_QUORUM)).to.be.revertedWithCustomError(
        zkMultisig,
        "NotAuthorizedCall",
      );

      await expect(zkMultisig.updateCreationVerifier(ZERO_ADDR)).to.be.revertedWithCustomError(
        zkMultisig,
        "NotAuthorizedCall",
      );

      await expect(zkMultisig.updateVotingVerifier(ZERO_ADDR)).to.be.revertedWithCustomError(
        zkMultisig,
        "NotAuthorizedCall",
      );
    });
  });

  describe("addParticipants", () => {
    it("should add participants correctly", async () => {
      const initialCMTRoot = await zkMultisig.getParticipantsCMTRoot();

      const newPermanentPoints = [
        { x: 5, y: 6 },
        { x: 12, y: 24 },
      ];
      const newRotationPoints = [
        { x: 7, y: 8 },
        { x: 13, y: 26 },
      ];

      const tx = await zkMultisig.addParticipantsExternal(newPermanentPoints, newRotationPoints);

      await expect(tx).to.emit(zkMultisig, "ParticipantAdded").withArgs([5, 6], [7, 8]);
      await expect(tx).to.emit(zkMultisig, "ParticipantAdded").withArgs([12, 24], [13, 26]);

      expect(await zkMultisig.getParticipantsCount()).to.be.eq(7);
      expect(await zkMultisig.getParticipantsCMTRoot()).not.to.be.eq(initialCMTRoot);

      const participants = await zkMultisig.getParticipants();
      expect(participants[0][5]).to.be.deep.eq([5, 6]);
      expect(participants[1][5]).to.be.deep.eq([7, 8]);
      expect(participants[0][6]).to.be.deep.eq([12, 24]);
      expect(participants[1][6]).to.be.deep.eq([13, 26]);

      const [cumulativePermanentKey, cumulativeRotationKey] = getCumulativeKeys(
        [...initialParticipantsPerm, ...newPermanentPoints],
        [...initialParticipantsRot, ...newRotationPoints],
      );
      expect(await zkMultisig.getCumulativePermanentKey()).to.be.deep.eq(cumulativePermanentKey);
      expect(await zkMultisig.getCumulativeRotationKey()).to.be.deep.eq(cumulativeRotationKey);
    });

    it("should revert if msg.sender is not ZKMultisig", async () => {
      await expect(zkMultisig.addParticipants([], [])).to.be.revertedWithCustomError(zkMultisig, "NotAuthorizedCall");
    });

    it("should revert if no participants are provided", async () => {
      await expect(zkMultisig.addParticipantsExternal([], [])).to.be.revertedWithCustomError(
        zkMultisig,
        "NoParticipantsToProcess",
      );
    });

    it("should revert if arrays with different length are provided", async () => {
      await expect(
        zkMultisig.addParticipantsExternal(
          [
            { x: 1, y: 1 },
            { x: 2, y: 2 },
          ],
          [{ x: 3, y: 3 }],
        ),
      ).to.be.revertedWithCustomError(zkMultisig, "KeyLenMismatch");
    });

    it("should not add participant keys that are already added", async () => {
      await zkMultisig.addParticipantsExternal(
        [
          { x: 1, y: 1 },
          { x: 1, y: 1 },
        ],
        [
          { x: 3, y: 3 },
          { x: 2, y: 1 },
        ],
      );

      expect(await zkMultisig.getParticipantsCount()).to.be.eq(6);
    });
  });

  describe("removeParticipants", () => {
    it("should remove participants correctly", async () => {
      const initialCMTRoot = await zkMultisig.getParticipantsCMTRoot();

      const tx = await zkMultisig.removeParticipantsExternal([initialParticipantsPerm[0], initialParticipantsPerm[2]]);

      await expect(tx)
        .to.emit(zkMultisig, "ParticipantRemoved")
        .withArgs([initialParticipantsPerm[0].x, initialParticipantsPerm[0].y]);
      await expect(tx)
        .to.emit(zkMultisig, "ParticipantRemoved")
        .withArgs([initialParticipantsPerm[2].x, initialParticipantsPerm[2].y]);

      expect(await zkMultisig.getParticipantsCount()).to.be.eq(3);
      expect(await zkMultisig.getParticipantsCMTRoot()).not.to.be.eq(initialCMTRoot);

      const participants = await zkMultisig.getParticipants();
      const initialParticipantsPermArr = pointsToArray(initialParticipantsPerm);

      for (const [j, key] of initialParticipantsPermArr.entries()) {
        const foundKey = participants[0].some((item) => item.every((v, i) => v === key[i]));

        const shouldExist = ![0, 2].includes(j);
        expect(foundKey).to.equal(shouldExist);
      }

      const [, cumulativeRotationKey] = getCumulativeKeys(initialParticipantsPerm, initialParticipantsRot);
      const [cumulativePermanentKey] = getCumulativeKeys(
        initialParticipantsPerm.filter((_, i) => ![0, 2].includes(i)),
        initialParticipantsRot,
      );
      expect(await zkMultisig.getCumulativePermanentKey()).to.be.deep.eq(cumulativePermanentKey);
      expect(await zkMultisig.getCumulativeRotationKey()).to.be.deep.eq(cumulativeRotationKey);
    });

    it("should revert if msg.sender is not ZKMultisig", async () => {
      await expect(zkMultisig.removeParticipants([])).to.be.revertedWithCustomError(zkMultisig, "NotAuthorizedCall");
    });

    it("should revert if no participants are provided", async () => {
      await expect(zkMultisig.removeParticipantsExternal([])).to.be.revertedWithCustomError(
        zkMultisig,
        "NoParticipantsToProcess",
      );
    });

    it("should revert if removing all participants", async () => {
      await expect(zkMultisig.removeParticipantsExternal(initialParticipantsPerm)).to.be.revertedWithCustomError(
        zkMultisig,
        "RemovingAllParticipants",
      );
    });

    it("should not remove participant keys that don't exist", async () => {
      const keysToRemove = [{ x: 1, y: 2 }];

      const removeParticipantsData = zkMultisig.interface.encodeFunctionData("removeParticipants", [keysToRemove]);

      const proposalContent = {
        target: await zkMultisig.getAddress(),
        value: 0,
        data: removeParticipantsData,
      };

      const salt = randomNumber();

      const proposalId = await zkMultisig.computeProposalId(proposalContent, salt);

      await createProposal(zkMultisig, salt, proposalContent);

      await vote(zkMultisig, 5n, 6n, proposalId);
      await vote(zkMultisig, 1n, 2n, proposalId);
      await vote(zkMultisig, 3n, 4n, proposalId);
      await vote(zkMultisig, 9n, 10n, proposalId, false);
      await vote(zkMultisig, 7n, 8n, proposalId);

      const tx = await zkMultisig.revealAndExecute(4);

      await expect(tx).not.to.emit(zkMultisig, "ParticipantRemoved");
    });
  });

  describe("updateQuorumPercentage", () => {
    it("should update quorum percentage correctly", async () => {
      const newQuorum = BigInt(50) * PRECISION;

      const updateQuorumPercentageData = zkMultisig.interface.encodeFunctionData("updateQuorumPercentage", [newQuorum]);

      const proposalContent = {
        target: await zkMultisig.getAddress(),
        value: 0,
        data: updateQuorumPercentageData,
      };

      const salt = randomNumber();

      const proposalId = await zkMultisig.computeProposalId(proposalContent, salt);

      await createProposal(zkMultisig, salt, proposalContent);

      await vote(zkMultisig, 5n, 6n, proposalId, false);
      await vote(zkMultisig, 1n, 2n, proposalId);
      await vote(zkMultisig, 3n, 4n, proposalId);
      await vote(zkMultisig, 9n, 10n, proposalId);
      await vote(zkMultisig, 7n, 8n, proposalId);

      await zkMultisig.revealAndExecute(4);

      expect(await zkMultisig.getQuorumPercentage()).to.be.eq(newQuorum);
      expect(await zkMultisig.getRequiredQuorum()).to.be.eq(2);
    });

    it("should revert if quorum percentage value is invalid", async () => {
      await expect(zkMultisig.updateQuorumPercentageExternal(0))
        .to.be.revertedWithCustomError(zkMultisig, "InvalidQuorum")
        .withArgs(0);
      await expect(zkMultisig.updateQuorumPercentageExternal(110n * PRECISION))
        .to.be.revertedWithCustomError(zkMultisig, "InvalidQuorum")
        .withArgs(110n * PRECISION);
      await expect(zkMultisig.updateQuorumPercentageExternal(MIN_QUORUM))
        .to.be.revertedWithCustomError(zkMultisig, "InvalidQuorum")
        .withArgs(MIN_QUORUM);
    });

    it("should revert if msg.sender is not ZKMultisig", async () => {
      await expect(zkMultisig.updateQuorumPercentage(60n * PRECISION)).to.be.revertedWithCustomError(
        zkMultisig,
        "NotAuthorizedCall",
      );
    });
  });

  describe("updateVerifier", () => {
    it("should update verifiers correctly", async () => {
      const updateCreationVerifierData = zkMultisig.interface.encodeFunctionData("updateCreationVerifier", [
        await zkMultisigFactory.getAddress(),
      ]);
      const updateVotingVerifierData = zkMultisig.interface.encodeFunctionData("updateVotingVerifier", [
        await zkMultisigFactory.getAddress(),
      ]);

      const proposalContentCreation = {
        target: await zkMultisig.getAddress(),
        value: 0,
        data: updateCreationVerifierData,
      };
      const proposalContentVoting = {
        target: await zkMultisig.getAddress(),
        value: 0,
        data: updateVotingVerifierData,
      };

      let salt = randomNumber();

      let proposalId = await zkMultisig.computeProposalId(proposalContentCreation, salt);

      await createProposal(zkMultisig, salt, proposalContentCreation);

      const v1 = await vote(zkMultisig, 1n, 2n, proposalId);
      const v2 = await vote(zkMultisig, 7n, 8n, proposalId);
      const v3 = await vote(zkMultisig, 3n, 4n, proposalId);
      const v4 = await vote(zkMultisig, 9n, 10n, proposalId);
      const v5 = await vote(zkMultisig, 5n, 6n, proposalId);

      await zkMultisig.revealAndExecute(5);

      expect(await zkMultisig.getCreationVerifier()).to.be.eq(await zkMultisigFactory.getAddress());

      await zkMultisig.updateVerifierExternal(creationVerifier, true);

      salt = randomNumber();

      proposalId = await zkMultisig.computeProposalId(proposalContentVoting, salt);

      await createProposal(zkMultisig, salt, proposalContentVoting);

      await vote(zkMultisig, 1n, v1.newSk2, proposalId, false);
      await vote(zkMultisig, 7n, v2.newSk2, proposalId);
      await vote(zkMultisig, 3n, v3.newSk2, proposalId);
      await vote(zkMultisig, 9n, v4.newSk2, proposalId);
      await vote(zkMultisig, 5n, v5.newSk2, proposalId);

      await zkMultisig.reveal(4);
      await zkMultisig.execute(proposalId);

      expect(await zkMultisig.getVotingVerifier()).to.be.eq(await zkMultisigFactory.getAddress());
    });

    it("should revert if invalid verifier address is provided", async () => {
      const [signer] = await ethers.getSigners();

      await expect(zkMultisig.updateVerifierExternal(ZeroAddress, true)).to.be.revertedWithCustomError(
        zkMultisig,
        "ZeroVerifier",
      );
      await expect(zkMultisig.updateVerifierExternal(creationVerifier, true)).to.be.revertedWithCustomError(
        zkMultisig,
        "DuplicateVerifier",
      );
      await expect(zkMultisig.updateVerifierExternal(votingVerifier, false)).to.be.revertedWithCustomError(
        zkMultisig,
        "DuplicateVerifier",
      );
      await expect(zkMultisig.updateVerifierExternal(signer, false))
        .to.be.revertedWithCustomError(zkMultisig, "NotAContract")
        .withArgs(signer.address);
    });

    it("should revert if msg.sender is not ZKMultisig", async () => {
      await expect(zkMultisig.updateCreationVerifier(zkMultisigFactory)).to.be.revertedWithCustomError(
        zkMultisig,
        "NotAuthorizedCall",
      );
      await expect(zkMultisig.updateVotingVerifier(zkMultisigFactory)).to.be.revertedWithCustomError(
        zkMultisig,
        "NotAuthorizedCall",
      );
    });
  });

  describe("create", () => {
    it("should create proposal correctly", async () => {
      const salt = randomNumber();

      const proposalId = await zkMultisig.computeProposalId(proposalContent, salt);

      expect(await zkMultisig.getProposalStatus(proposalId)).to.be.eq(ProposalStatus.NONE);

      const tx = await createProposal(zkMultisig, salt, proposalContent);

      expect(tx).to.emit(zkMultisig, "ProposalCreated").withArgs(proposalId, proposalContent);

      expect((await zkMultisig.getParticipants())[1]).to.be.empty;
      expect(await zkMultisig.getCumulativeRotationKey()).to.be.deep.eq([0, 1]);

      expect(await zkMultisig.getCurrentProposalId()).to.be.eq(proposalId);
      expect(await zkMultisig.getProposalsCount()).to.be.eq(1);
      expect(await zkMultisig.getProposalsIds(0, 100)).to.be.deep.eq([proposalId]);
      expect(await zkMultisig.getProposalStatus(proposalId)).to.be.eq(ProposalStatus.VOTING);
      expect(await zkMultisig.getProposalInfo(proposalId)).to.be.deep.eq([
        [proposalContent.target, proposalContent.value, proposalContent.data],
        1,
        0,
        4,
      ]);

      const challenge = await zkMultisig.getProposalChallenge(proposalId);
      const h1 = poseidonHash(ethers.toBeHex(challenge, 32));
      const h2 = poseidonHash(h1);

      const [cumulativePermanentKey, cumulativeRotationKey] = getCumulativeKeys(
        initialParticipantsPerm,
        initialParticipantsRot,
      );
      const expectedEncryptionKey = addPoint(
        mulPointEscalar(cumulativePermanentKey, BigInt(h1)),
        mulPointEscalar(cumulativeRotationKey, BigInt(h2)),
      );
      expect(await zkMultisig.getEncryptionKey(proposalId)).to.be.deep.eq(expectedEncryptionKey);
    });

    it("should revert if the provided target is zero address", async () => {
      const proposalContent = {
        target: ethers.ZeroAddress,
        value: 0,
        data: "0x",
      };

      await expect(zkMultisig.create(proposalContent, randomNumber(), randomZKParams)).to.be.revertedWithCustomError(
        zkMultisig,
        "ZeroTarget",
      );
    });

    it("should revert if proposal with the same proposal ID exists", async () => {
      const salt = randomNumber();

      const proposalId = await zkMultisig.computeProposalId(proposalContent, salt);

      await createProposal(zkMultisig, salt, proposalContent);

      await zkMultisig.deactivateProposal(proposalId);

      await expect(zkMultisig.create(proposalContent, salt, randomZKParams))
        .to.be.revertedWithCustomError(zkMultisig, "ProposalExists")
        .withArgs(proposalId);
    });

    it("should revert if active proposal already exists", async () => {
      const salt = randomNumber();

      const proposalId = await zkMultisig.computeProposalId(proposalContent, salt);

      await createProposal(zkMultisig, salt, proposalContent);

      await expect(zkMultisig.create(proposalContent, salt, randomZKParams))
        .to.be.revertedWithCustomError(zkMultisig, "ActiveProposal")
        .withArgs(proposalId);
    });

    it("should revert if invalid zk params are provided", async () => {
      const salt = randomNumber();

      const proposalId = await zkMultisig.computeProposalId(proposalContent, salt);

      const cmtProof = await zkMultisig.getParticipantsCMTProof(encodePoint(initialParticipantsPerm[1]), proofSize);

      const circuit: ProposalCreation = await zkit.getCircuit("ProposalCreation");

      const proof = await circuit.generateProof({
        cmtRoot: BigInt(cmtProof[0]),
        challenge: proposalId,
        sk: 3,
        siblings: cmtProof[1].map((h) => BigInt(h)),
        siblingsLength: numberToArray(BigInt(cmtProof[2]), proofSize),
        directionBits: parseNumberToBitsArray(BigInt(cmtProof[3]), BigInt(cmtProof[2]) / 2n, proofSize),
      });

      const pi_b = proof.proof.pi_b;

      const zkParams: IZKMultisig.ZKParamsStruct = {
        a: [proof.proof.pi_a[0], proof.proof.pi_a[1]],
        b: [
          [pi_b[0][1], pi_b[0][0]],
          [pi_b[1][1], pi_b[1][0]],
        ],
        c: [proof.proof.pi_c[0], proof.proof.pi_c[1]],
      };

      zkParams.b[0][0] = pi_b[0][0];
      await expect(zkMultisig.create(proposalContent, salt, zkParams)).to.be.revertedWithCustomError(
        zkMultisig,
        "InvalidProof",
      );
    });
  });

  describe("vote", () => {
    it("should vote on the proposal correctly", async () => {
      const salt = randomNumber();

      const proposalId = await zkMultisig.computeProposalId(proposalContent, salt);

      await createProposal(zkMultisig, salt, proposalContent);

      const initialCMTRoot = await zkMultisig.getParticipantsCMTRoot();

      const cmtProof1: ProofStructOutput = await zkMultisig.getParticipantsCMTProof(
        encodePoint(initialParticipantsPerm[4]),
        proofSize,
      );
      const cmtProof2: ProofStructOutput = await zkMultisig.getParticipantsCMTProof(
        encodePoint(initialParticipantsRot[4], 2),
        proofSize,
      );

      // first vote
      const keyNullifier1 = BigInt(poseidonHash(ethers.toBeHex(2n, 32)));
      const blinder1 = getBlinder(1n, proposalId);

      expect(await zkMultisig.isRotationKeyNullifierUsed(keyNullifier1)).to.be.false;

      const v1 = await vote(zkMultisig, 1n, 2n, proposalId);

      expect(v1.tx).to.emit(zkMultisig, "ProposalVoted").withArgs(proposalId, blinder1);

      expect(await zkMultisig.isRotationKeyNullifierUsed(keyNullifier1)).to.be.true;
      expect(await zkMultisig.getProposalInfo(proposalId)).to.be.deep.eq([
        [proposalContent.target, proposalContent.value, proposalContent.data],
        1,
        1,
        4,
      ]);
      expect(await zkMultisig.getProposalBlinders(proposalId)).to.be.deep.eq([blinder1]);
      expect(await zkMultisig.getProposalDecryptionKey(proposalId)).to.be.eq(v1.decryptionKeyShare);
      expect(await zkMultisig.getProposalAggregatedVotes(proposalId)).to.be.deep.eq(v1.vote);

      let participants = await zkMultisig.getParticipants();
      expect(await zkMultisig.getParticipantsCMTRoot()).not.to.be.eq(initialCMTRoot);
      expect(await zkMultisig.getParticipantsCount()).to.be.eq(5);
      expect(participants[0].length).to.be.eq(5);
      expect(participants[1].length).to.be.eq(1);
      expect(participants[1]).to.be.deep.eq([v1.newPk2]);

      let [cumulativePermanentKey] = getCumulativeKeys(initialParticipantsPerm, initialParticipantsRot);
      expect(await zkMultisig.getCumulativePermanentKey()).to.be.deep.eq(cumulativePermanentKey);
      expect(await zkMultisig.getCumulativeRotationKey()).to.be.deep.eq(v1.newPk2);

      // other votes
      const v2 = await vote(zkMultisig, 5n, 6n, proposalId);
      const v3 = await vote(zkMultisig, 9n, 10n, proposalId, false, initialCMTRoot, [cmtProof1, cmtProof2]);
      const v4 = await vote(zkMultisig, 3n, 4n, proposalId);

      const blinder2 = getBlinder(5n, proposalId);
      const blinder3 = getBlinder(9n, proposalId);
      const blinder4 = getBlinder(3n, proposalId);

      const keyNullifier2 = BigInt(poseidonHash(ethers.toBeHex(6n, 32)));
      const keyNullifier3 = BigInt(poseidonHash(ethers.toBeHex(10n, 32)));
      const keyNullifier4 = BigInt(poseidonHash(ethers.toBeHex(4n, 32)));

      expect(v2.tx).to.emit(zkMultisig, "ProposalVoted").withArgs(proposalId, blinder2);
      expect(v3.tx).to.emit(zkMultisig, "ProposalVoted").withArgs(proposalId, blinder3);
      expect(v4.tx).to.emit(zkMultisig, "ProposalVoted").withArgs(proposalId, blinder4);

      expect(await zkMultisig.isRotationKeyNullifierUsed(keyNullifier2)).to.be.true;
      expect(await zkMultisig.isRotationKeyNullifierUsed(keyNullifier3)).to.be.true;
      expect(await zkMultisig.isRotationKeyNullifierUsed(keyNullifier4)).to.be.true;
      expect(await zkMultisig.getProposalInfo(proposalId)).to.be.deep.eq([
        [proposalContent.target, proposalContent.value, proposalContent.data],
        1,
        4,
        4,
      ]);
      expect(await zkMultisig.getProposalBlinders(proposalId)).to.be.deep.eq([blinder1, blinder2, blinder3, blinder4]);
      expect(await zkMultisig.getProposalDecryptionKey(proposalId)).to.be.eq(
        aggregateDecryptionKeyShares([
          v1.decryptionKeyShare,
          v2.decryptionKeyShare,
          v3.decryptionKeyShare,
          v4.decryptionKeyShare,
        ]),
      );
      expect(await zkMultisig.getProposalAggregatedVotes(proposalId)).to.be.deep.eq(
        aggregateVotes([v1.vote, v2.vote, v3.vote, v4.vote]),
      );

      participants = await zkMultisig.getParticipants();
      expect(await zkMultisig.getParticipantsCount()).to.be.eq(5);
      expect(participants[0].length).to.be.eq(5);
      expect(participants[1].length).to.be.eq(4);
      expect(participants[1]).to.be.deep.eq([v1.newPk2, v2.newPk2, v3.newPk2, v4.newPk2]);

      [cumulativePermanentKey] = getCumulativeKeys(initialParticipantsPerm, initialParticipantsRot);
      expect(await zkMultisig.getCumulativePermanentKey()).to.be.deep.eq(cumulativePermanentKey);
      expect(await zkMultisig.getCumulativeRotationKey()).to.be.deep.eq(
        aggregatePoints([v1.newPk2, v2.newPk2, v3.newPk2, v4.newPk2]),
      );
    });

    it("should revert if proposal is not in the voting status", async () => {
      const invalidProposalId = randomNumber();

      await expect(vote(zkMultisig, 1n, 2n, invalidProposalId))
        .to.be.revertedWithCustomError(zkMultisig, "NotVoting")
        .withArgs(0);
    });

    it("should revert if using already rotated pk2", async () => {
      const salt = randomNumber();

      const proposalId = await zkMultisig.computeProposalId(proposalContent, salt);

      await createProposal(zkMultisig, salt, proposalContent);

      await vote(zkMultisig, 3n, 4n, proposalId);

      await expect(vote(zkMultisig, 3n, 4n, proposalId, false))
        .to.be.revertedWithCustomError(zkMultisig, "UsedNullifier")
        .withArgs(BigInt(poseidonHash(ethers.toBeHex(4n, 32))));
    });

    it("should revert if the same user tries to vote twice", async () => {
      const salt = randomNumber();

      const proposalId = await zkMultisig.computeProposalId(proposalContent, salt);

      await createProposal(zkMultisig, salt, proposalContent);

      await vote(zkMultisig, 3n, 4n, proposalId);

      const blinder = getBlinder(3n, proposalId);

      const encodedVote = ethers.AbiCoder.defaultAbiCoder().encode(
        ["tuple(uint256,uint256)[2]"],
        [
          [
            [10n, 20n],
            [30n, 40n],
          ],
        ],
      );

      const voteParams = {
        encryptedVote: encodedVote,
        decryptionKeyShare: 100,
        keyNullifier: 100,
        blinder,
        cmtRoot: await zkMultisig.getParticipantsCMTRoot(),
        rotationKey: { x: 10, y: 20 },
        proofData: randomZKParams,
      };

      await expect(zkMultisig.vote(voteParams))
        .to.be.revertedWithCustomError(zkMultisig, "UsedBlinder")
        .withArgs(blinder);
    });

    it("should revert if invalid CMT root is provided", async () => {
      const salt = randomNumber();

      const proposalId = await zkMultisig.computeProposalId(proposalContent, salt);

      await createProposal(zkMultisig, salt, proposalContent);

      await vote(zkMultisig, 3n, 4n, proposalId);

      const invalidRoot = ethers.toBeHex(randomNumber(), 32);

      await expect(vote(zkMultisig, 5n, 6n, proposalId, false, invalidRoot))
        .to.be.revertedWithCustomError(zkMultisig, "InvalidCMTRoot")
        .withArgs(invalidRoot);
    });

    it("should revert if invalid zk params are provided", async () => {
      const salt = randomNumber();

      await createProposal(zkMultisig, salt, proposalContent);

      const encodedVote = ethers.AbiCoder.defaultAbiCoder().encode(
        ["tuple(uint256,uint256)[2]"],
        [
          [
            [1n, 2n],
            [3n, 4n],
          ],
        ],
      );

      const voteParams = {
        encryptedVote: encodedVote,
        decryptionKeyShare: 100,
        keyNullifier: 100,
        blinder: 100,
        cmtRoot: await zkMultisig.getParticipantsCMTRoot(),
        rotationKey: { x: 10, y: 20 },
        proofData: randomZKParams,
      };

      await expect(zkMultisig.vote(voteParams)).to.be.revertedWithCustomError(zkMultisig, "InvalidProof");
    });
  });

  describe("reveal", () => {
    it("should reveal votes correctly", async () => {
      let salt = randomNumber();

      let proposalId = await zkMultisig.computeProposalId(proposalContent, salt);

      await createProposal(zkMultisig, salt, proposalContent);

      const v1 = await vote(zkMultisig, 5n, 6n, proposalId);
      const v2 = await vote(zkMultisig, 1n, 2n, proposalId, false);
      const v3 = await vote(zkMultisig, 3n, 4n, proposalId);
      const v4 = await vote(zkMultisig, 9n, 10n, proposalId);
      const v5 = await vote(zkMultisig, 7n, 8n, proposalId);

      let tx = await zkMultisig.reveal(4);

      await expect(tx).to.emit(zkMultisig, "ProposalRevealed").withArgs(proposalId, true);

      expect(await zkMultisig.getProposalStatus(proposalId)).to.be.eq(ProposalStatus.ACCEPTED);

      salt = randomNumber();

      proposalId = await zkMultisig.computeProposalId(proposalContent, salt);

      await createProposal(zkMultisig, salt, proposalContent);

      await vote(zkMultisig, 5n, v1.newSk2, proposalId, false);
      await vote(zkMultisig, 1n, v2.newSk2, proposalId, false);
      await vote(zkMultisig, 3n, v3.newSk2, proposalId);
      await vote(zkMultisig, 9n, v4.newSk2, proposalId, false);
      await vote(zkMultisig, 7n, v5.newSk2, proposalId);

      tx = await zkMultisig.reveal(2);

      await expect(tx).to.emit(zkMultisig, "ProposalRevealed").withArgs(proposalId, false);

      expect(await zkMultisig.getProposalStatus(proposalId)).to.be.eq(ProposalStatus.REJECTED);
    });

    it("should revert if the provided approvalVoteCount is incorrect or not everyone has voted", async () => {
      let salt = randomNumber();

      let proposalId = await zkMultisig.computeProposalId(proposalContent, salt);

      await createProposal(zkMultisig, salt, proposalContent);

      await vote(zkMultisig, 1n, 2n, proposalId, false);
      await vote(zkMultisig, 3n, 4n, proposalId);
      await vote(zkMultisig, 9n, 10n, proposalId);
      await vote(zkMultisig, 7n, 8n, proposalId);

      await expect(zkMultisig.reveal(3)).to.be.revertedWithCustomError(zkMultisig, "VoteCountMismatch");

      await vote(zkMultisig, 5n, 6n, proposalId);

      await expect(zkMultisig.reveal(3)).to.be.revertedWithCustomError(zkMultisig, "VoteCountMismatch");
    });
  });

  describe("execute", () => {
    it("should execute proposal correctly", async () => {
      const newPermanentPoints = [
        { x: 1, y: 11 },
        { x: 3, y: 33 },
      ];
      const newRotationPoints = [
        { x: 2, y: 22 },
        { x: 4, y: 44 },
      ];

      const addParticipantsData = zkMultisig.interface.encodeFunctionData("addParticipants", [
        newPermanentPoints,
        newRotationPoints,
      ]);

      const proposalContent = {
        target: await zkMultisig.getAddress(),
        value: 0,
        data: addParticipantsData,
      };

      const salt = randomNumber();

      const proposalId = await zkMultisig.computeProposalId(proposalContent, salt);

      await createProposal(zkMultisig, salt, proposalContent);

      const v1 = await vote(zkMultisig, 5n, 6n, proposalId);
      const v2 = await vote(zkMultisig, 1n, 2n, proposalId);
      const v3 = await vote(zkMultisig, 3n, 4n, proposalId);
      const v4 = await vote(zkMultisig, 9n, 10n, proposalId, false);
      const v5 = await vote(zkMultisig, 7n, 8n, proposalId);

      await zkMultisig.reveal(4);

      const tx = await zkMultisig.execute(proposalId);

      await expect(tx).to.emit(zkMultisig, "ProposalExecuted").withArgs(proposalId);
      await expect(tx).to.emit(zkMultisig, "ParticipantAdded").withArgs([1, 11], [2, 22]);
      await expect(tx).to.emit(zkMultisig, "ParticipantAdded").withArgs([3, 33], [4, 44]);

      expect(await zkMultisig.getProposalStatus(proposalId)).to.be.eq(ProposalStatus.EXECUTED);
      expect(await zkMultisig.getParticipantsCount()).to.be.eq(7);

      const participants = await zkMultisig.getParticipants();
      expect(participants[0][5]).to.be.deep.eq([1, 11]);
      expect(participants[1][5]).to.be.deep.eq([2, 22]);
      expect(participants[0][6]).to.be.deep.eq([3, 33]);
      expect(participants[1][6]).to.be.deep.eq([4, 44]);

      const [cumulativePermanentKey, cumulativeRotationKey] = getCumulativeKeys(
        [...initialParticipantsPerm, ...newPermanentPoints],
        [...arrayToPoints([v1.newPk2, v2.newPk2, v3.newPk2, v4.newPk2, v5.newPk2]), ...newRotationPoints],
      );
      expect(await zkMultisig.getCumulativePermanentKey()).to.be.deep.eq(cumulativePermanentKey);
      expect(await zkMultisig.getCumulativeRotationKey()).to.be.deep.eq(cumulativeRotationKey);
    });

    it("should execute proposal with value correctly", async () => {
      await (
        await ethers.getSigners()
      )[0].sendTransaction({
        to: await zkMultisig.getAddress(),
        value: ethers.parseEther("1"),
      });

      const ethReceiver = await ethers.deployContract("EthReceiverMock");

      const proposalContent = {
        target: await ethReceiver.getAddress(),
        value: ethers.parseEther("1"),
        data: "0x",
      };

      const salt = randomNumber();

      const proposalId = await zkMultisig.computeProposalId(proposalContent, salt);

      await createProposal(zkMultisig, salt, proposalContent);

      await vote(zkMultisig, 1n, 2n, proposalId);
      await vote(zkMultisig, 7n, 8n, proposalId);
      await vote(zkMultisig, 5n, 6n, proposalId);
      await vote(zkMultisig, 9n, 10n, proposalId);
      await vote(zkMultisig, 3n, 4n, proposalId);

      await zkMultisig.reveal(5);

      const tx = await zkMultisig.execute(proposalId, { value: ethers.parseEther("1") });

      await expect(tx).to.emit(zkMultisig, "ProposalExecuted").withArgs(proposalId);
      await expect(tx)
        .to.emit(ethReceiver, "ReceivedEth")
        .withArgs(await zkMultisig.getAddress(), ethers.parseEther("1"));
    });

    it("should revert if the proposal is not accepted", async () => {
      const invalidProposalId = randomNumber();

      await expect(zkMultisig.execute(invalidProposalId))
        .to.be.revertedWithCustomError(zkMultisig, "ProposalNotAccepted")
        .withArgs(invalidProposalId);

      const salt = randomNumber();

      const proposalId = await zkMultisig.computeProposalId(proposalContent, salt);

      await createProposal(zkMultisig, salt, proposalContent);

      await vote(zkMultisig, 1n, 2n, proposalId);
      await vote(zkMultisig, 7n, 8n, proposalId, false);
      await vote(zkMultisig, 5n, 6n, proposalId, false);
      await vote(zkMultisig, 9n, 10n, proposalId);
      await vote(zkMultisig, 3n, 4n, proposalId);

      await expect(zkMultisig.execute(proposalId))
        .to.be.revertedWithCustomError(zkMultisig, "ProposalNotAccepted")
        .withArgs(proposalId);

      await zkMultisig.reveal(3);

      await expect(zkMultisig.execute(proposalId))
        .to.be.revertedWithCustomError(zkMultisig, "ProposalNotAccepted")
        .withArgs(proposalId);
    });

    it("should revert if invalid value is provided", async () => {
      const proposalContent = {
        target: await zkMultisigFactory.getAddress(),
        value: ethers.parseEther("1"),
        data: "0x",
      };

      const salt = randomNumber();

      const proposalId = await zkMultisig.computeProposalId(proposalContent, salt);

      await createProposal(zkMultisig, salt, proposalContent);

      await vote(zkMultisig, 1n, 2n, proposalId);
      await vote(zkMultisig, 7n, 8n, proposalId);
      await vote(zkMultisig, 5n, 6n, proposalId, false);
      await vote(zkMultisig, 9n, 10n, proposalId);
      await vote(zkMultisig, 3n, 4n, proposalId);

      await zkMultisig.reveal(4);

      await expect(zkMultisig.execute(proposalId))
        .to.be.revertedWithCustomError(zkMultisig, "InvalidValue")
        .withArgs(0, ethers.parseEther("1"));
      await expect(zkMultisig.execute(proposalId, { value: ethers.parseEther("0.5") }))
        .to.be.revertedWithCustomError(zkMultisig, "InvalidValue")
        .withArgs(ethers.parseEther("0.5"), ethers.parseEther("1"));
    });
  });
});
