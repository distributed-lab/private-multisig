import { ethers, zkit } from "hardhat";
import { addPoint, Base8, mulPointEscalar, Point } from "@zk-kit/baby-jubjub";
import { poseidonHash } from "@/test/helpers/poseidon-hash";
import { ProposalCreation, Voting } from "@/generated-types/zkit";
import { IZKMultisig, ZKMultisigMock } from "@ethers-v6";
import { CartesianMerkleTree, ED256 } from "@/generated-types/ethers/contracts/ZKMultisig";
import ProofStructOutput = CartesianMerkleTree.ProofStructOutput;
import { randomBytes } from "crypto";
import APointStruct = ED256.APointStruct;

const proofSize = 40;
const inf: Point<bigint> = [0n, 1n];
const babyJubJubN = 2736030358979909402780800718157159386076813972158567259200215660948447373041n;

export function randomNumber() {
  return BigInt("0x" + randomBytes(32).toString("hex"));
}

export async function createProposal(
  zkMultisig: ZKMultisigMock,
  salt: bigint,
  content: IZKMultisig.ProposalContentStruct,
) {
  const proposalId = await zkMultisig.computeProposalId(content, salt);

  const challengeEncoded = ethers.AbiCoder.defaultAbiCoder().encode(
    ["uint256", "address", "uint256"],
    [(await ethers.provider.getNetwork()).chainId, await zkMultisig.getAddress(), proposalId],
  );

  const challenge = BigInt(ethers.keccak256(challengeEncoded));

  const cmtProof = await zkMultisig.getParticipantsCMTProof(encodePoint({ x: Base8[0], y: Base8[1] }), proofSize);

  const circuit: ProposalCreation = await zkit.getCircuit("ProposalCreation");

  const proof = await circuit.generateProof({
    cmtRoot: BigInt(cmtProof[0]),
    challenge,
    sk: 1,
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

  return await zkMultisig.create(content, salt, zkParams);
}

export async function vote(
  zkMultisig: ZKMultisigMock,
  sk1: bigint,
  sk2: bigint,
  proposalId: bigint,
  forVote: boolean = true,
  cmtProofRoot?: string,
  cmtProofs?: [ProofStructOutput, ProofStructOutput],
) {
  const pk1 = mulPointEscalar(Base8, sk1);
  const pk2 = mulPointEscalar(Base8, sk2);

  const cmtProof1 = cmtProofs
    ? cmtProofs[0]
    : await zkMultisig.getParticipantsCMTProof(encodePoint({ x: pk1[0], y: pk1[1] }), proofSize);
  const cmtProof2 = cmtProofs
    ? cmtProofs[1]
    : await zkMultisig.getParticipantsCMTProof(encodePoint({ x: pk2[0], y: pk2[1] }, 2), proofSize);

  const encryptionKey = await zkMultisig.getEncryptionKey(proposalId);

  const M = forVote ? Base8 : inf;

  const k = randomNumber() % babyJubJubN;
  const C1 = mulPointEscalar(Base8, k);
  const C2 = addPoint(M, mulPointEscalar(encryptionKey, k));

  const challenge = await zkMultisig.getProposalChallenge(proposalId);
  const h1 = poseidonHash(ethers.toBeHex(challenge, 32));
  const h2 = poseidonHash(h1);

  const decryptionKeyShare = (BigInt(h1) * sk1 + BigInt(h2) * sk2) % babyJubJubN;

  const keyNullifier = BigInt(poseidonHash(ethers.toBeHex(sk2, 32)));

  const cmtRoot = cmtProofRoot ?? cmtProof1[0];

  const rotationMsg = await zkMultisig.getRotationKDFMSGToSign(proposalId);

  // mock signature
  const newSk2 = (BigInt(rotationMsg) + sk2) % babyJubJubN;
  const newPk2 = mulPointEscalar(Base8, newSk2);

  const circuit: Voting = await zkit.getCircuit("Voting");

  const proof = await circuit.generateProof({
    encryptionKey,
    challenge,
    proposalId,
    cmtRoot: BigInt(cmtProof1[0]),
    sk1,
    sk2,
    newSk2,
    vote: M,
    k,
    decryptionKeyShare,
    siblings: [cmtProof1[1].map((h) => BigInt(h)), cmtProof2[1].map((h) => BigInt(h))],
    siblingsLength: [numberToArray(BigInt(cmtProof1[2]), proofSize), numberToArray(BigInt(cmtProof2[2]), proofSize)],
    directionBits: [
      parseNumberToBitsArray(BigInt(cmtProof1[3]), BigInt(cmtProof1[2]) / 2n, proofSize),
      parseNumberToBitsArray(BigInt(cmtProof2[3]), BigInt(cmtProof2[2]) / 2n, proofSize),
    ],
  });

  const pi_b = proof.proof.pi_b;
  const pub = proof.publicSignals;

  const zkParams: IZKMultisig.ZKParamsStruct = {
    a: [proof.proof.pi_a[0], proof.proof.pi_a[1]],
    b: [
      [pi_b[0][1], pi_b[0][0]],
      [pi_b[1][1], pi_b[1][0]],
    ],
    c: [proof.proof.pi_c[0], proof.proof.pi_c[1]],
  };

  const encodedVote = ethers.AbiCoder.defaultAbiCoder().encode(["tuple(uint256,uint256)[2]"], [[C1, C2]]);

  const rotationKey = {
    x: newPk2[0],
    y: newPk2[1],
  };

  const voteParams: IZKMultisig.VoteParamsStruct = {
    encryptedVote: encodedVote,
    decryptionKeyShare,
    keyNullifier,
    blinder: pub.blinder,
    cmtRoot,
    rotationKey,
    proofData: zkParams,
  };

  const tx = await zkMultisig.vote(voteParams);

  return {
    tx,
    decryptionKeyShare,
    vote: [C1, C2] as [[bigint, bigint], [bigint, bigint]],
    newSk2,
    newPk2,
  };
}

export function aggregateDecryptionKeyShares(keyShares: bigint[]) {
  let sum = 0n;

  for (let i = 0; i < keyShares.length; i++) {
    sum += keyShares[i];
  }

  return sum % babyJubJubN;
}

export function aggregateVotes(votes: [[bigint, bigint], [bigint, bigint]][]) {
  let sumC1 = inf;
  let sumC2 = inf;

  for (let i = 0; i < votes.length; i++) {
    sumC1 = addPoint(sumC1, votes[i][0]);
    sumC2 = addPoint(sumC2, votes[i][1]);
  }

  return [sumC1, sumC2];
}

export function aggregatePoints(points: [bigint, bigint][]) {
  let sum = inf;

  for (let i = 0; i < points.length; i++) {
    sum = addPoint(sum, points[i]);
  }

  return sum;
}

export function parseNumberToBitsArray(num: bigint, expectedPathLen: bigint, desiredProofSize: number): number[] {
  const binary = num.toString(2);

  let resultArr = Array<number>(desiredProofSize / 2).fill(0);

  let j = 0;
  for (let i = Math.abs(Number(expectedPathLen) - binary.length); i < Number(expectedPathLen); i++) {
    resultArr[i] = Number(binary[j]);

    j++;
  }

  return resultArr;
}

export function numberToArray(proofSiblingsLength: any, desiredProofSize: number) {
  let siblingsLength = Array<number>(desiredProofSize / 2).fill(0);

  for (let i = 0; i < proofSiblingsLength / 2n; i++) {
    siblingsLength[i] = 1;
  }

  return siblingsLength;
}

export function encodePoint(point: APointStruct, keyType: number = 1) {
  const x1 = ethers.toBeHex(point.x, 32).slice(2);
  const y1 = ethers.toBeHex(point.y, 32).slice(2);
  const typeHash = ethers.toBeHex(keyType, 32).slice(2);

  return poseidonHash("0x" + x1 + y1 + typeHash);
}

export function getBlinder(sk: bigint, proposalId: bigint) {
  const skHex = ethers.toBeHex(sk, 32).slice(2);
  const proposalIdHex = ethers.toBeHex(proposalId, 32).slice(2);

  return BigInt(poseidonHash("0x" + skHex + proposalIdHex));
}

export function pointsToArray(points: APointStruct[]) {
  return points.map(({ x, y }) => [x, y]);
}

export function arrayToPoints(arr: [bigint, bigint][]): APointStruct[] {
  return arr.map(([x, y]) => ({ x, y }));
}

export function generateParticipants(length: number) {
  const permanentKeys: APointStruct[] = [];
  const rotationKeys: APointStruct[] = [];

  let currentSk = 1;

  for (let i = 0; i < length; i++) {
    const permanentKey = mulPointEscalar(Base8, BigInt(currentSk++));
    permanentKeys.push({
      x: permanentKey[0],
      y: permanentKey[1],
    });

    const rotationKey = mulPointEscalar(Base8, BigInt(currentSk++));
    rotationKeys.push({
      x: rotationKey[0],
      y: rotationKey[1],
    });
  }

  return [permanentKeys, rotationKeys];
}

export function getCumulativeKeys(permanentPoints: APointStruct[], rotationPoints: APointStruct[]) {
  const sumPoints = (points: APointStruct[]): Point<bigint> => {
    return points.reduce<Point<bigint>>(
      (acc, p) => {
        const point: Point<bigint> = [BigInt(p.x), BigInt(p.y)];
        return addPoint(acc, point);
      },
      [0n, 1n],
    );
  };

  const permPointsSum = sumPoints(permanentPoints);
  const rotPointsSum = sumPoints(rotationPoints);

  return [permPointsSum, rotPointsSum];
}
