pragma circom 2.1.6;

include "./babyjubjub/babyjub.circom";
include "../node_modules/@solarity/circom-lib/data-structures/CartesianMerkleTree.circom";
include "../node_modules/@solarity/circom-lib/hasher/poseidon/poseidon.circom";

template ProposalCreation(proofSize) {
    signal input cmtRoot;
    signal input proposalId; // TODO constraint

    signal input sk1;
    signal input sk2;

    signal input siblings[2][proofSize];
    signal input siblingsLength[2][proofSize/2];
    signal input directionBits[2][proofSize/2];
    signal input nonExistenceKey[2];

    component pbk1 = BabyPbk();
    pbk1.in <== sk1;

    signal publicKey1[2];
    publicKey1[0] <== pbk1.Ax;
    publicKey1[1] <== pbk1.Ay;

    component pbk2 = BabyPbk();
    pbk2.in <== sk2;

    signal publicKey2[2];
    publicKey2[0] <== pbk2.Ax;
    publicKey2[1] <== pbk2.Ay;

    component keyHash1 = Poseidon(3);
    keyHash1.in[0] <== publicKey1[0];
    keyHash1.in[1] <== publicKey1[1];
    keyHash1.in[2] <== 1;
    keyHash1.dummy <== 0;

    signal key1;
    key1 <== keyHash1.out;

    component cmt1 = CartesianMerkleTree(proofSize);
    cmt1.root <== cmtRoot;
    cmt1.siblings <== siblings[0];
    cmt1.siblingsLength <== siblingsLength[0];
    cmt1.directionBits <== directionBits[0];
    cmt1.key <== key1;
    cmt1.nonExistenceKey <== nonExistenceKey[0];
    cmt1.isExclusion <== 0;
    cmt1.dummy <== 0;

    component keyHash2 = Poseidon(3);
    keyHash2.in[0] <== publicKey2[0];
    keyHash2.in[1] <== publicKey2[1];
    keyHash2.in[2] <== 2;
    keyHash2.dummy <== 0;

    signal key2;
    key2 <== keyHash2.out;

    component cmt2 = CartesianMerkleTree(proofSize);
    cmt2.root <== cmtRoot;
    cmt2.siblings <== siblings[1];
    cmt2.siblingsLength <== siblingsLength[1];
    cmt2.directionBits <== directionBits[1];
    cmt2.key <== key2;
    cmt2.nonExistenceKey <== nonExistenceKey[1];
    cmt2.isExclusion <== 0;
    cmt2.dummy <== 0;
}

component main {public [cmtRoot, proposalId]} = ProposalCreation(20);
