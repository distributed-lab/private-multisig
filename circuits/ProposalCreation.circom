pragma circom 2.1.6;

include "./babyjubjub/babyjub.circom";
include "../node_modules/@solarity/circom-lib/data-structures/CartesianMerkleTree.circom";
include "../node_modules/@solarity/circom-lib/hasher/poseidon/poseidon.circom";

template ProposalCreation(proofSize) {
    signal input cmtRoot;
    signal input proposalId;

    signal input sk;

    signal input siblings[proofSize];
    signal input siblingsLength[proofSize/2];
    signal input directionBits[proofSize/2];
    signal input nonExistenceKey;

    component pbk = BabyPbk();
    pbk.in <== sk;

    signal publicKey[2];
    publicKey[0] <== pbk.Ax;
    publicKey[1] <== pbk.Ay;

    component keyHash = Poseidon(3);
    keyHash.in[0] <== publicKey[0];
    keyHash.in[1] <== publicKey[1];
    keyHash.in[2] <== 1;
    keyHash.dummy <== 0;

    signal key;
    key <== keyHash.out;

    component cmt = CartesianMerkleTree(proofSize);
    cmt.root <== cmtRoot;
    cmt.siblings <== siblings;
    cmt.siblingsLength <== siblingsLength;
    cmt.directionBits <== directionBits;
    cmt.key <== key;
    cmt.nonExistenceKey <== nonExistenceKey;
    cmt.isExclusion <== 0;
    cmt.dummy <== 0;

    signal proposalConstraint;
    proposalConstraint <== proposalId * key;
}

component main {public [cmtRoot, proposalId]} = ProposalCreation(20);
