pragma circom 2.1.6;

include "./babyjubjub/babyjub.circom";
include "@solarity/circom-lib/hasher/poseidon/poseidon.circom";
include "@solarity/circom-lib/data-structures/CartesianMerkleTree.circom";

template ProposalCreation(proofSize) {
    signal input cmtRoot;
    signal input challenge;

    signal input sk;

    signal input siblings[proofSize];
    signal input siblingsLength[proofSize/2];
    signal input directionBits[proofSize/2];

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
    cmt.nonExistenceKey <== 0;
    cmt.isExclusion <== 0;
    cmt.dummy <== 0;

    signal challengeConstraint;
    challengeConstraint <== challenge * key;
}

component main {public [cmtRoot, challenge]} = ProposalCreation(40);
