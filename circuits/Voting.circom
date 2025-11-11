pragma circom 2.1.6;

include "./IsGOrInf.circom";
include "./ElGamal.circom";
include "./babyjubjub/babyjub.circom";
include "./babyjubjub/escalarmulany.circom";
include "../node_modules/@solarity/circom-lib/data-structures/CartesianMerkleTree.circom";
include "../node_modules/@solarity/circom-lib/hasher/poseidon/poseidon.circom";

template Voting(proofSize) {
    signal input decryptionKeyShare;
    signal input encryptionKey[2];
    signal input challenge;
    signal input proposalId;
    signal input cmtRoot;

    signal input sk1;
    signal input sk2;

    signal input vote[2];
    signal input k;

    // CMT inclusion proof
    signal input siblings[2][proofSize];
    signal input siblingsLength[2][proofSize/2];
    signal input directionBits[2][proofSize/2];
    signal input nonExistenceKey[2];

    signal output blinder;
    signal output nullifier;
    signal output C1[2];
    signal output C2[2];

    // pk = skG
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

    // blinder check
    component blinderHash = Poseidon(2);
    blinderHash.in[0] <== sk1;
    blinderHash.in[1] <== proposalId;
    blinderHash.dummy <== 0;

    blinder <== blinderHash.out;

    // sk2 nullifier check
    component nullifierHash = Poseidon(1);
    nullifierHash.in[0] <== sk2;
    nullifierHash.dummy <== 0;

    nullifier <== nullifierHash.out;

    // decryption key share calculation
    component h1Hash = Poseidon(1);
    h1Hash.in[0] <== challenge;
    h1Hash.dummy <== 0;

    signal h1;
    h1 <== h1Hash.out;

    component h2Hash = Poseidon(1);
    h2Hash.in[0] <== h1;
    h2Hash.dummy <== 0;

    signal h2;
    h2 <== h2Hash.out;

    signal hpk1[2];
    signal hpk2[2];

    component h1Bits = Num2Bits(254);
    h1Bits.in <== h1;

    component pk1Mul = EscalarMulAny(254);
    pk1Mul.p <== publicKey1;

    var i;
    for (i = 0; i < 254; i++) {
        pk1Mul.e[i] <== h1Bits.out[i];
    }

    hpk1 <== pk1Mul.out;

    component h2Bits = Num2Bits(254);
    h2Bits.in <== h2;

    component pk2Mul = EscalarMulAny(254);
    pk2Mul.p <== publicKey2;

    for (i = 0; i < 254; i++) {
        pk2Mul.e[i] <== h2Bits.out[i];
    }

    hpk2 <== pk2Mul.out;

    signal expectedEncryptionKeyShare[2];
    component add = BabyAdd();
    add.x1 <== hpk1[0];
    add.y1 <== hpk1[1];
    add.x2 <== hpk2[0];
    add.y2 <== hpk2[1];

    expectedEncryptionKeyShare[0] <== add.xout;
    expectedEncryptionKeyShare[1] <== add.yout;

    signal encryptionKeyShare[2];
    component encKey = BabyPbk();
    encKey.in <== decryptionKeyShare;

    encryptionKeyShare[0] <== encKey.Ax;
    encryptionKeyShare[1] <== encKey.Ay;

    encryptionKeyShare[0] === expectedEncryptionKeyShare[0];
    encryptionKeyShare[1] === expectedEncryptionKeyShare[1];

    // check for the vote to be either G or inf
    component voteChecker = IsGOrInf();
    voteChecker.x <== vote[0];
    voteChecker.y <== vote[1];

    // vote ElGamal encryption
    component elgamal = ElGamal();
    elgamal.pk <== encryptionKey;
    elgamal.M <== vote;
    elgamal.nonce <== k;

    C1 <== elgamal.C;
    C2 <== elgamal.D;
}

component main {public [decryptionKeyShare, encryptionKey, challenge, proposalId, cmtRoot, decryptionKeyShare]} = Voting(20);
