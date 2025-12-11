pragma circom 2.1.6;

include "./babyjubjub/babyjub.circom";
include "./babyjubjub/escalarmulany.circom";

template ElGamal() {
    signal input pk[2];
    signal input M[2];
    signal input nonce;

    signal output C[2];
    signal output D[2];

    component pbk = BabyPbk();
    pbk.in <== nonce;

    C[0] <== pbk.Ax;
    C[1] <== pbk.Ay;

    signal rP[2];

    component nonceBits = Num2Bits(253);
    nonceBits.in <== nonce;

    component mul = EscalarMulAny(253);
    mul.p <== pk;

    var i;
    for (i = 0; i < 253; i++) {
        mul.e[i] <== nonceBits.out[i];
    }

    rP <== mul.out;

    component add = BabyAdd();
    add.x1 <== M[0];
    add.y1 <== M[1];
    add.x2 <== rP[0];
    add.y2 <== rP[1];

    D[0] <== add.xout;
    D[1] <== add.yout;
}
