pragma circom 2.1.6;

include "@solarity/circom-lib/bitify/comparators.circom";

template IsGOrInf() {
    var Gx = 5299619240641551281634865583518297030282874472190772894086521144482721001553;
    var Gy = 16950150798460657717958625567821834550301663161624707787222815936182638968203;

    signal input x;
    signal input y;

    component diffGx = IsZero();
    diffGx.in <== x - Gx;

    component diffGy = IsZero();
    diffGy.in <== y - Gy;

    signal isG;
    isG <== diffGx.out * diffGy.out;

    component diffInfX = IsZero();
    diffInfX.in <== x - 0;

    component diffInfY = IsZero();
    diffInfY.in <== y - 1;

    signal isInf;
    isInf <== diffInfX.out * diffInfY.out;

    signal isValid;
    isValid <== isG + isInf;

    isValid === 1;
}
