// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {ED256} from "@solarity/solidity-lib/libs/crypto/ED256.sol";

library BabyJubJub {
    using ED256 for *;

    function curve() internal pure returns (ED256.Curve memory) {
        return
            ED256.Curve({
                a: 168700,
                d: 168696,
                p: 21888242871839275222246405745257275088548364400416034343698204186575808495617,
                n: 2736030358979909402780800718157159386076813972158567259200215660948447373041,
                gx: 5299619240641551281634865583518297030282874472190772894086521144482721001553,
                gy: 16950150798460657717958625567821834550301663161624707787222815936182638968203
            });
    }

    function add(
        ED256.PPoint memory pPoint_,
        ED256.APoint memory aPoint_
    ) internal pure returns (ED256.PPoint memory) {
        return curve().pAddPoint(pPoint_, aPoint_.toProjective());
    }

    function subA(
        ED256.PPoint memory pPoint_,
        ED256.APoint memory aPoint_
    ) internal pure returns (ED256.PPoint memory) {
        return curve().pSubPoint(pPoint_, aPoint_.toProjective());
    }

    function subP(
        ED256.PPoint memory p1_,
        ED256.PPoint memory p2_
    ) internal pure returns (ED256.PPoint memory) {
        return curve().pSubPoint(p1_, p2_);
    }

    function mul(
        ED256.PPoint memory p_,
        uint256 scalar_
    ) internal pure returns (ED256.PPoint memory) {
        return curve().pMultShamir(p_, scalar_);
    }

    function mul2(
        ED256.PPoint memory p1_,
        ED256.PPoint memory p2_,
        uint256 scalar1_,
        uint256 scalar2_
    ) internal view returns (ED256.APoint memory) {
        ED256.Curve memory babyJubJub_ = curve();

        return babyJubJub_.toAffine(babyJubJub_.pMultShamir2(p1_, p2_, scalar1_, scalar2_));
    }

    function verifyScalarMult(
        ED256.PPoint memory p_,
        uint256 scalar_
    ) internal view returns (bool) {
        ED256.Curve memory babyJubJub_ = curve();

        return babyJubJub_.pEqual(p_, babyJubJub_.pMultShamir(babyJubJub_.pBasepoint(), scalar_));
    }
}
