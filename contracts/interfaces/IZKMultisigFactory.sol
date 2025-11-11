// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {ED256} from "@solarity/solidity-lib/libs/crypto/ED256.sol";

interface IZKMultisigFactory {
    error InvalidImplementationOrVerifier();

    event ZKMultisigCreated(
        address indexed zkMultisigAddress,
        ED256.APoint[] initialParticipantsPerm,
        ED256.APoint[] initialParticipantsRot,
        uint256 initialQuorumPercentage
    );

    function createMultisig(
        ED256.APoint[] calldata permanentKeys_,
        ED256.APoint[] calldata rotationKeys_,
        uint256 quorumPercentage_,
        uint256 salt_
    ) external returns (address);

    function getZKMultisigsCount() external view returns (uint256);

    function getZKMultisigs(
        uint256 offset_,
        uint256 limit_
    ) external view returns (address[] memory);

    function computeZKMultisigAddress(
        address deployer,
        uint256 salt
    ) external view returns (address);

    function getKDFMSGToSign(address zkMutlisigAddress_) external view returns (bytes32);

    function getDefaultKDFMSGToSign() external view returns (bytes32);

    function isZKMultisig(address multisigAddress_) external view returns (bool);
}
