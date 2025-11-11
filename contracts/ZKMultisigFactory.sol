// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";

import {Paginator} from "@solarity/solidity-lib/libs/arrays/Paginator.sol";
import {ED256} from "@solarity/solidity-lib/libs/crypto/ED256.sol";

import {IZKMultisigFactory} from "./interfaces/IZKMultisigFactory.sol";
import {IZKMultisig} from "./interfaces/IZKMultisig.sol";

contract ZKMultisigFactory is EIP712Upgradeable, IZKMultisigFactory {
    using EnumerableSet for EnumerableSet.AddressSet;
    using Paginator for EnumerableSet.AddressSet;

    // bytes32(uint256(keccak256("private.multisig.contract.ZKMultisigFactory")) - 1)
    bytes32 private constant ZK_MULTISIG_FACTORY_STORAGE =
        0x38978376a0cb2da5e8822474eb0dac781c45e719147d5ca8642e873e8011dbbb;

    bytes32 public constant KDF_MESSAGE_TYPEHASH = keccak256("KDF(address zkMultisigAddress)");

    struct ZKMultisigFactoryStorage {
        address zkMultisigImpl;
        address creationVerifier;
        address votingVerifier;
        EnumerableSet.AddressSet zkMultisigs;
    }

    function initialize(
        address zkMultisigImplementation_,
        address creationVerifier_,
        address votingVerifier_
    ) external initializer {
        __EIP712_init("ZKMultisigFactory", "1");

        if (
            zkMultisigImplementation_.code.length == 0 ||
            creationVerifier_.code.length == 0 ||
            votingVerifier_.code.length == 0
        ) {
            revert InvalidImplementationOrVerifier();
        }

        ZKMultisigFactoryStorage storage $ = _getZKMultisigFactoryStorage();

        $.creationVerifier = creationVerifier_;
        $.votingVerifier = votingVerifier_;

        $.zkMultisigImpl = zkMultisigImplementation_;
    }

    function createMultisig(
        ED256.APoint[] calldata permanentKeys_,
        ED256.APoint[] calldata rotationKeys_,
        uint256 quorumPercentage_,
        uint256 salt_
    ) external returns (address) {
        ZKMultisigFactoryStorage storage $ = _getZKMultisigFactoryStorage();

        address zkMultisigAddress_ = address(
            new ERC1967Proxy{salt: keccak256(abi.encode(msg.sender, salt_))}($.zkMultisigImpl, "")
        );
        IZKMultisig(zkMultisigAddress_).initialize(
            permanentKeys_,
            rotationKeys_,
            quorumPercentage_,
            $.creationVerifier,
            $.votingVerifier
        );

        $.zkMultisigs.add(zkMultisigAddress_);

        emit ZKMultisigCreated(
            zkMultisigAddress_,
            permanentKeys_,
            rotationKeys_,
            quorumPercentage_
        );

        return zkMultisigAddress_;
    }

    function getZKMultisigImplementation() external view returns (address) {
        return _getZKMultisigFactoryStorage().zkMultisigImpl;
    }

    function getCreationVerifier() external view returns (address) {
        return _getZKMultisigFactoryStorage().creationVerifier;
    }

    function getVotingVerifier() external view returns (address) {
        return _getZKMultisigFactoryStorage().votingVerifier;
    }

    function computeZKMultisigAddress(
        address deployer_,
        uint256 salt_
    ) external view returns (address) {
        return
            Create2.computeAddress(
                keccak256(abi.encode(deployer_, salt_)),
                keccak256(
                    abi.encodePacked(
                        type(ERC1967Proxy).creationCode,
                        abi.encode(_getZKMultisigFactoryStorage().zkMultisigImpl, "")
                    )
                )
            );
    }

    function getZKMultisigsCount() external view returns (uint256) {
        return _getZKMultisigFactoryStorage().zkMultisigs.length();
    }

    function getZKMultisigs(
        uint256 offset_,
        uint256 limit_
    ) external view returns (address[] memory) {
        return _getZKMultisigFactoryStorage().zkMultisigs.part(offset_, limit_);
    }

    function isZKMultisig(address multisigAddress_) external view returns (bool) {
        return _getZKMultisigFactoryStorage().zkMultisigs.contains(multisigAddress_);
    }

    function getDefaultKDFMSGToSign() external view returns (bytes32) {
        return _hashTypedDataV4(getKDFMSGHash(address(0)));
    }

    function getKDFMSGToSign(address zkMutlisigAddress_) public view returns (bytes32) {
        return _hashTypedDataV4(getKDFMSGHash(zkMutlisigAddress_));
    }

    function getKDFMSGHash(address zkMutlisigAddress_) private pure returns (bytes32) {
        return keccak256(abi.encode(KDF_MESSAGE_TYPEHASH, zkMutlisigAddress_));
    }

    function _getZKMultisigFactoryStorage()
        private
        pure
        returns (ZKMultisigFactoryStorage storage $)
    {
        assembly {
            $.slot := ZK_MULTISIG_FACTORY_STORAGE
        }
    }
}
