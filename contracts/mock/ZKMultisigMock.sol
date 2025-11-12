// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {ED256} from "@solarity/solidity-lib/libs/crypto/ED256.sol";

import {ZKMultisig} from "../ZKMultisig.sol";
import {BabyJubJub} from "../libs/BabyJubJub.sol";

contract ZKMultisigMock is ZKMultisig {
    using EnumerableSet for *;
    using ED256 for *;

    receive() external payable {}

    function addParticipantsExternal(
        ED256.APoint[] calldata permanentKeys_,
        ED256.APoint[] calldata rotationKeys_
    ) external {
        _addParticipants(permanentKeys_, rotationKeys_);
    }

    function removeParticipantsExternal(ED256.APoint[] calldata permanentKeys_) external {
        _removeParticipants(permanentKeys_);
    }

    function updateQuorumPercentageExternal(uint256 newQuorumPercentage_) external {
        _updateQuorumPercentage(newQuorumPercentage_);
    }

    function updateVerifierExternal(address verifier_, bool creation_) external {
        if (creation_) {
            _updateCreationVerifier(verifier_);
        } else {
            _updateVotingVerifier(verifier_);
        }
    }

    function deactivateProposal(uint256 proposalId_) external {
        _getZKMultisigMockStorage().proposals[proposalId_].status = ProposalStatus.EXECUTED;
    }

    function getCreationVerifier() external view returns (address) {
        return _getZKMultisigMockStorage().creationVerifier;
    }

    function getVotingVerifier() external view returns (address) {
        return _getZKMultisigMockStorage().votingVerifier;
    }

    function getCumulativePermanentKey() external view returns (ED256.APoint memory) {
        ED256.Curve memory babyJubJub_ = BabyJubJub.curve();

        return ED256.toAffine(babyJubJub_, _getZKMultisigMockStorage().cumulativePermanentKey);
    }

    function getCumulativeRotationKey() external view returns (ED256.APoint memory) {
        ED256.Curve memory babyJubJub_ = BabyJubJub.curve();

        return ED256.toAffine(babyJubJub_, _getZKMultisigMockStorage().cumulativeRotationKey);
    }

    function getCurrentProposalId() external view returns (uint256) {
        return _getZKMultisigMockStorage().currentProposalId;
    }

    function getProposalBlinders(uint256 proposalId_) external view returns (uint256[] memory) {
        return _getZKMultisigMockStorage().proposals[proposalId_].blinders.values();
    }

    function getProposalDecryptionKey(uint256 proposalId_) external view returns (uint256) {
        return _getZKMultisigMockStorage().proposals[proposalId_].decryptionKey;
    }

    function getProposalAggregatedVotes(
        uint256 proposalId_
    ) external view returns (ED256.APoint[2] memory) {
        ED256.PPoint[2] memory votes_ = _getZKMultisigMockStorage()
            .proposals[proposalId_]
            .aggregatedVotes;

        ED256.Curve memory babyJubJub_ = BabyJubJub.curve();

        return [ED256.toAffine(babyJubJub_, votes_[0]), ED256.toAffine(babyJubJub_, votes_[1])];
    }

    function isRotationKeyNullifierUsed(uint256 nullifier_) external view returns (bool) {
        return _getZKMultisigMockStorage().rotationKeyNullifiers[nullifier_];
    }

    function _getZKMultisigMockStorage() private pure returns (ZKMultisigStorage storage $) {
        assembly {
            $.slot := 0x498bc96b7d273653a6dbed08a392bbda0eadd6b7201a83a295108683ba304490
        }
    }
}
