// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";

import {CartesianMerkleTree} from "@solarity/solidity-lib/libs/data-structures/CartesianMerkleTree.sol";
import {PRECISION, PERCENTAGE_100} from "@solarity/solidity-lib/utils/Globals.sol";
import {Paginator} from "@solarity/solidity-lib/libs/arrays/Paginator.sol";
import {Groth16VerifierHelper} from "@solarity/solidity-lib/libs/zkp/Groth16VerifierHelper.sol";
import {ED256} from "@solarity/solidity-lib/libs/crypto/ED256.sol";

import {IZKMultisig} from "./interfaces/IZKMultisig.sol";
import {PoseidonUnit1L, PoseidonUnit3L} from "./libs/Poseidon.sol";
import {BabyJubJub} from "./libs/BabyJubJub.sol";

contract ZKMultisig is UUPSUpgradeable, EIP712Upgradeable, IZKMultisig {
    using BabyJubJub for *;
    using EnumerableSet for *;
    using Paginator for EnumerableSet.UintSet;
    using CartesianMerkleTree for CartesianMerkleTree.UintCMT;
    using Groth16VerifierHelper for address;
    using Address for address;
    using Math for uint256;

    // bytes32(uint256(keccak256("private.multisig.contract.ZKMultisig")) - 1)
    bytes32 private constant ZK_MULTISIG_STORAGE =
        0x498bc96b7d273653a6dbed08a392bbda0eadd6b7201a83a295108683ba304490;

    bytes32 public constant KDF_ROTATION_MSG_TYPEHASH =
        keccak256("KDF(address zkMultisigAddr,uint256 proposalId)");

    uint256 public constant PARTICIPANTS_TREE_DEPTH = 20;
    uint256 public constant MIN_QUORUM_SIZE = 1;

    struct ZKMultisigStorage {
        address creationVerifier;
        address votingVerifier;
        uint256 quorumPercentage;
        uint256 currentProposalId;
        CartesianMerkleTree.UintCMT participantsCMT;
        EnumerableSet.UintSet proposalIds;
        EnumerableSet.UintSet participantsPermanent;
        EnumerableSet.UintSet participantsRotation;
        ED256.PPoint cumulativePermanentKey;
        ED256.PPoint cumulativeRotationKey;
        mapping(uint256 => ED256.APoint) participantPermanentKeys;
        mapping(uint256 => ED256.APoint) participantRotationKeys;
        mapping(uint256 => bool) rotationKeyNullifiers;
        mapping(uint256 => ProposalData) proposals;
    }

    modifier onlyThis() {
        _validateMsgSender();
        _;
    }

    constructor() {
        _disableInitializers();
    }

    function initialize(
        ED256.APoint[] calldata permanentKeys_,
        ED256.APoint[] calldata rotationKeys_,
        uint256 quorumPercentage_,
        address creationVerifier_,
        address votingVerifier_
    ) external initializer {
        __EIP712_init("ZKMultisig", "1");

        ZKMultisigStorage storage $ = _getZKMultisigStorage();

        $.participantsCMT.initialize(uint32(PARTICIPANTS_TREE_DEPTH));
        $.participantsCMT.setHasher(poseidon3);

        _updateCreationVerifier(creationVerifier_);
        _updateVotingVerifier(votingVerifier_);
        _updateQuorumPercentage(quorumPercentage_);

        $.cumulativePermanentKey = ED256.pInfinity();
        $.cumulativeRotationKey = ED256.pInfinity();

        _addParticipants(permanentKeys_, rotationKeys_);
    }

    function addParticipants(
        ED256.APoint[] calldata permanentKeys_,
        ED256.APoint[] calldata rotationKeys_
    ) external onlyThis {
        _addParticipants(permanentKeys_, rotationKeys_);
    }

    function removeParticipants(ED256.APoint[] calldata permanentKeys_) external onlyThis {
        _removeParticipants(permanentKeys_);
    }

    function updateQuorumPercentage(uint256 newQuorumPercentage_) external onlyThis {
        _updateQuorumPercentage(newQuorumPercentage_);
    }

    function updateCreationVerifier(address creationVerifier_) external onlyThis {
        _updateCreationVerifier(creationVerifier_);
    }

    function updateVotingVerifier(address votingVerifier_) external onlyThis {
        _updateVotingVerifier(votingVerifier_);
    }

    function create(
        ProposalContent calldata content_,
        uint256 salt_,
        ZKParams calldata proofData_
    ) external returns (uint256) {
        // validate inputs
        if (content_.target == address(0)) revert ZeroTarget();

        ZKMultisigStorage storage $ = _getZKMultisigStorage();

        if ($.proposals[$.currentProposalId].status == ProposalStatus.VOTING) {
            revert ActiveProposal($.currentProposalId);
        }

        uint256 proposalId_ = computeProposalId(content_, salt_);

        ProposalData storage proposal = $.proposals[proposalId_];

        // validate proposal state
        if (proposal.status != ProposalStatus.NONE) {
            revert ProposalExists(proposalId_);
        }

        uint256 challenge_ = uint256(
            keccak256(abi.encode(block.chainid, address(this), proposalId_))
        ) % BabyJubJub.curve().p;

        _validateCreationZKParams(challenge_, proofData_);

        $.currentProposalId = proposalId_;

        // create proposal
        $.proposalIds.add(proposalId_);

        proposal.content = content_;
        proposal.roots.add($.participantsCMT.getRoot());

        proposal.challenge = challenge_;
        proposal.encryptionKey = _computeEncryptionKey(challenge_);

        proposal.status = ProposalStatus.VOTING;

        $.cumulativeRotationKey = ED256.pInfinity();
        $.participantsRotation.clear();

        emit ProposalCreated(proposalId_, content_);

        return proposalId_;
    }

    function vote(VoteParams calldata params_) external {
        _vote(_getZKMultisigStorage().currentProposalId, params_);
    }

    function revealAndExecute(uint256 approvalVoteCount_) external payable {
        uint256 proposalId_ = _getZKMultisigStorage().currentProposalId;

        _reveal(proposalId_, approvalVoteCount_);

        _execute(proposalId_);
    }

    function reveal(uint256 approvalVoteCount_) external {
        _reveal(_getZKMultisigStorage().currentProposalId, approvalVoteCount_);
    }

    function execute(uint256 proposalId_) external payable {
        _execute(proposalId_);
    }

    function getRotationKDFMSGToSign(uint256 proposalId_) external view returns (bytes32) {
        return
            _hashTypedDataV4(
                keccak256(abi.encode(KDF_ROTATION_MSG_TYPEHASH, address(this), proposalId_))
            );
    }

    function getParticipantsCMTRoot() external view returns (bytes32) {
        return _getZKMultisigStorage().participantsCMT.getRoot();
    }

    function getParticipantsCMTProof(
        uint256 publicKeyHash_,
        uint32 desiredProofSize_
    ) external view override returns (CartesianMerkleTree.Proof memory) {
        return _getZKMultisigStorage().participantsCMT.getProof(publicKeyHash_, desiredProofSize_);
    }

    function getParticipantsCount() external view returns (uint256) {
        return _getZKMultisigStorage().participantsPermanent.length();
    }

    function getParticipants()
        external
        view
        returns (ED256.APoint[] memory permanentKeys_, ED256.APoint[] memory rotationKeys_)
    {
        ZKMultisigStorage storage $ = _getZKMultisigStorage();

        uint256 permanentKeysCount_ = $.participantsPermanent.length();
        permanentKeys_ = new ED256.APoint[](permanentKeysCount_);

        for (uint256 i = 0; i < permanentKeysCount_; i++) {
            permanentKeys_[i] = $.participantPermanentKeys[$.participantsPermanent.at(i)];
        }

        uint256 rotationKeysCount_ = $.participantsRotation.length();
        rotationKeys_ = new ED256.APoint[](rotationKeysCount_);

        for (uint256 i = 0; i < rotationKeysCount_; i++) {
            rotationKeys_[i] = $.participantRotationKeys[$.participantsRotation.at(i)];
        }
    }

    function getProposalsCount() external view returns (uint256) {
        return _getZKMultisigStorage().proposalIds.length();
    }

    function getProposalsIds(
        uint256 offset,
        uint256 limit
    ) external view override returns (uint256[] memory) {
        return _getZKMultisigStorage().proposalIds.part(offset, limit);
    }

    function getQuorumPercentage() external view returns (uint256) {
        return _getZKMultisigStorage().quorumPercentage;
    }

    function getProposalInfo(uint256 proposalId_) external view returns (ProposalInfoView memory) {
        ProposalData storage proposal = _getZKMultisigStorage().proposals[proposalId_];

        return
            ProposalInfoView({
                content: proposal.content,
                status: proposal.status,
                votesCount: proposal.blinders.length(),
                requiredQuorum: getRequiredQuorum()
            });
    }

    function computeProposalId(
        ProposalContent calldata content_,
        uint256 salt_
    ) public pure returns (uint256) {
        return
            uint256(keccak256(abi.encode(content_.target, content_.value, content_.data, salt_))) %
            BabyJubJub.curve().p;
    }

    function getEncryptionKey(uint256 proposalId_) external view returns (ED256.APoint memory) {
        return _getZKMultisigStorage().proposals[proposalId_].encryptionKey;
    }

    function getProposalChallenge(uint256 proposalId_) external view returns (uint256) {
        return _getZKMultisigStorage().proposals[proposalId_].challenge;
    }

    function isBlinderVoted(
        uint256 proposalId_,
        uint256 blinderToCheck_
    ) public view returns (bool) {
        return _getZKMultisigStorage().proposals[proposalId_].blinders.contains(blinderToCheck_);
    }

    function getProposalStatus(uint256 proposalId_) external view returns (ProposalStatus) {
        return _getZKMultisigStorage().proposals[proposalId_].status;
    }

    // return the required quorum amount (not percentage) for a given number of participants
    function getRequiredQuorum() public view returns (uint256) {
        ZKMultisigStorage storage $ = _getZKMultisigStorage();

        return
            (($.participantsPermanent.length() * $.quorumPercentage) / PERCENTAGE_100).max(
                MIN_QUORUM_SIZE
            );
    }

    function poseidon3(bytes32 el1_, bytes32 el2_, bytes32 el3_) public pure returns (bytes32) {
        return bytes32(PoseidonUnit3L.poseidon([uint256(el1_), uint256(el2_), uint256(el3_)]));
    }

    function _authorizeUpgrade(address newImplementation_) internal override onlyThis {}

    function _addParticipants(
        ED256.APoint[] calldata permanentKeys_,
        ED256.APoint[] calldata rotationKeys_
    ) internal {
        uint256 participantsToAdd_ = permanentKeys_.length;

        if (participantsToAdd_ == 0) revert NoParticipantsToProcess();
        if (participantsToAdd_ != rotationKeys_.length) revert KeyLenMismatch();

        ZKMultisigStorage storage $ = _getZKMultisigStorage();

        uint256 totalNodesCount_ = $.participantsCMT.getNodesCount() + participantsToAdd_ * 2;

        if (totalNodesCount_ > 2 ** PARTICIPANTS_TREE_DEPTH) {
            revert TooManyParticipants(totalNodesCount_);
        }

        for (uint256 i = 0; i < participantsToAdd_; i++) {
            uint256 permanentKeyHash_ = PoseidonUnit3L.poseidon(
                [permanentKeys_[i].x, permanentKeys_[i].y, 1]
            );

            uint256 rotationKeyHash_ = PoseidonUnit3L.poseidon(
                [rotationKeys_[i].x, rotationKeys_[i].y, 2]
            );

            if (!$.participantsPermanent.contains(permanentKeyHash_)) {
                $.participantsCMT.add(permanentKeyHash_);
                $.participantsCMT.add(rotationKeyHash_);

                $.participantsPermanent.add(permanentKeyHash_);
                $.participantsRotation.add(rotationKeyHash_);

                $.participantPermanentKeys[permanentKeyHash_] = permanentKeys_[i];
                $.participantRotationKeys[rotationKeyHash_] = rotationKeys_[i];

                $.cumulativePermanentKey = $.cumulativePermanentKey.add(permanentKeys_[i]);
                $.cumulativeRotationKey = $.cumulativeRotationKey.add(rotationKeys_[i]);

                emit ParticipantAdded(permanentKeys_[i], rotationKeys_[i]);
            }
        }
    }

    function _removeParticipants(ED256.APoint[] calldata permanentKeys_) internal {
        if (permanentKeys_.length == 0) revert NoParticipantsToProcess();

        ZKMultisigStorage storage $ = _getZKMultisigStorage();

        for (uint256 i = 0; i < permanentKeys_.length; i++) {
            uint256 permanentKeyHash_ = PoseidonUnit3L.poseidon(
                [permanentKeys_[i].x, permanentKeys_[i].y, 1]
            );

            if ($.participantsPermanent.contains(permanentKeyHash_)) {
                $.participantsCMT.remove(permanentKeyHash_);
                $.participantsPermanent.remove(permanentKeyHash_);
                delete $.participantPermanentKeys[permanentKeyHash_];

                $.cumulativePermanentKey = $.cumulativePermanentKey.subA(permanentKeys_[i]);

                emit ParticipantRemoved(permanentKeys_[i]);
            }
        }

        if (_getZKMultisigStorage().participantsPermanent.length() == 0) {
            revert RemovingAllParticipants();
        }
    }

    function _updateQuorumPercentage(uint256 newQuorumPercentage_) internal {
        ZKMultisigStorage storage $ = _getZKMultisigStorage();

        if (
            newQuorumPercentage_ == 0 ||
            newQuorumPercentage_ > PERCENTAGE_100 ||
            newQuorumPercentage_ == $.quorumPercentage
        ) {
            revert InvalidQuorum(newQuorumPercentage_);
        }

        $.quorumPercentage = newQuorumPercentage_;
    }

    function _updateCreationVerifier(address creationVerifier_) internal {
        ZKMultisigStorage storage $ = _getZKMultisigStorage();

        _validateVerifier(creationVerifier_, $.creationVerifier);

        $.creationVerifier = creationVerifier_;
    }

    function _updateVotingVerifier(address votingVerifier_) internal {
        ZKMultisigStorage storage $ = _getZKMultisigStorage();

        _validateVerifier(votingVerifier_, $.votingVerifier);

        $.votingVerifier = votingVerifier_;
    }

    function _vote(uint256 proposalId_, VoteParams calldata params_) internal {
        ZKMultisigStorage storage $ = _getZKMultisigStorage();

        ProposalData storage proposal = $.proposals[proposalId_];

        if (proposal.status != ProposalStatus.VOTING) {
            revert NotVoting(proposalId_);
        }

        if ($.rotationKeyNullifiers[params_.keyNullifier]) {
            revert UsedNullifier(params_.keyNullifier);
        }

        if (isBlinderVoted(proposalId_, params_.blinder)) {
            revert UsedBlinder(params_.blinder);
        }

        if (!proposal.roots.contains(params_.cmtRoot)) {
            revert InvalidCMTRoot(params_.cmtRoot);
        }

        $.rotationKeyNullifiers[params_.keyNullifier] = true;
        proposal.blinders.add(params_.blinder);

        ED256.APoint[2] memory vote_ = abi.decode(params_.encryptedVote, (ED256.APoint[2]));

        _validateVotingZKParams(proposalId_, params_, vote_);

        proposal.aggregatedVotes[0] = proposal.aggregatedVotes[0].add(vote_[0]);
        proposal.aggregatedVotes[1] = proposal.aggregatedVotes[1].add(vote_[1]);

        proposal.decryptionKey =
            (proposal.decryptionKey + params_.decryptionKeyShare) %
            BabyJubJub.curve().n;

        uint256 rotationKeyHash_ = PoseidonUnit3L.poseidon(
            [params_.rotationKey.x, params_.rotationKey.y, 2]
        );

        $.participantsCMT.add(rotationKeyHash_);
        proposal.roots.add($.participantsCMT.getRoot());

        $.participantsRotation.add(rotationKeyHash_);
        $.participantRotationKeys[rotationKeyHash_] = params_.rotationKey;

        $.cumulativeRotationKey = $.cumulativeRotationKey.add(params_.rotationKey);

        emit ProposalVoted(proposalId_, params_.blinder);
    }

    function _reveal(uint256 proposalId_, uint256 approvalVoteCount_) internal {
        ZKMultisigStorage storage $ = _getZKMultisigStorage();

        ProposalData storage proposal = $.proposals[proposalId_];

        ED256.PPoint memory xC1_ = proposal.aggregatedVotes[0].mul(proposal.decryptionKey);
        ED256.PPoint memory T_ = proposal.aggregatedVotes[1].subP(xC1_);

        if (!T_.verifyScalarMult(approvalVoteCount_)) revert VoteCountMismatch();

        bool isAccepted_ = approvalVoteCount_ >= getRequiredQuorum();

        proposal.status = isAccepted_ ? ProposalStatus.ACCEPTED : ProposalStatus.REJECTED;

        emit ProposalRevealed(proposalId_, isAccepted_);
    }

    function _execute(uint256 proposalId_) internal {
        ProposalData storage proposal = _getZKMultisigStorage().proposals[proposalId_];

        if (proposal.status != ProposalStatus.ACCEPTED) {
            revert ProposalNotAccepted(proposalId_);
        }

        if (msg.value != proposal.content.value) {
            revert InvalidValue(msg.value, proposal.content.value);
        }

        proposal.content.target.functionCallWithValue(
            proposal.content.data,
            proposal.content.value
        );

        proposal.status = ProposalStatus.EXECUTED;

        emit ProposalExecuted(proposalId_);
    }

    function _computeEncryptionKey(
        uint256 challenge_
    ) internal view returns (ED256.APoint memory) {
        uint256 h1_ = PoseidonUnit1L.poseidon([challenge_]);
        uint256 h2_ = PoseidonUnit1L.poseidon([h1_]);

        ZKMultisigStorage storage $ = _getZKMultisigStorage();

        return $.cumulativePermanentKey.mul2($.cumulativeRotationKey, h1_, h2_);
    }

    function _validateVerifier(address verifier_, address actualVerifier_) internal view {
        if (verifier_ == address(0)) revert ZeroVerifier();
        if (verifier_ == actualVerifier_) revert DuplicateVerifier();
        if (verifier_.code.length == 0) revert NotAContract(verifier_);
    }

    function _validateCreationZKParams(
        uint256 challenge_,
        ZKParams calldata proofData_
    ) internal view {
        ZKMultisigStorage storage $ = _getZKMultisigStorage();

        uint256[] memory inputs_ = new uint256[](2);
        inputs_[0] = uint256($.participantsCMT.getRoot());
        inputs_[1] = challenge_;

        if (
            !$.creationVerifier.verifyProof(
                Groth16VerifierHelper.Groth16Proof({
                    proofPoints: Groth16VerifierHelper.ProofPoints({
                        a: proofData_.a,
                        b: proofData_.b,
                        c: proofData_.c
                    }),
                    publicSignals: inputs_
                })
            )
        ) {
            revert InvalidProof();
        }
    }

    function _validateVotingZKParams(
        uint256 proposalId_,
        VoteParams calldata params_,
        ED256.APoint[2] memory vote_
    ) internal view {
        ZKMultisigStorage storage $ = _getZKMultisigStorage();

        ProposalData storage proposal = $.proposals[proposalId_];

        uint256[] memory inputs_ = new uint256[](14);
        inputs_[0] = params_.blinder;
        inputs_[1] = params_.keyNullifier;
        inputs_[2] = vote_[0].x;
        inputs_[3] = vote_[0].y;
        inputs_[4] = vote_[1].x;
        inputs_[5] = vote_[1].y;
        inputs_[6] = params_.rotationKey.x;
        inputs_[7] = params_.rotationKey.y;
        inputs_[8] = params_.decryptionKeyShare;
        inputs_[9] = proposal.encryptionKey.x;
        inputs_[10] = proposal.encryptionKey.y;
        inputs_[11] = proposal.challenge;
        inputs_[12] = proposalId_;
        inputs_[13] = uint256(params_.cmtRoot);

        if (
            !$.votingVerifier.verifyProof(
                Groth16VerifierHelper.Groth16Proof({
                    proofPoints: Groth16VerifierHelper.ProofPoints({
                        a: params_.proofData.a,
                        b: params_.proofData.b,
                        c: params_.proofData.c
                    }),
                    publicSignals: inputs_
                })
            )
        ) {
            revert InvalidProof();
        }
    }

    function _validateMsgSender() private view {
        if (msg.sender != address(this)) revert NotAuthorizedCall();
    }

    function _getZKMultisigStorage() private pure returns (ZKMultisigStorage storage $) {
        assembly {
            $.slot := ZK_MULTISIG_STORAGE
        }
    }
}
