// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {ED256} from "@solarity/solidity-lib/libs/crypto/ED256.sol";
import {CartesianMerkleTree} from "@solarity/solidity-lib/libs/data-structures/CartesianMerkleTree.sol";

interface IZKMultisig {
    enum ProposalStatus {
        NONE,
        VOTING,
        ACCEPTED,
        REJECTED,
        EXECUTED
    }

    struct ZKParams {
        uint256[2] a;
        uint256[2][2] b;
        uint256[2] c;
    }

    struct VoteParams {
        bytes encryptedVote;
        uint256 decryptionKeyShare;
        uint256 keyNullifier;
        uint256 blinder;
        bytes32 cmtRoot;
        ED256.APoint rotationKey;
        ZKParams proofData;
    }

    struct ProposalContent {
        address target;
        uint256 value;
        bytes data;
    }

    struct ProposalData {
        ProposalStatus status;
        ProposalContent content;
        EnumerableSet.UintSet blinders;
        EnumerableSet.Bytes32Set roots;
        uint256 challenge;
        uint256 decryptionKey;
        ED256.APoint encryptionKey;
        ED256.PPoint[2] aggregatedVotes;
    }

    struct ProposalInfoView {
        ProposalContent content;
        ProposalStatus status;
        uint256 votesCount;
        uint256 requiredQuorum;
    }

    error ZeroTarget();
    error ProposalExists(uint256 proposalId);
    error ProposalNotAccepted(uint256 proposalId);
    error ActiveProposal(uint256 proposalId);
    error InvalidValue(uint256 actualValue, uint256 expectedValue);
    error KeyLenMismatch();
    error TooManyParticipants(uint256 participants);
    error RemovingAllParticipants();
    error InvalidQuorum(uint256 quorumPercentage);
    error ZeroVerifier();
    error DuplicateVerifier();
    error NotAContract(address verifier);
    error NotVoting(uint256 proposalId);
    error UsedNullifier(uint256 nullifier);
    error InvalidCMTRoot(bytes32 root);
    error UsedBlinder(uint256 blinder);
    error InvalidProof();
    error NoParticipantsToProcess();
    error VoteCountMismatch();
    error NotAuthorizedCall();

    event ParticipantAdded(ED256.APoint permanentKey, ED256.APoint rotationKey);
    event ParticipantRemoved(ED256.APoint permanentKey);
    event ProposalCreated(uint256 indexed proposalId, ProposalContent content);
    event ProposalVoted(uint256 indexed proposalId, uint256 voterBlinder);
    event ProposalRevealed(uint256 indexed proposalId, bool isAccepted);
    event ProposalExecuted(uint256 indexed proposalId);

    function initialize(
        ED256.APoint[] memory permanentKeys_,
        ED256.APoint[] memory rotationKeys_,
        uint256 quorumPercentage_,
        address creationVerifier_,
        address votingVerifier_
    ) external;

    function addParticipants(
        ED256.APoint[] calldata permanentKeys_,
        ED256.APoint[] calldata rotationKeys_
    ) external;

    function removeParticipants(ED256.APoint[] calldata permanentKeys_) external;

    function updateQuorumPercentage(uint256 newQuorumPercentage_) external;

    function create(
        ProposalContent calldata content_,
        uint256 salt_,
        ZKParams calldata proofData_
    ) external returns (uint256);

    function vote(uint256 proposalId_, VoteParams calldata params_) external;

    function reveal(uint256 proposalId_, uint256 approvalVoteCount_) external;

    function execute(uint256 proposalId_) external payable;

    function getParticipantsCMTRoot() external view returns (bytes32);

    function getParticipantsCMTProof(
        uint256 publicKeyHash_,
        uint32 desiredProofSize_
    ) external view returns (CartesianMerkleTree.Proof memory);

    function getParticipantsCount() external view returns (uint256);

    function getParticipants()
        external
        view
        returns (ED256.APoint[] memory, ED256.APoint[] memory);

    function getProposalsCount() external view returns (uint256);

    function getProposalsIds(
        uint256 offset_,
        uint256 limit_
    ) external view returns (uint256[] memory);

    function getQuorumPercentage() external view returns (uint256);

    function getProposalInfo(uint256 proposalId_) external view returns (ProposalInfoView memory);

    function getProposalStatus(uint256 proposalId_) external view returns (ProposalStatus);

    function getProposalChallenge(uint256 proposalId_) external view returns (uint256);

    function computeProposalId(
        ProposalContent calldata content_,
        uint256 salt_
    ) external view returns (uint256);

    function isBlinderVoted(
        uint256 proposalId_,
        uint256 blinderToCheck_
    ) external view returns (bool);
}
