# Private ZK Multisig Smart Contracts

This project consists of a basic implementation of Private ZK (Zero-Knowledge) multisig smart contracts.

It allows multisig participants to approve or reject proposals 
without revealing who voted and how until everyone has voted.

The contracts are divided into two parts:

- **ZK Multisig Factory** - Manages and deploys multisig contracts.
- **ZK Multisig** - The implementation of the multisig contract itself.

## Key Features
- Anonymous membership via Cartesian Merkle proofs.
- ECC ElGamal encrypted votes with ciphertext aggregation.
- Non-interactive DKG-based keys.
- On-chain ZK verification of core operations.

For more details, refer to the [original paper](https://ethresear.ch/t/private-multisig-v0-1/23244).

## Limitations
- All participants are required to vote.
- Only one proposal can be in the voting state at a time.
- Votes revelation and results computation scale linearly with the number of participants.

## Steps to Build the Project

1. Generate circuit verifiers
    ```bash
    npx hardhat zkit verifiers
    ```
2. Compile the contracts and run tests:
    ```bash
    npm run compile
    npm run test
    ```
