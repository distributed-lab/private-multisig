# Private Multisig Smart Contracts

This project consists of a basic implementation of private multisig smart contracts.

It allows multisig participants to approve or reject proposals anonymously without revealing individual ballots until everyone has voted.

> [!TIP]
> Please check out the [original paper](https://ethresear.ch/t/private-multisig-v0-1/23244).

## Key Features

- Anonymous membership via [Cartesian Merkle proofs](https://arxiv.org/pdf/2504.10944).
- ECC ElGamal encrypted votes with homomorphic ciphertext aggregation.
- Non-interactive DKG-based keys.
- On-chain ZK verification of core operations.

## Limitations

- All participants are required to vote.
- Only one proposal can be in the voting state at a time.
- Votes revelation and results computation scale linearly with the number of participants.

> [!WARNING]
> This is an unaudited PoC. Use at your own risk.

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
3. Deploy the contracts:
    ```bash
    npm run deploy-sepolia
    ```

## Disclaimer

Privacy is not a feature, it's a right.
