import { Deployer, Reporter } from "@solarity/hardhat-migrate";

import { deployPoseidons } from "./helpers/poseidon";

import {
  ZKMultisigFactory__factory,
  ZKMultisig__factory,
  ProposalCreationGroth16Verifier__factory,
  VotingGroth16Verifier__factory,
} from "@ethers-v6";

export = async (deployer: Deployer) => {
  await deployPoseidons(deployer, [1, 3]);

  const creationVerifier = await deployer.deploy(ProposalCreationGroth16Verifier__factory);
  const votingVerifier = await deployer.deploy(VotingGroth16Verifier__factory);

  const multisig = await deployer.deploy(ZKMultisig__factory);
  const factory = await deployer.deploy(ZKMultisigFactory__factory);

  await factory.initialize(
    await multisig.getAddress(),
    await creationVerifier.getAddress(),
    await votingVerifier.getAddress(),
  );

  Reporter.reportContracts(["Factory", await factory.getAddress()]);
};
