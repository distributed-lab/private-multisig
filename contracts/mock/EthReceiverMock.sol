// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract EthReceiverMock {
    event ReceivedEth(address from_, uint256 amount_);

    receive() external payable {
        emit ReceivedEth(msg.sender, msg.value);
    }
}
