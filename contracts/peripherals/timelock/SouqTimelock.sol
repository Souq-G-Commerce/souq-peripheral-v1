// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.10;

import "./TimelockUpgradeable.sol";
import {IAccessManager} from "../../interfaces/IAccessManager.sol";
import {Errors} from "../../libraries/Errors.sol";

/**
 * @title SouqTimelock
 * @author Souq.Finance
 * @notice This contract implements a timelock mechanism similar to the one used by Compound Finance, but with access control added
 * @notice License: https://souq-peripheral-v1.s3.amazonaws.com/LICENSE.md
 */

contract SouqTimelock is TimelockUpgradeable {
    using SafeMath for uint;

    IAccessManager public accessManager;

    constructor(address _admin, uint _delay, address _accessManager) {
        TimelockUpgradeable.initialize(_admin, _delay);
        accessManager = IAccessManager(_accessManager);
    }

    /**
     * @dev modifier for when the address has timelock admin role
     */
    modifier onlyTimelockAdmin() {
        require(accessManager.hasRole(accessManager.TIMELOCK_ADMIN_ROLE(), msg.sender), Errors.CALLER_NOT_TIMELOCK_ADMIN);
        _;
    }

    /**
     * @dev Queues a transaction to be executed after a specified delay period
     * @param target The address of the contract where the transaction will be executed
     * @param value The amount of Ether to send with the transaction
     * @param signature The function signature of the method to be called on the target contract
     * @param data The data payload for the function call
     * @param eta The estimated time (in seconds since the Unix epoch) when the transaction can be executed
     * @return bytes32 The hash of the queued transaction
     */
    function queueTransaction(
        address target,
        uint value,
        string memory signature,
        bytes memory data,
        uint eta
    ) external override onlyTimelockAdmin returns (bytes32) {
        require(eta >= getBlockTimestamp().add(delay), "Timelock::queueTransaction: Estimated execution block must satisfy delay.");

        bytes32 txHash = keccak256(abi.encode(target, value, signature, data, eta));
        queuedTransactions[txHash] = true;

        emit QueueTransaction(txHash, target, value, signature, data, eta);
        return txHash;
    }

    /**
     * @dev Cancels a previously queued transaction
     * @param target The address of the contract where the transaction was queued
     * @param value The amount of Ether sent with the transaction
     * @param signature The function signature of the method to be called on the target contract
     * @param data The data payload for the function call
     * @param eta The estimated time (in seconds since the Unix epoch) when the transaction was scheduled
     */
    function cancelTransaction(
        address target,
        uint value,
        string memory signature,
        bytes memory data,
        uint eta
    ) external override onlyTimelockAdmin {
        bytes32 txHash = keccak256(abi.encode(target, value, signature, data, eta));
        queuedTransactions[txHash] = false;

        emit CancelTransaction(txHash, target, value, signature, data, eta);
    }

    /**
     * @dev Executes a queued transaction after the delay period has passed
     * @param target The address of the contract where the transaction was queued.
     * @param value The amount of Ether sent with the transaction.
     * @param signature The function signature of the method to be called on the target contract.
     * @param data The data payload for the function call.
     * @param eta The estimated time (in seconds since the Unix epoch) when the transaction was scheduled.
     * @return bytes32 The return data from the executed transaction
     */
    function executeTransaction(
        address target,
        uint value,
        string memory signature,
        bytes memory data,
        uint eta
    ) external payable override onlyTimelockAdmin returns (bytes memory) {
        bytes32 txHash = keccak256(abi.encode(target, value, signature, data, eta));
        require(queuedTransactions[txHash], "Timelock::executeTransaction: Transaction hasn't been queued.");
        require(getBlockTimestamp() >= eta, "Timelock::executeTransaction: Transaction hasn't surpassed time lock.");
        require(getBlockTimestamp() <= eta.add(GRACE_PERIOD), "Timelock::executeTransaction: Transaction is stale.");

        queuedTransactions[txHash] = false;

        bytes memory callData;

        if (bytes(signature).length == 0) {
            callData = data;
        } else {
            callData = abi.encodePacked(bytes4(keccak256(bytes(signature))), data);
        }

        (bool success, bytes memory returnData) = target.call{value: value}(callData);
        require(success, "Timelock::executeTransaction: Transaction execution reverted.");

        emit ExecuteTransaction(txHash, target, value, signature, data, eta);

        return returnData;
    }

    /**
     * @dev Reverts the function call to set a pending administrator. This function is removed in this contract as it uses Access Control.
     * @param _pendingAdmin The address of the new pending administrator (not used in this implementation)
     */
    function setPendingAdmin(address _pendingAdmin) external pure override {
        require(_pendingAdmin != address(0), Errors.ADDRESS_IS_ZERO);
        revert(Errors.TIMELOCK_USES_ACCESS_CONTROL);
    }
}
