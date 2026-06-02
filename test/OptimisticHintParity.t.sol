// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Test} from "forge-std/Test.sol";
import {MLDSAOptimistic} from "../src/MLDSAOptimistic.sol";

contract OptHarness is MLDSAOptimistic {
    constructor() MLDSAOptimistic(300, 0.01 ether) {}

    function exec(uint8 opcode, bytes calldata input) external pure returns (bytes memory) {
        return executeStep(opcode, input);
    }
}

/// @title OptimisticHintParity
/// @notice Cross-language parity: re-executes every generated verification step
///         emitted by the TypeScript hint generator (test/vectors/optimistic-steps.json,
///         produced from the repo's real ML-DSA-65 vector) — all opcodes:
///         ExpandA, SHAKE-256, SampleInBall, and the polynomial primitives — and
///         asserts the on-chain executeStep() reproduces each output byte-for-byte.
///
///         This is the guarantee that the off-chain generator and the on-chain
///         fraud-proof re-execution agree — so an honest prover's commitment is
///         never spuriously challengeable and a dishonest one always is.
contract OptimisticHintParityTest is Test {
    OptHarness opt;

    function setUp() public {
        opt = new OptHarness();
    }

    function test_AllSteps_MatchOnChain() public view {
        string memory json = vm.readFile("test/vectors/optimistic-steps.json");

        uint256 count = vm.parseJsonUint(json, ".count");
        uint256[] memory opcodes = vm.parseJsonUintArray(json, ".opcodes");
        bytes[] memory inputs = vm.parseJsonBytesArray(json, ".inputs");
        bytes[] memory outputs = vm.parseJsonBytesArray(json, ".outputs");

        assertEq(opcodes.length, count, "opcodes len");
        assertEq(inputs.length, count, "inputs len");
        assertEq(outputs.length, count, "outputs len");
        // Full coverage: every emitted step (ExpandA, SHAKE-256, SampleInBall,
        // and all polynomial primitives), not just opcode>=3.
        assertGt(count, 135, "expected the full step set incl. final-result opcodes");

        for (uint256 i = 0; i < count; i++) {
            bytes memory got = opt.exec(uint8(opcodes[i]), inputs[i]);
            assertEq(
                keccak256(got),
                keccak256(outputs[i]),
                string.concat("step ", vm.toString(i), " (opcode ", vm.toString(opcodes[i]), ") mismatch")
            );
        }
    }
}
