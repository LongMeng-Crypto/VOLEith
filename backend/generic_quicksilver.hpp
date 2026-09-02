/* SPDX-License-Identifier: MIT */
#ifndef VOLE_BACKEND_GENERIC_QUICKSILVER_HPP
#define VOLE_BACKEND_GENERIC_QUICKSILVER_HPP

#include "backend_witness.hpp"
#include "prepared_binary_circuit.hpp"
#include "security_parameters.hpp"
#include "quicksilver_types.hpp"

#include <span>

namespace vole_backend {

QuicksilverProof quicksilver_prove(
    const BinaryCircuit& circuit, const PackedWitness& witness,
    std::span<const std::uint8_t> public_inputs,
    std::span<const std::uint8_t> expected_outputs,
    const std::vector<std::uint8_t*>& v_columns, const std::uint8_t* u_after_witness,
    const QuicksilverChallenge& challenge_2);

std::array<std::uint8_t, lambda_bytes> quicksilver_verify(
    const BinaryCircuit& circuit, const PackedWitness& masked_witness,
    std::span<const std::uint8_t> public_inputs,
    std::span<const std::uint8_t> expected_outputs,
    const std::vector<std::uint8_t*>& q_columns,
    const std::array<std::uint8_t, lambda_bytes>& delta_bytes,
    const QuicksilverChallenge& challenge_2,
    const QuicksilverProof& proof);

ParameterizedQuicksilverProof quicksilver_prove(
    SecurityLevel security, const PreparedBinaryCircuit& circuit,
    const PackedWitness& witness, std::span<const std::uint8_t> public_inputs,
    std::span<const std::uint8_t> expected_outputs,
    const std::vector<std::uint8_t*>& v_columns,
    const std::uint8_t* u_after_witness,
    std::span<const std::uint8_t> challenge_2);

ParameterizedQuicksilverProof quicksilver_prove(
    SecurityLevel security, const BinaryCircuit& circuit,
    const PackedWitness& witness, std::span<const std::uint8_t> public_inputs,
    std::span<const std::uint8_t> expected_outputs,
    const std::vector<std::uint8_t*>& v_columns,
    const std::uint8_t* u_after_witness,
    std::span<const std::uint8_t> challenge_2);

std::vector<std::uint8_t> quicksilver_verify(
    SecurityLevel security, const PreparedBinaryCircuit& circuit,
    const PackedWitness& masked_witness,
    std::span<const std::uint8_t> public_inputs,
    std::span<const std::uint8_t> expected_outputs,
    const std::vector<std::uint8_t*>& q_columns,
    std::span<const std::uint8_t> delta,
    std::span<const std::uint8_t> challenge_2,
    const ParameterizedQuicksilverProof& proof);

std::vector<std::uint8_t> quicksilver_verify(
    SecurityLevel security, const BinaryCircuit& circuit,
    const PackedWitness& masked_witness,
    std::span<const std::uint8_t> public_inputs,
    std::span<const std::uint8_t> expected_outputs,
    const std::vector<std::uint8_t*>& q_columns,
    std::span<const std::uint8_t> delta,
    std::span<const std::uint8_t> challenge_2,
    const ParameterizedQuicksilverProof& proof);

} // namespace vole_backend

#endif
