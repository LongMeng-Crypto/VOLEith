/* SPDX-License-Identifier: MIT */

#include "../circuits/sha256/sha256_circuit.hpp"
#include "../backend/circuit_format.hpp"

#include <boost/test/unit_test.hpp>
#include <openssl/evp.h>

#include <algorithm>

using faest::sha256_circuit::Circuit;
using faest::sha256_circuit::Digest;
using faest::sha256_circuit::Message;
using faest::sha256_circuit::Op;

BOOST_AUTO_TEST_SUITE(sha256_binary_circuit)

BOOST_AUTO_TEST_CASE(fifty_five_a_standard_vector) {
  Message message{};
  std::fill_n(message.begin(), 55, static_cast<std::uint8_t>('a'));
  const Digest expected = {
      0x9f, 0x43, 0x90, 0xf8, 0xd3, 0x0c, 0x2d, 0xd9,
      0x2e, 0xc9, 0xf0, 0x95, 0xb6, 0x5e, 0x2b, 0x9a,
      0xe9, 0xb0, 0xa9, 0x25, 0xa5, 0x25, 0x8e, 0x24,
      0x1c, 0x9f, 0x1e, 0x91, 0x0f, 0x73, 0x43, 0x18,
  };

  const Circuit circuit;
  BOOST_TEST(circuit.evaluate(message) == expected);
  BOOST_TEST(circuit.verify_statement(message, expected));

  auto wrong = expected;
  wrong[0] ^= 1;
  BOOST_TEST(!circuit.verify_statement(message, wrong));
}

BOOST_AUTO_TEST_CASE(structure_and_gate_count) {
  const Circuit circuit;
  const auto& stats = circuit.statistics();

  BOOST_TEST(stats.secret_inputs == 440U);
  BOOST_TEST_MESSAGE("SHA-256 circuit: " << stats.multiplication_gates << " AND gates, "
                                          << stats.xor_gates << " XOR gates, "
                                          << stats.total_nodes << " total nodes; schedule="
                                          << stats.schedule_multiplications << ", rounds="
                                          << stats.round_multiplications << ", feed-forward="
                                          << stats.feed_forward_multiplications);
  BOOST_TEST(stats.total_nodes == circuit.nodes().size());
  const auto ir_stats = circuit.binary_circuit().statistics();
  BOOST_TEST(ir_stats.private_inputs == stats.secret_inputs);
  BOOST_TEST(ir_stats.public_inputs == 0U);
  BOOST_TEST(ir_stats.xor_gates == stats.xor_gates);
  BOOST_TEST(ir_stats.multiplication_gates == stats.multiplication_gates);
  BOOST_TEST(circuit.binary_circuit().outputs().size() == 256U);
  BOOST_TEST(stats.multiplication_gates == 22217U);
  BOOST_TEST(stats.schedule_multiplications + stats.round_multiplications +
                 stats.feed_forward_multiplications ==
             stats.multiplication_gates);
  BOOST_TEST(std::count_if(circuit.nodes().begin(), circuit.nodes().end(),
                           [](const auto& node) { return node.op == Op::And; }) ==
             stats.multiplication_gates);

  for (const auto output : circuit.output_wires()) BOOST_TEST(output < circuit.nodes().size());

  Message message{};
  const auto witness = circuit.multiplication_witness(message);
  BOOST_TEST(witness.size() == stats.multiplication_gates);
  BOOST_TEST(std::all_of(witness.begin(), witness.end(), [](auto bit) { return bit <= 1; }));
}

BOOST_AUTO_TEST_CASE(additional_standard_vectors) {
  const Circuit circuit;
  Message zero{};
  const Digest zero_expected = {
      0x02, 0x77, 0x94, 0x66, 0xcd, 0xec, 0x16, 0x38,
      0x11, 0xd0, 0x78, 0x81, 0x5c, 0x63, 0x3f, 0x21,
      0x90, 0x14, 0x13, 0x08, 0x14, 0x49, 0x00, 0x2f,
      0x24, 0xaa, 0x3e, 0x80, 0xf0, 0xb8, 0x8e, 0xf7,
  };
  BOOST_TEST(circuit.evaluate(zero) == zero_expected);

  Message incremental{};
  for (std::size_t i = 0; i != 55; ++i) incremental[i] = i;
  const Digest incremental_expected = {
      0x46, 0x3e, 0xb2, 0x8e, 0x72, 0xf8, 0x2e, 0x0a,
      0x96, 0xc0, 0xa4, 0xcc, 0x53, 0x69, 0x0c, 0x57,
      0x12, 0x81, 0x13, 0x1f, 0x67, 0x2a, 0xa2, 0x29,
      0xe0, 0xd4, 0x5a, 0xe5, 0x9b, 0x59, 0x8b, 0x59,
  };
  BOOST_TEST(circuit.evaluate(incremental) == incremental_expected);
}

BOOST_AUTO_TEST_CASE(generic_multiblock_matches_openssl) {
  const std::array<std::size_t, 8> lengths = {0, 1, 55, 56, 64, 119, 120, 550};
  for (const auto length : lengths) {
    const Circuit circuit(length);
    Message message{};
    for (std::size_t i = 0; i != length; ++i) message[i] = static_cast<std::uint8_t>(7 * i + 3);
    Digest expected{};
    unsigned int output_size = 0;
    BOOST_REQUIRE(EVP_Digest(message.data(), length, expected.data(), &output_size,
                             EVP_sha256(), nullptr) == 1);
    BOOST_REQUIRE(output_size == expected.size());
    BOOST_TEST(circuit.evaluate(message) == expected, "length=" << length);
    BOOST_TEST(circuit.verify_statement(message, expected));
    BOOST_TEST(circuit.block_count() == (length * 8 + 65 + 511) / 512);
  }
  BOOST_TEST(Circuit(550).statistics().multiplication_gates == 202803U);
}

BOOST_AUTO_TEST_CASE(sha256_ir_vbc_round_trip) {
  const Circuit circuit(55);
  const auto encoded = vole_backend::serialize_vbc(circuit.binary_circuit());
  const auto decoded = vole_backend::deserialize_vbc(encoded);
  BOOST_TEST(decoded.statistics().private_inputs == 440U);
  BOOST_TEST(decoded.statistics().multiplication_gates == 22217U);
  BOOST_TEST(decoded.outputs().size() == 256U);
  BOOST_TEST(vole_backend::circuit_hash(decoded) ==
             vole_backend::circuit_hash(circuit.binary_circuit()));
}

BOOST_AUTO_TEST_SUITE_END()
