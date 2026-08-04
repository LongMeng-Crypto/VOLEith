/* SPDX-License-Identifier: MIT */

#include "../backend/binary_circuit.hpp"

#include <boost/test/unit_test.hpp>

#include <array>
#include <string>
#include <vector>

BOOST_AUTO_TEST_SUITE(binary_circuit_ir)

BOOST_AUTO_TEST_CASE(build_validate_and_evaluate) {
  vole_backend::BinaryCircuit circuit;
  vole_backend::CircuitBuilder builder(circuit);
  const auto a = builder.private_input();
  const auto b = builder.private_input();
  const auto c = builder.public_input();
  const auto sum = builder.xor_wire(a, b);
  const auto product = builder.and_wire(sum, c);
  builder.output(product);

  std::string error;
  BOOST_TEST(circuit.validate(&error), error);
  const auto stats = circuit.statistics();
  BOOST_TEST(stats.private_inputs == 2U);
  BOOST_TEST(stats.public_inputs == 1U);
  BOOST_TEST(stats.xor_gates == 1U);
  BOOST_TEST(stats.multiplication_gates == 1U);

  const std::array<std::uint8_t, 2> private_bits = {1, 0};
  const std::array<std::uint8_t, 1> public_bits = {1};
  const auto evaluation = circuit.evaluate(private_bits, public_bits);
  BOOST_REQUIRE(evaluation.outputs.size() == 1U);
  BOOST_TEST(evaluation.outputs[0] == 1U);
  BOOST_TEST(evaluation.multiplication_outputs == std::vector<std::uint8_t>{1});
}

BOOST_AUTO_TEST_CASE(canonical_constant_propagation) {
  vole_backend::BinaryCircuit circuit;
  vole_backend::CircuitBuilder builder(circuit);
  const auto input = builder.private_input();
  BOOST_TEST(builder.xor_wire(input, builder.zero()) == input);
  BOOST_TEST(builder.xor_wire(input, input) == builder.zero());
  BOOST_TEST(builder.and_wire(input, builder.one()) == input);
  BOOST_TEST(builder.and_wire(input, builder.zero()) == builder.zero());
  BOOST_TEST(circuit.statistics().xor_gates == 0U);
  BOOST_TEST(circuit.statistics().multiplication_gates == 0U);
}

BOOST_AUTO_TEST_SUITE_END()
