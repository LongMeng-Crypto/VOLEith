/* SPDX-License-Identifier: MIT */

#include "../backend/circuit_format.hpp"
#include "../backend/generic_nizk.hpp"
#include "../backend/json_circuit.hpp"

#include <boost/test/unit_test.hpp>

namespace {

vole_backend::CircuitHash hash_bytes(std::string_view hex) {
  vole_backend::CircuitHash result{};
  if (hex.size() != result.size() * 2) throw std::invalid_argument("bad test hash");
  const auto nibble = [](char c) -> std::uint8_t {
    if (c >= '0' && c <= '9') return c - '0';
    return static_cast<std::uint8_t>(c - 'a' + 10);
  };
  for (std::size_t i = 0; i != result.size(); ++i)
    result[i] = static_cast<std::uint8_t>((nibble(hex[2 * i]) << 4) | nibble(hex[2 * i + 1]));
  return result;
}

vole_backend::BinaryCircuit example_circuit(bool product_output = true) {
  vole_backend::BinaryCircuit circuit;
  vole_backend::CircuitBuilder builder(circuit);
  const auto a = builder.private_input();
  const auto b = builder.private_input();
  const auto c = builder.public_input();
  const auto sum = builder.xor_wire(a, b);
  const auto product = builder.and_wire(sum, c);
  builder.output(product_output ? product : sum);
  return circuit;
}

} // namespace

BOOST_AUTO_TEST_SUITE(generic_vole_backend)

BOOST_AUTO_TEST_CASE(vbc_round_trip_hash_and_rejection) {
  const auto circuit = example_circuit();
  const auto encoded = vole_backend::serialize_vbc(circuit);
  const auto decoded = vole_backend::deserialize_vbc(encoded);
  BOOST_TEST(vole_backend::serialize_vbc(decoded) == encoded);
  BOOST_TEST(vole_backend::circuit_hash(decoded) == vole_backend::circuit_hash(circuit));

  auto bad_magic = encoded;
  bad_magic[0] ^= 1;
  BOOST_CHECK_THROW(vole_backend::deserialize_vbc(bad_magic), std::invalid_argument);
  auto trailing = encoded;
  trailing.push_back(0);
  BOOST_CHECK_THROW(vole_backend::deserialize_vbc(trailing), std::invalid_argument);
  auto bad_opcode = encoded;
  bad_opcode[16] = 0xff;
  BOOST_CHECK_THROW(vole_backend::deserialize_vbc(bad_opcode), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(json_and_xor_known_answer) {
  constexpr std::string_view json = R"json({
    "format":"vole-binary-circuit", "version":1,
    "nodes":[
      {"op":"constant","value":0}, {"op":"constant","value":1},
      {"op":"private"}, {"op":"private"}, {"op":"public"},
      {"op":"xor","lhs":2,"rhs":3}, {"op":"and","lhs":5,"rhs":4}
    ],
    "outputs":[5,6]
  })json";
  const auto circuit = vole_backend::compile_json_circuit(json);
  BOOST_TEST(vole_backend::circuit_hash(circuit) ==
             hash_bytes("fbf8b643be908696be7e46e603aa506447e6fc9c7c7c52b313cdcdfb60aad7b5"));
  const auto stats = circuit.statistics();
  BOOST_TEST(stats.private_inputs == 2U);
  BOOST_TEST(stats.public_inputs == 1U);
  BOOST_TEST(stats.xor_gates == 1U);
  BOOST_TEST(stats.multiplication_gates == 1U);

  // KAT truth table: outputs are (a XOR b, (a XOR b) AND c).
  for (std::uint8_t a = 0; a != 2; ++a) {
    for (std::uint8_t b = 0; b != 2; ++b) {
      for (std::uint8_t c = 0; c != 2; ++c) {
        const std::array<std::uint8_t, 2> private_inputs{a, b};
        const std::array<std::uint8_t, 1> public_inputs{c};
        const auto evaluation = circuit.evaluate(private_inputs, public_inputs);
        const std::vector<std::uint8_t> expected{
            static_cast<std::uint8_t>(a ^ b),
            static_cast<std::uint8_t>((a ^ b) & c)};
        BOOST_TEST(evaluation.outputs == expected);
      }
    }
  }

  BOOST_CHECK_THROW(vole_backend::compile_json_circuit(
      R"({"format":"vole-binary-circuit","version":1,"extra":0,"nodes":[],"outputs":[]})"),
      std::invalid_argument);

  const std::array<std::uint8_t, 2> private_inputs{1, 0};
  const vole_backend::PublicStatement statement{{1}, {1, 1}};
  const std::array<std::uint8_t, 14> context{
      'a','n','d','-','x','o','r','-','k','a','t','-','v','1'};
  vole_backend::ProverRandomness randomness{};
  for (std::size_t i = 0; i != randomness.size(); ++i)
    randomness[i] = static_cast<std::uint8_t>(i);
  const auto proof = vole_backend::prove(circuit, private_inputs, statement, context, randomness);
  BOOST_TEST(proof.size() == 2765U);
  BOOST_TEST(vole_backend::circuit_hash(proof) ==
             hash_bytes("9bbdccb03de71ad97a7c7efa38842028b2c55003521a99cb96dd5527efa4a323"));
  BOOST_TEST(vole_backend::verify(circuit, statement, context, proof));
}

BOOST_AUTO_TEST_CASE(private_public_generic_nizk_round_trip) {
  const auto source_circuit = example_circuit();
  const auto circuit = vole_backend::deserialize_vbc(
      vole_backend::serialize_vbc(source_circuit));
  const std::array<std::uint8_t, 2> private_inputs = {1, 0};
  vole_backend::PublicStatement statement{{1}, {1}};
  const std::array<std::uint8_t, 10> context = {'g','e','n','e','r','i','c','-','v','1'};
  vole_backend::ProverRandomness randomness{};
  for (std::size_t i = 0; i != randomness.size(); ++i) randomness[i] = static_cast<std::uint8_t>(i + 1);

  const auto proof = vole_backend::prove(circuit, private_inputs, statement, context, randomness);
  BOOST_TEST(proof.size() == vole_backend::serialized_proof_bytes(circuit));
  BOOST_TEST(vole_backend::verify(circuit, statement, context, proof));

  auto wrong_public = statement;
  wrong_public.public_inputs[0] ^= 1;
  BOOST_TEST(!vole_backend::verify(circuit, wrong_public, context, proof));
  auto wrong_output = statement;
  wrong_output.expected_outputs[0] ^= 1;
  BOOST_TEST(!vole_backend::verify(circuit, wrong_output, context, proof));
  auto wrong_context = context;
  wrong_context[0] ^= 1;
  BOOST_TEST(!vole_backend::verify(circuit, statement, wrong_context, proof));

  // Same node count and witness size, different declared output: the circuit
  // hash binding must make the original proof invalid.
  const auto other_circuit = example_circuit(false);
  BOOST_TEST(vole_backend::serialized_proof_bytes(other_circuit) == proof.size());
  BOOST_TEST(!vole_backend::verify(other_circuit, statement, context, proof));

  auto tampered = proof;
  tampered[tampered.size() / 2] ^= 1;
  BOOST_TEST(!vole_backend::verify(circuit, statement, context, tampered));
}

BOOST_AUTO_TEST_SUITE_END()
