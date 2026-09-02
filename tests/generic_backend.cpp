/* SPDX-License-Identifier: MIT */

#include "../backend/circuit_format.hpp"
#include "../backend/backend_witness.hpp"
#include "../backend/generic_nizk.hpp"
#include "../backend/generic_quicksilver.hpp"
#include "../backend/json_circuit.hpp"
#include "../backend/quadratic_relation.hpp"
#include "../backend/vole/faest_vole.hpp"

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

class LegacyTestRelation final : public vole_backend::QuicksilverRelation {
public:
  explicit LegacyTestRelation(const vole_backend::BinaryCircuit& circuit)
      : circuit_(circuit) {}
  std::array<std::uint8_t, 32> id() const override {
    return vole_backend::circuit_hash(circuit_);
  }
  std::size_t private_input_bits() const override {
    return circuit_.statistics().private_inputs;
  }
  std::size_t public_input_bits() const override {
    return circuit_.statistics().public_inputs;
  }
  std::size_t output_bits() const override { return circuit_.outputs().size(); }
  std::size_t witness_bits() const override {
    return vole_backend::witness_layout(circuit_).vole_bits;
  }
  std::vector<std::uint8_t> build_witness(
      std::span<const std::uint8_t> private_inputs,
      const vole_backend::PublicStatement& statement) const override {
    return vole_backend::build_witness(circuit_, private_inputs,
                                       statement.public_inputs);
  }
  vole_backend::QuicksilverProof prove_constraints(
      std::span<const std::uint8_t> witness,
      const vole_backend::PublicStatement& statement,
      const std::vector<std::uint8_t*>& v, const std::uint8_t* u_extra,
      const vole_backend::QuicksilverChallenge& challenge) const override {
    return vole_backend::quicksilver_prove(
        circuit_, {witness.begin(), witness.end()}, statement.public_inputs,
        statement.expected_outputs, v, u_extra, challenge);
  }
  std::array<std::uint8_t, vole_backend::lambda_bytes> verify_constraints(
      std::span<const std::uint8_t> d,
      const vole_backend::PublicStatement& statement,
      const std::vector<std::uint8_t*>& q,
      const std::array<std::uint8_t, vole_backend::lambda_bytes>& delta,
      const vole_backend::QuicksilverChallenge& challenge,
      const vole_backend::QuicksilverProof& proof) const override {
    return vole_backend::quicksilver_verify(
        circuit_, {d.begin(), d.end()}, statement.public_inputs,
        statement.expected_outputs, q, delta, challenge, proof);
  }

private:
  const vole_backend::BinaryCircuit& circuit_;
};

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
             hash_bytes("deea83c8346414a27ea59fee8e0d91ac28fa5affd9f5d5f8908bcec180586c11"));
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

BOOST_AUTO_TEST_CASE(parameterized_soundness_round_trip_and_separation) {
  const auto circuit = example_circuit();
  const std::array<std::uint8_t, 2> private_inputs = {1, 0};
  const vole_backend::PublicStatement statement{{1}, {1}};
  const std::array<std::uint8_t, 17> context = {
      's','e','c','u','r','i','t','y','-','l','e','v','e','l','-','v','2'};
  vole_backend::ProverRandomness randomness{};
  for (std::size_t i = 0; i != randomness.size(); ++i)
    randomness[i] = static_cast<std::uint8_t>(0x41 + i);

  const std::array levels = {
      vole_backend::SecurityLevel::Bits128,
      vole_backend::SecurityLevel::Bits192,
      vole_backend::SecurityLevel::Bits256,
  };
  const std::array<std::size_t, 3> expected_sizes = {2765, 6292, 12190};
  std::array<std::vector<std::uint8_t>, 3> proofs;
  for (std::size_t i = 0; i != levels.size(); ++i) {
    proofs[i] = vole_backend::prove(circuit, levels[i], private_inputs,
                                    statement, context, randomness);
    BOOST_TEST(proofs[i].size() == expected_sizes[i]);
    BOOST_TEST(proofs[i].size() ==
               vole_backend::serialized_proof_bytes(circuit, levels[i]));
    BOOST_TEST(vole_backend::verify(circuit, levels[i], statement, context,
                                    proofs[i]));
    for (const auto other : levels) {
      if (other != levels[i])
        BOOST_TEST(!vole_backend::verify(circuit, other, statement, context,
                                         proofs[i]));
    }
    auto tampered = proofs[i];
    tampered[6] = static_cast<std::uint8_t>(tampered[6] % 3 + 1);
    if (tampered[6] == proofs[i][6]) tampered[6] = tampered[6] % 3 + 1;
    BOOST_TEST(!vole_backend::verify(circuit, levels[i], statement, context,
                                     tampered));
    tampered = proofs[i];
    tampered[tampered.size() / 2] ^= 1;
    BOOST_TEST(!vole_backend::verify(circuit, levels[i], statement, context,
                                     tampered));
  }
  BOOST_TEST(proofs[0] != proofs[1]);
  BOOST_TEST(proofs[1] != proofs[2]);
}

BOOST_AUTO_TEST_CASE(parameterized_faest_vole_layouts) {
  struct Expected {
    vole_backend::SecurityLevel level;
    std::size_t lambda;
    std::size_t tau;
    std::size_t opening;
  };
  const std::array expected = {
      Expected{vole_backend::SecurityLevel::Bits128, 128, 11, 2160},
      Expected{vole_backend::SecurityLevel::Bits192, 192, 16, 5040},
      Expected{vole_backend::SecurityLevel::Bits256, 256, 22, 9952},
  };
  for (const auto& item : expected) {
    const auto parameters = vole_backend::faest_vole_parameters(item.level);
    BOOST_TEST(parameters.lambda == item.lambda);
    BOOST_TEST(parameters.tau == item.tau);
    BOOST_TEST(vole_backend::vole_opening_size(item.level) == item.opening);
    const auto layout = vole_backend::vole_layout(8, item.level);
    BOOST_TEST(layout.correction_bytes ==
               (item.tau - 1) * layout.ell_hat_bytes);
  }
}

BOOST_AUTO_TEST_CASE(legacy_128_binary_proof_remains_verifiable) {
  const auto circuit = example_circuit();
  const LegacyTestRelation legacy(circuit);
  const std::array<std::uint8_t, 2> private_inputs = {1, 0};
  const vole_backend::PublicStatement statement{{1}, {1}};
  const std::array<std::uint8_t, 9> context = {'l','e','g','a','c','y','-','v','1'};
  vole_backend::ProverRandomness randomness{};
  randomness.fill(0x77);
  const auto proof = vole_backend::prove(
      static_cast<const vole_backend::QuicksilverRelation&>(legacy),
      private_inputs, statement, context, randomness);
  BOOST_TEST(proof[5] == 1U);
  BOOST_TEST(vole_backend::verify(circuit,
                                  vole_backend::SecurityLevel::Bits128,
                                  statement, context, proof));
  BOOST_TEST(!vole_backend::verify(circuit,
                                   vole_backend::SecurityLevel::Bits192,
                                   statement, context, proof));
}

BOOST_AUTO_TEST_SUITE_END()
