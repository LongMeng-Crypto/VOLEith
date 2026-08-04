/* SPDX-License-Identifier: MIT */

#include "../circuits/aes/aes128_circuit.hpp"
#include "../circuits/aes/aes128_faest_circuit.hpp"
#include "../backend/generic_nizk.hpp"

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(aes128_binary_circuit)

BOOST_AUTO_TEST_CASE(fips_197_known_answer) {
  const vole_circuits::aes::Aes128Circuit circuit;
  const vole_circuits::aes::Block key{
      0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
  const vole_circuits::aes::Block plaintext{
      0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
  const vole_circuits::aes::Block expected{
      0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a};
  BOOST_TEST(circuit.evaluate(key, plaintext) == expected);
  const auto stats = circuit.binary_circuit().statistics();
  BOOST_TEST(stats.private_inputs == 128U);
  BOOST_TEST(stats.public_inputs == 128U);
  BOOST_TEST(circuit.binary_circuit().outputs().size() == 128U);
  BOOST_TEST(stats.multiplication_gates == 76800U);
}

BOOST_AUTO_TEST_CASE(generic_proof_round_trip) {
  const vole_circuits::aes::Aes128Circuit frontend;
  vole_circuits::aes::Block key{}, plaintext{};
  for (unsigned i = 0; i != 16; ++i) { key[i] = i; plaintext[i] = 0x11U * i; }
  const auto ciphertext = frontend.evaluate(key, plaintext);
  std::vector<std::uint8_t> private_bits(128), public_bits(128), output_bits(128);
  for (unsigned i = 0; i != 128; ++i) {
    private_bits[i] = (key[i / 8] >> (i & 7U)) & 1U;
    public_bits[i] = (plaintext[i / 8] >> (i & 7U)) & 1U;
    output_bits[i] = (ciphertext[i / 8] >> (i & 7U)) & 1U;
  }
  const vole_backend::PublicStatement statement{public_bits, output_bits};
  const std::array<std::uint8_t, 10> context{'a','e','s','1','2','8','-','v','1','!'};
  vole_backend::ProverRandomness randomness{};
  for (unsigned i = 0; i != randomness.size(); ++i) randomness[i] = i;
  const auto& circuit = frontend.binary_circuit();
  const auto proof = vole_backend::prove(circuit, private_bits, statement, context, randomness);
  BOOST_TEST(proof.size() == vole_backend::serialized_proof_bytes(circuit));
  BOOST_TEST(vole_backend::verify(circuit, statement, context, proof));
}

BOOST_AUTO_TEST_CASE(faest_style_relation_round_trip) {
  const vole_circuits::aes::Aes128FaestRelation relation;
  const auto encoded = vole_backend::serialize_vqir(relation.ir());
  const auto decoded = vole_backend::deserialize_vqir(encoded);
  BOOST_TEST(decoded.private_input_bits == 128U);
  BOOST_TEST(decoded.auxiliary_witness_bits == 1152U);
  BOOST_TEST(decoded.multiplication_constraints == 200U);

  const vole_circuits::aes::Block key{
      0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
  const vole_circuits::aes::Block plaintext{
      0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
  const vole_circuits::aes::Block ciphertext{
      0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a};
  std::vector<std::uint8_t> private_bits(128), public_bits(128), output_bits(128);
  for (unsigned i = 0; i != 128; ++i) {
    private_bits[i] = (key[i / 8] >> (i & 7U)) & 1U;
    public_bits[i] = (plaintext[i / 8] >> (i & 7U)) & 1U;
    output_bits[i] = (ciphertext[i / 8] >> (i & 7U)) & 1U;
  }
  const vole_backend::PublicStatement statement{public_bits, output_bits};
  const std::array<std::uint8_t, 12> context{'a','e','s','-','f','a','e','s','t','-','v','1'};
  vole_backend::ProverRandomness randomness{};
  for (unsigned i = 0; i != randomness.size(); ++i) randomness[i] = i;
  const auto proof = vole_backend::prove(relation, private_bits, statement, context, randomness);
  BOOST_TEST(proof.size() == vole_backend::serialized_proof_bytes(relation));
  BOOST_TEST(vole_backend::verify(relation, statement, context, proof));

  auto wrong = statement;
  wrong.expected_outputs[0] ^= 1;
  BOOST_TEST(!vole_backend::verify(relation, wrong, context, proof));
}

BOOST_AUTO_TEST_SUITE_END()
