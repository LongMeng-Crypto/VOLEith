/* SPDX-License-Identifier: MIT */

#include "../circuits/aes/aes128_faest_circuit.hpp"
#include "../backend/circuit_format.hpp"
#include "../backend/generic_nizk.hpp"

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(aes128_faest_relation)

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
  const std::array expected_fingerprints{
      std::array<std::uint8_t, 32>{0x71,0x9b,0x8f,0x9e,0x54,0x01,0xec,0xce,0x22,0xd0,0x46,0xb8,0x4c,0x8d,0x1e,0xfc,0xbc,0x67,0xe4,0x74,0x76,0x08,0xcb,0x6e,0x58,0x11,0xcc,0xef,0xde,0x05,0x19,0xe0},
      std::array<std::uint8_t, 32>{0x37,0x2a,0xb7,0xc8,0xb0,0xad,0x62,0xfd,0xc5,0x87,0xc3,0x25,0x6f,0x0b,0xcb,0x65,0xee,0xf9,0x91,0xde,0xa8,0x93,0x1e,0x38,0x55,0x17,0xbc,0x50,0x85,0xe3,0xcf,0x83},
  };
  std::size_t profile_index = 0;
  for (const auto profile : {vole_backend::VoleProfile::Small,
                             vole_backend::VoleProfile::Fast}) {
    const auto proof = vole_backend::prove(
        relation, profile, private_bits, statement, context, randomness);
    BOOST_TEST(
        proof.size() == vole_backend::serialized_proof_bytes(relation, profile));
    BOOST_TEST(proof[5] == 4U);
    BOOST_TEST(proof[6] == 1U);
    BOOST_TEST(proof[7] == vole_backend::vole_profile_code(profile));
    BOOST_TEST(vole_backend::circuit_hash(proof) ==
               expected_fingerprints[profile_index++]);
    BOOST_TEST(vole_backend::verify(relation, profile, statement, context,
                                    proof));

    const auto other = profile == vole_backend::VoleProfile::Small
                           ? vole_backend::VoleProfile::Fast
                           : vole_backend::VoleProfile::Small;
    BOOST_TEST(!vole_backend::verify(relation, other, statement, context,
                                     proof));
    auto wrong = statement;
    wrong.expected_outputs[0] ^= 1;
    BOOST_TEST(!vole_backend::verify(relation, profile, wrong, context,
                                     proof));
    auto tampered = proof;
    tampered[tampered.size() / 2] ^= 1;
    BOOST_TEST(!vole_backend::verify(relation, profile, statement, context,
                                     tampered));
  }
}

BOOST_AUTO_TEST_SUITE_END()
