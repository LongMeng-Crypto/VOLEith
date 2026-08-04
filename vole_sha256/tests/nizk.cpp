/* SPDX-License-Identifier: MIT */

#include "../nizk.hpp"
#include "../faest_vole.hpp"
#include "../witness.hpp"

#include <boost/test/unit_test.hpp>

#include <openssl/evp.h>

#include <algorithm>

using faest::sha256_circuit::Circuit;
using faest::sha256_circuit::Message;

namespace {

struct NizkInputs {
  Circuit circuit;
  Message message{};
  faest::sha256_circuit::Digest digest{};
  std::array<std::uint8_t, 12> context = {'t', 'e', 's', 't', '-', 'c', 'o', 'n', 't', 'e', 'x', 't'};
  vole_sha256::ProverRandomness randomness{};

  NizkInputs() {
    for (std::size_t i = 0; i != circuit.message_length(); ++i) message[i] = static_cast<std::uint8_t>(i + 9);
    for (std::size_t i = 0; i != randomness.size(); ++i) {
      randomness[i] = static_cast<std::uint8_t>(0xc3U + 7U * i);
    }
    digest = circuit.evaluate(message);
  }
};

} // namespace

BOOST_AUTO_TEST_SUITE(vole_sha256_nizk)

BOOST_AUTO_TEST_CASE(prove_serialize_verify_round_trip) {
  NizkInputs input;
  const auto proof = vole_sha256::prove(input.circuit, input.message, input.digest, input.context,
                                        input.randomness);
  BOOST_TEST(proof.size() == vole_sha256::serialized_proof_bytes(input.circuit));
  BOOST_TEST(vole_sha256::verify(input.circuit, input.digest, input.context, proof));
}

BOOST_AUTO_TEST_CASE(proof_is_deterministic_given_randomness) {
  NizkInputs input;
  const auto first = vole_sha256::prove(input.circuit, input.message, input.digest, input.context,
                                        input.randomness);
  const auto second = vole_sha256::prove(input.circuit, input.message, input.digest, input.context,
                                         input.randomness);
  BOOST_TEST(first == second);

  auto other_randomness = input.randomness;
  other_randomness[0] ^= 1;
  const auto third = vole_sha256::prove(input.circuit, input.message, input.digest, input.context,
                                        other_randomness);
  BOOST_TEST(first != third);
  BOOST_TEST(vole_sha256::verify(input.circuit, input.digest, input.context, third));
}

BOOST_AUTO_TEST_CASE(statement_and_context_are_bound) {
  NizkInputs input;
  const auto proof = vole_sha256::prove(input.circuit, input.message, input.digest, input.context,
                                        input.randomness);
  auto wrong_digest = input.digest;
  wrong_digest[4] ^= 0x80;
  BOOST_TEST(!vole_sha256::verify(input.circuit, wrong_digest, input.context, proof));

  auto wrong_context = input.context;
  wrong_context[2] ^= 1;
  BOOST_TEST(!vole_sha256::verify(input.circuit, input.digest, wrong_context, proof));

  const Circuit wrong_length(input.circuit.message_length() - 1);
  BOOST_TEST(!vole_sha256::verify(wrong_length, input.digest, input.context, proof));
}

BOOST_AUTO_TEST_CASE(serialized_fields_are_bound) {
  NizkInputs input;
  const auto proof = vole_sha256::prove(input.circuit, input.message, input.digest, input.context,
                                        input.randomness);
  const auto witness = vole_sha256::witness_layout(input.circuit);
  const auto vole = vole_sha256::vole_layout(witness.vole_bits);
  const std::size_t u_tilde = 8 + vole.correction_bytes;
  const std::size_t d = u_tilde + 18;
  const std::size_t a1 = d + witness.vole_bytes;
  const std::size_t a2 = a1 + 16;
  const std::size_t opening = a2 + 16;
  const std::size_t challenge = opening + vole_sha256::vole_opening_bytes;
  const std::size_t iv = challenge + 16;
  const std::size_t counter = iv + 16;
  const std::array<std::size_t, 9> offsets = {
      0,      // magic/version
      100,    // VOLE correction
      u_tilde,
      d,
      a1,
      opening,
      challenge,
      iv,
      counter,
  };
  for (const auto offset : offsets) {
    auto tampered = proof;
    tampered[offset] ^= 1;
    BOOST_TEST(!vole_sha256::verify(input.circuit, input.digest, input.context, tampered),
               "tampered byte " << offset);
  }

  BOOST_TEST(!vole_sha256::verify(input.circuit, input.digest, input.context,
                                  std::span<const std::uint8_t>(proof.data(), proof.size() - 1)));
}

BOOST_AUTO_TEST_CASE(prover_rejects_false_statement) {
  NizkInputs input;
  input.digest[0] ^= 1;
  BOOST_CHECK_THROW(vole_sha256::prove(input.circuit, input.message, input.digest, input.context,
                                       input.randomness),
                    std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(maximum_length_nine_block_round_trip) {
  const Circuit circuit(550);
  Message message{};
  for (std::size_t i = 0; i != circuit.message_length(); ++i) {
    message[i] = static_cast<std::uint8_t>(11 * i + 5);
  }
  const auto digest = circuit.evaluate(message);
  const std::array<std::uint8_t, 9> context = {'m','a','x','-','5','5','0','-','v'};
  vole_sha256::ProverRandomness randomness{};
  randomness.fill(0x5a);
  const auto proof = vole_sha256::prove(circuit, message, digest, context, randomness);
  BOOST_TEST(proof.size() == vole_sha256::serialized_proof_bytes(circuit));
  BOOST_TEST(vole_sha256::verify(circuit, digest, context, proof));
}

BOOST_AUTO_TEST_CASE(known_answer_proof_fingerprint) {
  Circuit circuit;
  Message message{};
  for (std::size_t i = 0; i != circuit.message_length(); ++i) message[i] = static_cast<std::uint8_t>(i);
  const auto digest = circuit.evaluate(message);
  const std::array<std::uint8_t, 6> context = {'K', 'A', 'T', '-', 'v', '2'};
  vole_sha256::ProverRandomness randomness{};
  for (std::size_t i = 0; i != randomness.size(); ++i) randomness[i] = static_cast<std::uint8_t>(i);
  const auto proof = vole_sha256::prove(circuit, message, digest, context, randomness);

  std::array<std::uint8_t, 32> fingerprint{};
  unsigned int fingerprint_size = 0;
  BOOST_REQUIRE(EVP_Digest(proof.data(), proof.size(), fingerprint.data(), &fingerprint_size,
                           EVP_sha256(), nullptr) == 1);
  BOOST_REQUIRE(fingerprint_size == fingerprint.size());
  const std::array<std::uint8_t, 32> expected = {
      0x76, 0x1c, 0x0f, 0xb1, 0xae, 0x86, 0xda, 0xfb,
      0xec, 0x49, 0x2f, 0xf3, 0x04, 0xda, 0xb0, 0x50,
      0x47, 0x2f, 0xf0, 0x5e, 0x92, 0x39, 0x72, 0x59,
      0xd0, 0x26, 0xc9, 0xc9, 0xa1, 0x1c, 0xc8, 0x84,
  };
  BOOST_TEST(std::equal(fingerprint.begin(), fingerprint.end(), expected.begin()));
  BOOST_TEST(vole_sha256::verify(circuit, digest, context, proof));
}

BOOST_AUTO_TEST_SUITE_END()
