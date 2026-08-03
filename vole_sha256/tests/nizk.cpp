/* SPDX-License-Identifier: MIT */

#include "../nizk.hpp"

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
    for (std::size_t i = 0; i != message.size(); ++i) message[i] = static_cast<std::uint8_t>(i + 9);
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
  BOOST_TEST(proof.size() == vole_sha256::serialized_proof_bytes);
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
}

BOOST_AUTO_TEST_CASE(serialized_fields_are_bound) {
  NizkInputs input;
  const auto proof = vole_sha256::prove(input.circuit, input.message, input.digest, input.context,
                                        input.randomness);
  const std::array<std::size_t, 9> offsets = {
      0,      // magic/version
      100,    // VOLE correction
      50070,  // u_tilde
      51000,  // d
      55045,  // a1/a2
      55500,  // BAVC opening
      57240,  // challenge_3
      57255,  // iv_pre
      57269,  // counter
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

BOOST_AUTO_TEST_CASE(known_answer_proof_fingerprint) {
  Circuit circuit;
  Message message{};
  for (std::size_t i = 0; i != message.size(); ++i) message[i] = static_cast<std::uint8_t>(i);
  const auto digest = circuit.evaluate(message);
  const std::array<std::uint8_t, 6> context = {'K', 'A', 'T', '-', 'v', '1'};
  vole_sha256::ProverRandomness randomness{};
  for (std::size_t i = 0; i != randomness.size(); ++i) randomness[i] = static_cast<std::uint8_t>(i);
  const auto proof = vole_sha256::prove(circuit, message, digest, context, randomness);

  std::array<std::uint8_t, 32> fingerprint{};
  unsigned int fingerprint_size = 0;
  BOOST_REQUIRE(EVP_Digest(proof.data(), proof.size(), fingerprint.data(), &fingerprint_size,
                           EVP_sha256(), nullptr) == 1);
  BOOST_REQUIRE(fingerprint_size == fingerprint.size());
  const std::array<std::uint8_t, 32> expected = {
      0x08, 0x49, 0x27, 0xa0, 0x52, 0x23, 0x79, 0xee,
      0xa5, 0xa6, 0x56, 0x0f, 0x25, 0x53, 0xaa, 0xcb,
      0x07, 0x20, 0xbd, 0xab, 0xea, 0x9c, 0x69, 0x4e,
      0xba, 0x90, 0xca, 0xa0, 0xa0, 0x28, 0x43, 0xfe,
  };
  // Compare the byte representation directly.  Boost.Test's expression
  // decomposition has produced optimization-dependent results for
  // std::array<uint8_t, N> equality with some Boost/GCC combinations.
  BOOST_TEST(std::equal(fingerprint.begin(), fingerprint.end(), expected.begin()));
  BOOST_TEST(vole_sha256::verify(circuit, digest, context, proof));
}

BOOST_AUTO_TEST_SUITE_END()
