/* SPDX-License-Identifier: MIT */

#include "../circuits/sha256/faest_quicksilver.hpp"
#include "../backend/faest_vole.hpp"
#include "../circuits/sha256/witness.hpp"

#include <boost/test/unit_test.hpp>

#include <algorithm>

using faest::sha256_circuit::Circuit;
using faest::sha256_circuit::Message;

namespace {

std::array<std::uint8_t, vole_backend::lambda_bytes> root_key() {
  std::array<std::uint8_t, vole_backend::lambda_bytes> key{};
  for (std::size_t i = 0; i != key.size(); ++i) key[i] = static_cast<std::uint8_t>(i);
  return key;
}

vole_backend::QuicksilverChallenge challenge_2() {
  vole_backend::QuicksilverChallenge challenge{};
  for (std::size_t i = 0; i != challenge.size(); ++i) {
    challenge[i] = static_cast<std::uint8_t>(0xa5U ^ (17U * i));
  }
  return challenge;
}

struct Fixture {
  Circuit circuit;
  Message message{};
  faest::sha256_circuit::Digest digest{};
  vole_sha256::PackedWitness witness{};
  std::array<std::uint8_t, 16> iv{};
  vole_backend::FaestVoleCommitment commitment;
  vole_backend::ReconstructedVole reconstructed;

  Fixture()
      : commitment(root_key(), iv, vole_sha256::witness_layout(circuit).vole_bits) {
    for (std::size_t i = 0; i != circuit.message_length(); ++i) {
      message[i] = static_cast<std::uint8_t>(3 * i + 1);
    }
    digest = circuit.evaluate(message);
    witness = vole_sha256::build_witness(circuit, message);
    reconstructed = commitment.open_and_reconstruct();
  }
};

} // namespace

BOOST_AUTO_TEST_SUITE(vole_sha256_faest_integration)

BOOST_AUTO_TEST_CASE(real_vole_commit_and_reconstruct) {
  Fixture fixture;
  const auto layout = vole_sha256::witness_layout(fixture.circuit);
  const auto vole = vole_backend::vole_layout(layout.vole_bits);
  BOOST_TEST(fixture.commitment.parameters().lambda == 128U);
  BOOST_TEST(fixture.commitment.u().size() == vole.ell_hat_bytes);
  BOOST_TEST(fixture.reconstructed.q_storage.size() ==
             vole_backend::lambda_bits * vole.ell_hat_bytes);
  BOOST_TEST(vole_backend::check_vole_correlation(fixture.commitment, fixture.reconstructed));
}

BOOST_AUTO_TEST_CASE(real_quicksilver_accepts_sha256_relation) {
  Fixture fixture;
  auto v = fixture.commitment.v_columns();
  auto q = fixture.reconstructed.columns();
  const auto masked = vole_backend::mask_witness(fixture.witness, fixture.commitment.u());
  const auto chall2 = challenge_2();
  const auto layout = vole_sha256::witness_layout(fixture.circuit);

  const auto proof = vole_sha256::sha256_quicksilver_prove(
      fixture.circuit, fixture.witness, v,
      fixture.commitment.u().data() + layout.vole_bytes, fixture.digest, chall2);
  const auto reconstructed_a0 = vole_sha256::sha256_quicksilver_verify(
      fixture.circuit, masked, q, fixture.reconstructed.challenge, fixture.digest, chall2, proof);
  BOOST_TEST(reconstructed_a0 == proof.a0);
}

BOOST_AUTO_TEST_CASE(wrong_public_digest_is_rejected) {
  Fixture fixture;
  auto v = fixture.commitment.v_columns();
  auto q = fixture.reconstructed.columns();
  const auto masked = vole_backend::mask_witness(fixture.witness, fixture.commitment.u());
  const auto chall2 = challenge_2();
  const auto layout = vole_sha256::witness_layout(fixture.circuit);
  const auto proof = vole_sha256::sha256_quicksilver_prove(
      fixture.circuit, fixture.witness, v,
      fixture.commitment.u().data() + layout.vole_bytes, fixture.digest, chall2);

  auto wrong_digest = fixture.digest;
  wrong_digest[17] ^= 0x08;
  const auto reconstructed_a0 = vole_sha256::sha256_quicksilver_verify(
      fixture.circuit, masked, q, fixture.reconstructed.challenge, wrong_digest, chall2, proof);
  BOOST_TEST(reconstructed_a0 != proof.a0);
}

BOOST_AUTO_TEST_CASE(wrong_and_output_is_rejected) {
  Fixture fixture;
  auto bad_witness = fixture.witness;
  const std::size_t bad_bit = fixture.circuit.secret_input_bits() + 10000;
  bad_witness[bad_bit / 8] ^= static_cast<std::uint8_t>(1U << (bad_bit % 8));

  auto v = fixture.commitment.v_columns();
  auto q = fixture.reconstructed.columns();
  const auto bad_masked = vole_backend::mask_witness(bad_witness, fixture.commitment.u());
  const auto chall2 = challenge_2();
  const auto layout = vole_sha256::witness_layout(fixture.circuit);
  const auto proof = vole_sha256::sha256_quicksilver_prove(
      fixture.circuit, bad_witness, v,
      fixture.commitment.u().data() + layout.vole_bytes, fixture.digest, chall2);
  const auto reconstructed_a0 = vole_sha256::sha256_quicksilver_verify(
      fixture.circuit, bad_masked, q, fixture.reconstructed.challenge, fixture.digest, chall2,
      proof);
  BOOST_TEST(reconstructed_a0 != proof.a0);
}

BOOST_AUTO_TEST_CASE(tampered_masked_witness_is_rejected) {
  Fixture fixture;
  auto v = fixture.commitment.v_columns();
  auto q = fixture.reconstructed.columns();
  auto masked = vole_backend::mask_witness(fixture.witness, fixture.commitment.u());
  const auto chall2 = challenge_2();
  const auto layout = vole_sha256::witness_layout(fixture.circuit);
  const auto proof = vole_sha256::sha256_quicksilver_prove(
      fixture.circuit, fixture.witness, v,
      fixture.commitment.u().data() + layout.vole_bytes, fixture.digest, chall2);

  masked[731] ^= 0x40;
  const auto reconstructed_a0 = vole_sha256::sha256_quicksilver_verify(
      fixture.circuit, masked, q, fixture.reconstructed.challenge, fixture.digest, chall2, proof);
  BOOST_TEST(reconstructed_a0 != proof.a0);
}

BOOST_AUTO_TEST_SUITE_END()
