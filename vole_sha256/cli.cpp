/* SPDX-License-Identifier: MIT */

#include "nizk.hpp"
#include "sha256_circuit.hpp"
#include "witness.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <chrono>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#if defined(__unix__) || defined(__APPLE__)
#include <sys/resource.h>
#endif

namespace {

using Circuit = faest::sha256_circuit::Circuit;
using Digest = faest::sha256_circuit::Digest;
using Message = faest::sha256_circuit::Message;

std::vector<std::uint8_t> from_hex(std::string_view text) {
  if (text.size() % 2 != 0) throw std::invalid_argument("hex value has odd length");
  const auto nibble = [](char c) -> unsigned int {
    if (c >= '0' && c <= '9') return static_cast<unsigned int>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<unsigned int>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return static_cast<unsigned int>(c - 'A' + 10);
    throw std::invalid_argument("invalid hexadecimal character");
  };
  std::vector<std::uint8_t> output(text.size() / 2);
  for (std::size_t i = 0; i != output.size(); ++i) {
    output[i] = static_cast<std::uint8_t>((nibble(text[2 * i]) << 4) | nibble(text[2 * i + 1]));
  }
  return output;
}

template<class Range> std::string to_hex(const Range& bytes) {
  std::ostringstream output;
  output << std::hex << std::setfill('0');
  for (const auto byte : bytes) output << std::setw(2) << static_cast<unsigned int>(byte);
  return output.str();
}

template<class Array> Array fixed_hex(std::string_view text, std::string_view name) {
  const auto bytes = from_hex(text);
  if (bytes.size() != Array{}.size()) {
    throw std::invalid_argument(std::string(name) + " must contain exactly " +
                                std::to_string(Array{}.size()) + " bytes");
  }
  Array result{};
  std::copy(bytes.begin(), bytes.end(), result.begin());
  return result;
}

std::vector<std::uint8_t> read_file(const std::string& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) throw std::runtime_error("cannot open input file: " + path);
  return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

void write_file(const std::string& path, std::span<const std::uint8_t> bytes) {
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output) throw std::runtime_error("cannot open output file: " + path);
  output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  if (!output) throw std::runtime_error("failed writing output file: " + path);
}

Digest sha256(std::span<const std::uint8_t> bytes) {
  Digest result{};
  unsigned int length = 0;
  if (EVP_Digest(bytes.data(), bytes.size(), result.data(), &length, EVP_sha256(), nullptr) != 1 ||
      length != result.size()) {
    throw std::runtime_error("OpenSSL SHA-256 failed");
  }
  return result;
}

std::map<std::string, std::string> options(int argc, char** argv, int first) {
  std::map<std::string, std::string> result;
  for (int i = first; i < argc; ++i) {
    const std::string key = argv[i];
    if (!key.starts_with("--") || i + 1 == argc) {
      throw std::invalid_argument("expected --option value");
    }
    result[key] = argv[++i];
  }
  return result;
}

const std::string& required(const std::map<std::string, std::string>& opts,
                            const std::string& key) {
  const auto found = opts.find(key);
  if (found == opts.end()) throw std::invalid_argument("missing required option " + key);
  return found->second;
}

std::vector<std::uint8_t> context_bytes(const std::map<std::string, std::string>& opts) {
  const auto found = opts.find("--context");
  if (found == opts.end()) return {};
  return {found->second.begin(), found->second.end()};
}

vole_sha256::ProverRandomness randomness(const std::map<std::string, std::string>& opts) {
  const auto found = opts.find("--randomness-hex");
  if (found != opts.end()) {
    return fixed_hex<vole_sha256::ProverRandomness>(found->second, "randomness");
  }
  vole_sha256::ProverRandomness result{};
  if (RAND_bytes(result.data(), result.size()) != 1) {
    throw std::runtime_error("OpenSSL RAND_bytes failed");
  }
  return result;
}

double millis(std::chrono::steady_clock::duration duration) {
  return std::chrono::duration<double, std::milli>(duration).count();
}

long peak_rss_kib() {
#if defined(__unix__) || defined(__APPLE__)
  rusage usage{};
  if (getrusage(RUSAGE_SELF, &usage) == 0) return usage.ru_maxrss;
#endif
  return -1;
}

void usage() {
  std::cerr
      << "Usage:\n"
      << "  vole-sha256 prove --message-hex HEX --proof FILE [--context TEXT] "
         "[--randomness-hex HEX]\n"
      << "  vole-sha256 verify --digest-hex HEX --proof FILE [--context TEXT]\n"
      << "  vole-sha256 inspect --proof FILE\n"
      << "  vole-sha256 benchmark [--iterations N] [--message-hex HEX] [--context TEXT] "
         "[--random-messages true] [--print-samples true]\n";
}

int command_prove(const std::map<std::string, std::string>& opts) {
  const auto message = fixed_hex<Message>(required(opts, "--message-hex"), "message");
  const auto context = context_bytes(opts);
  const auto rho = randomness(opts);
  const Circuit circuit;
  const auto digest = circuit.evaluate(message);
  const auto proof = vole_sha256::prove(circuit, message, digest, context, rho);
  write_file(required(opts, "--proof"), proof);
  std::cout << "digest=" << to_hex(digest) << '\n'
            << "proof_bytes=" << proof.size() << '\n'
            << "proof_sha256=" << to_hex(sha256(proof)) << '\n';
  return 0;
}

int command_verify(const std::map<std::string, std::string>& opts) {
  const auto digest = fixed_hex<Digest>(required(opts, "--digest-hex"), "digest");
  const auto context = context_bytes(opts);
  const auto proof = read_file(required(opts, "--proof"));
  const Circuit circuit;
  const bool accepted = vole_sha256::verify(circuit, digest, context, proof);
  std::cout << (accepted ? "VALID" : "INVALID") << '\n';
  return accepted ? 0 : 1;
}

int command_inspect(const std::map<std::string, std::string>& opts) {
  const auto proof = read_file(required(opts, "--proof"));
  std::cout << "proof_bytes=" << proof.size() << '\n'
            << "expected_bytes=" << vole_sha256::serialized_proof_bytes << '\n'
            << "proof_sha256=" << to_hex(sha256(proof)) << '\n';
  if (proof.size() == vole_sha256::serialized_proof_bytes) {
    const std::span<const std::uint8_t> challenge(proof.data() + 57234, 16);
    const std::uint32_t counter = static_cast<std::uint32_t>(proof[57266]) |
                                  (static_cast<std::uint32_t>(proof[57267]) << 8) |
                                  (static_cast<std::uint32_t>(proof[57268]) << 16) |
                                  (static_cast<std::uint32_t>(proof[57269]) << 24);
    std::cout << "challenge_3=" << to_hex(challenge) << '\n' << "counter=" << counter << '\n';
  }
  return proof.size() == vole_sha256::serialized_proof_bytes ? 0 : 1;
}

int command_benchmark(const std::map<std::string, std::string>& opts) {
  Message message{};
  const auto message_option = opts.find("--message-hex");
  if (message_option != opts.end()) message = fixed_hex<Message>(message_option->second, "message");
  else for (std::size_t i = 0; i != message.size(); ++i) message[i] = static_cast<std::uint8_t>(i);
  const bool random_messages = opts.contains("--random-messages") &&
                               opts.at("--random-messages") != "false";
  const bool print_samples = opts.contains("--print-samples") &&
                             opts.at("--print-samples") != "false";
  if (random_messages && message_option != opts.end()) {
    throw std::invalid_argument("--random-messages and --message-hex are mutually exclusive");
  }
  const auto context = context_bytes(opts);
  const auto iterations_option = opts.find("--iterations");
  const unsigned int iterations = iterations_option == opts.end()
                                      ? 3U
                                      : static_cast<unsigned int>(std::stoul(iterations_option->second));
  if (iterations == 0) throw std::invalid_argument("iterations must be positive");

  const auto circuit_start = std::chrono::steady_clock::now();
  const Circuit circuit;
  const auto circuit_end = std::chrono::steady_clock::now();

  double prove_ms = 0;
  double verify_ms = 0;
  double witness_ms = 0;
  std::size_t proof_size = 0;
  for (unsigned int i = 0; i != iterations; ++i) {
    if (random_messages) {
      static constexpr std::string_view alphabet =
          "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
      std::array<std::uint8_t, Message{}.size()> random_bytes{};
      if (RAND_bytes(random_bytes.data(), random_bytes.size()) != 1) {
        throw std::runtime_error("OpenSSL RAND_bytes failed");
      }
      for (std::size_t j = 0; j != message.size(); ++j) {
        message[j] = static_cast<std::uint8_t>(alphabet[random_bytes[j] % alphabet.size()]);
      }
    }
    const auto digest = circuit.evaluate(message);
    const auto witness_start = std::chrono::steady_clock::now();
    const auto witness = vole_sha256::build_witness(circuit, message);
    const auto witness_end = std::chrono::steady_clock::now();
    witness_ms += millis(witness_end - witness_start);
    (void)witness;

    vole_sha256::ProverRandomness rho{};
    if (random_messages) {
      if (RAND_bytes(rho.data(), rho.size()) != 1) {
        throw std::runtime_error("OpenSSL RAND_bytes failed");
      }
    } else {
      for (std::size_t j = 0; j != rho.size(); ++j) rho[j] = static_cast<std::uint8_t>(i + 13 * j);
    }
    const auto prove_start = std::chrono::steady_clock::now();
    const auto proof = vole_sha256::prove(circuit, message, digest, context, rho);
    const auto prove_end = std::chrono::steady_clock::now();
    const auto verify_start = std::chrono::steady_clock::now();
    const bool accepted = vole_sha256::verify(circuit, digest, context, proof);
    const auto verify_end = std::chrono::steady_clock::now();
    if (!accepted) throw std::runtime_error("benchmark proof did not verify");
    const double sample_prove_ms = millis(prove_end - prove_start);
    const double sample_verify_ms = millis(verify_end - verify_start);
    prove_ms += sample_prove_ms;
    verify_ms += sample_verify_ms;
    proof_size = proof.size();

    if (print_samples) {
      std::cout << "\n[sample " << i + 1 << '/' << iterations << "]\n"
                << "secret_input_ascii="
                << std::string(message.begin(), message.end()) << '\n'
                << "secret_input_hex=" << to_hex(message) << '\n'
                << "public_sha256=" << to_hex(digest) << '\n'
                << "prover_time_ms=" << sample_prove_ms << '\n'
                << "verifier_time_ms=" << sample_verify_ms << '\n'
                << "proof_size_bytes=" << proof.size() << '\n'
                << "verification=VALID\n";
    }
  }

  std::cout << "\n[summary]\n"
            << "iterations=" << iterations << '\n'
            << "random_messages=" << (random_messages ? "true" : "false") << '\n'
            << "multiplication_gates=" << circuit.statistics().multiplication_gates << '\n'
            << "logical_witness_bits=" << vole_sha256::logical_witness_bits << '\n'
            << "vole_witness_bytes=" << vole_sha256::vole_witness_bytes << '\n'
            << "proof_bytes=" << proof_size << '\n'
            << "circuit_build_ms=" << millis(circuit_end - circuit_start) << '\n'
            << "witness_generation_mean_ms=" << witness_ms / iterations << '\n'
            << "prove_mean_ms=" << prove_ms / iterations << '\n'
            << "verify_mean_ms=" << verify_ms / iterations << '\n'
            << "peak_rss_kib=" << peak_rss_kib() << '\n';
  return 0;
}

} // namespace

int main(int argc, char** argv) {
  try {
    if (argc < 2) {
      usage();
      return 2;
    }
    const std::string command = argv[1];
    const auto opts = options(argc, argv, 2);
    if (command == "prove") return command_prove(opts);
    if (command == "verify") return command_verify(opts);
    if (command == "inspect") return command_inspect(opts);
    if (command == "benchmark") return command_benchmark(opts);
    usage();
    return 2;
  } catch (const std::exception& error) {
    std::cerr << "error: " << error.what() << '\n';
    return 2;
  }
}
