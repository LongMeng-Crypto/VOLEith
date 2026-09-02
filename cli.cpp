/* SPDX-License-Identifier: MIT */

#include "backend/circuit_format.hpp"
#include "backend/generic_nizk.hpp"
#include "backend/json_circuit.hpp"
#include "circuits/sha256/nizk.hpp"
#include "circuits/sha256/sha256_circuit.hpp"
#include "circuits/sha256/witness.hpp"
#include "circuits/sha2/sha384_circuit.hpp"
#include "circuits/sha2/sha512_circuit.hpp"
#include "circuits/aes/aes128_circuit.hpp"
#include "circuits/aes/aes128_faest_circuit.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
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

std::pair<Message, std::size_t> message_hex(std::string_view text) {
  const auto bytes = from_hex(text);
  if (bytes.size() > faest::sha256_circuit::max_message_bytes) {
    throw std::invalid_argument("message exceeds 550 bytes");
  }
  Message result{};
  std::copy(bytes.begin(), bytes.end(), result.begin());
  return {result, bytes.size()};
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

std::vector<std::uint8_t> packed_bits(const std::map<std::string, std::string>& opts,
                                      const std::string& key, std::size_t bit_count,
                                      bool required_value) {
  const auto found = opts.find(key);
  if (found == opts.end()) {
    if (required_value && bit_count != 0) throw std::invalid_argument("missing required option " + key);
    return std::vector<std::uint8_t>(bit_count, 0);
  }
  const auto bytes = from_hex(found->second);
  if (bytes.size() != (bit_count + 7) / 8) throw std::invalid_argument(key + " has wrong packed size");
  if (bit_count % 8 != 0 && !bytes.empty() && (bytes.back() >> (bit_count % 8)) != 0) {
    throw std::invalid_argument(key + " has nonzero unused high bits");
  }
  std::vector<std::uint8_t> bits(bit_count);
  for (std::size_t i = 0; i != bit_count; ++i) bits[i] = (bytes[i / 8] >> (i % 8)) & 1U;
  return bits;
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
      << "  vole-sha256 verify --digest-hex HEX --message-length BYTES --proof FILE [--context TEXT]\n"
      << "  vole-sha256 inspect --message-length BYTES --proof FILE\n"
      << "  vole-sha256 benchmark [--iterations N] [--message-hex HEX] [--context TEXT] "
         "[--message-bytes N] [--random-messages true] [--print-samples true]\n"
      << "  vole-sha256 export-sha256-circuit --message-length BYTES --circuit FILE "
         "[--input-layout-bits SPEC]\n"
      << "  vole-sha256 sha256-partition-input --message-hex HEX "
         "--input-layout-bits SPEC\n"
      << "  vole-sha256 export-sha384-circuit --message-length BYTES --circuit FILE "
         "[--input-layout-bits SPEC]\n"
      << "  vole-sha256 sha384-partition-input --message-hex HEX "
         "--input-layout-bits SPEC\n"
      << "  vole-sha256 export-sha512-circuit --message-length BYTES --circuit FILE "
         "[--input-layout-bits SPEC]\n"
      << "  vole-sha256 sha512-partition-input --message-hex HEX "
         "--input-layout-bits SPEC\n"
      << "  vole-sha256 export-aes128-circuit --circuit FILE\n"
      << "  vole-sha256 export-aes128-faest-relation --relation FILE\n"
      << "  vole-sha256 json-to-vbc --json FILE --circuit FILE\n"
      << "  vole-sha256 circuit-inspect --circuit FILE [--security 128|192|256]\n"
      << "  vole-sha256 circuit-prove --circuit FILE --private-input-hex HEX "
         "[--public-input-hex HEX] --expected-output-hex HEX --proof FILE [--context TEXT] "
         "[--security 128|192|256]\n"
      << "  vole-sha256 circuit-verify --circuit FILE [--public-input-hex HEX] "
         "--expected-output-hex HEX --proof FILE [--context TEXT] [--security 128|192|256]\n"
      << "  vole-sha256 circuit-benchmark --circuit FILE --private-input-hex HEX "
         "[--public-input-hex HEX] --expected-output-hex HEX [--context TEXT] "
         "[--iterations N] [--security 128|192|256]\n"
      << "  vole-sha256 aes128-faest-prove --relation FILE --private-input-hex HEX "
         "--public-input-hex HEX --expected-output-hex HEX --proof FILE [--context TEXT]\n"
      << "  vole-sha256 aes128-faest-verify --relation FILE --public-input-hex HEX "
         "--expected-output-hex HEX --proof FILE [--context TEXT]\n"
      << "  vole-sha256 aes128-faest-benchmark --relation FILE --private-input-hex HEX "
         "--public-input-hex HEX --expected-output-hex HEX [--context TEXT] [--iterations N]\n";
}

int command_json_to_vbc(const std::map<std::string, std::string>& opts) {
  const auto input = read_file(required(opts, "--json"));
  const std::string json(input.begin(), input.end());
  const auto circuit = vole_backend::compile_json_circuit(json);
  const auto encoded = vole_backend::serialize_vbc(circuit);
  write_file(required(opts, "--circuit"), encoded);
  const auto stats = circuit.statistics();
  std::cout << "circuit_bytes=" << encoded.size() << '\n'
            << "circuit_hash=" << to_hex(vole_backend::circuit_hash(encoded)) << '\n'
            << "nodes=" << stats.total_nodes << '\n'
            << "private_input_bits=" << stats.private_inputs << '\n'
            << "public_input_bits=" << stats.public_inputs << '\n'
            << "outputs=" << circuit.outputs().size() << '\n'
            << "multiplication_gates=" << stats.multiplication_gates << '\n';
  return 0;
}

vole_backend::BinaryCircuit load_circuit(const std::map<std::string, std::string>& opts) {
  const auto bytes = read_file(required(opts, "--circuit"));
  return vole_backend::deserialize_vbc(bytes);
}

vole_backend::SecurityLevel generic_security(
    const std::map<std::string, std::string>& opts) {
  const auto found = opts.find("--security");
  return found == opts.end()
             ? vole_backend::SecurityLevel::Bits128
             : vole_backend::parse_security_level(found->second);
}

faest::sha256_circuit::InputVisibilityLayout sha256_input_visibility(
    const std::map<std::string, std::string>& opts,
    std::size_t message_length) {
  if (message_length > faest::sha256_circuit::max_message_bytes)
    throw std::invalid_argument("SHA-256 message exceeds 550 bytes");
  const auto found = opts.find("--input-layout-bits");
  if (found == opts.end())
    return faest::sha256_circuit::InputVisibilityLayout::all_secret(
        message_length * 8);
  return faest::sha256_circuit::InputVisibilityLayout::parse(
      message_length * 8, found->second);
}

int command_export_sha256_circuit(const std::map<std::string, std::string>& opts) {
  const auto message_length = std::stoul(required(opts, "--message-length"));
  const auto input_visibility = sha256_input_visibility(opts, message_length);
  const Circuit circuit(message_length, input_visibility);
  const auto encoded = vole_backend::serialize_vbc(circuit.binary_circuit());
  write_file(required(opts, "--circuit"), encoded);
  std::cout << "circuit_bytes=" << encoded.size() << '\n'
            << "circuit_hash=" << to_hex(vole_backend::circuit_hash(encoded)) << '\n'
            << "message_length=" << message_length << '\n'
            << "sha2_blocks=" << circuit.block_count() << '\n'
            << "input_layout_bits=" << input_visibility.canonical_specification() << '\n'
            << "private_input_bits=" << circuit.secret_input_bits() << '\n'
            << "public_input_bits=" << circuit.public_input_bits() << '\n'
            << "outputs=256\n"
            << "multiplication_gates=" << circuit.statistics().multiplication_gates << '\n';
  return 0;
}

int command_sha256_partition_input(
    const std::map<std::string, std::string>& opts) {
  const auto [message, message_length] = message_hex(required(opts, "--message-hex"));
  const auto input_visibility = sha256_input_visibility(opts, message_length);
  const Circuit circuit(message_length, input_visibility);
  const auto partitioned = circuit.partition_input(message);
  const auto private_packed =
      faest::sha256_circuit::pack_input_bits(partitioned.private_bits);
  const auto public_packed =
      faest::sha256_circuit::pack_input_bits(partitioned.public_bits);
  std::cout << "message_length=" << message_length << '\n'
            << "input_layout_bits=" << input_visibility.canonical_specification() << '\n'
            << "private_input_bits=" << partitioned.private_bits.size() << '\n'
            << "public_input_bits=" << partitioned.public_bits.size() << '\n'
            << "private_input_hex=" << to_hex(private_packed) << '\n'
            << "public_input_hex=" << to_hex(public_packed) << '\n'
            << "public_sha256=" << to_hex(circuit.evaluate(message)) << '\n';
  return 0;
}

std::vector<std::uint8_t> sha512_family_message_hex(std::string_view text) {
  auto bytes = from_hex(text);
  if (bytes.size() > vole_circuits::sha2::sha512_family_max_message_bytes)
    throw std::invalid_argument("SHA-384/SHA-512 message exceeds 1100 bytes");
  return bytes;
}

vole_circuits::InputVisibilityLayout sha512_family_input_visibility(
    const std::map<std::string, std::string>& opts,
    std::size_t message_length) {
  if (message_length > vole_circuits::sha2::sha512_family_max_message_bytes)
    throw std::invalid_argument("SHA-384/SHA-512 message exceeds 1100 bytes");
  const auto found = opts.find("--input-layout-bits");
  if (found == opts.end())
    return vole_circuits::InputVisibilityLayout::all_secret(
        message_length * 8);
  return vole_circuits::InputVisibilityLayout::parse(
      message_length * 8, found->second);
}

template<class CircuitType>
int command_export_sha512_family_circuit(
    const std::map<std::string, std::string>& opts,
    std::string_view algorithm) {
  const auto message_length = std::stoul(required(opts, "--message-length"));
  const auto input_visibility =
      sha512_family_input_visibility(opts, message_length);
  const CircuitType circuit(message_length, input_visibility);
  const auto encoded =
      vole_backend::serialize_vbc(circuit.binary_circuit());
  write_file(required(opts, "--circuit"), encoded);
  const auto& stats = circuit.statistics();
  std::cout << "algorithm=" << algorithm << '\n'
            << "circuit_bytes=" << encoded.size() << '\n'
            << "circuit_hash="
            << to_hex(vole_backend::circuit_hash(encoded)) << '\n'
            << "message_length=" << message_length << '\n'
            << "sha2_blocks=" << circuit.block_count() << '\n'
            << "input_layout_bits="
            << input_visibility.canonical_specification() << '\n'
            << "private_input_bits=" << circuit.secret_input_bits() << '\n'
            << "public_input_bits=" << circuit.public_input_bits() << '\n'
            << "outputs=" << circuit.digest_bytes() * 8 << '\n'
            << "xor_gates=" << stats.xor_gates << '\n'
            << "schedule_multiplications="
            << stats.schedule_multiplications << '\n'
            << "round_multiplications=" << stats.round_multiplications
            << '\n'
            << "feed_forward_multiplications="
            << stats.feed_forward_multiplications << '\n'
            << "multiplication_gates=" << stats.multiplication_gates
            << '\n';
  return 0;
}

template<class CircuitType>
int command_sha512_family_partition_input(
    const std::map<std::string, std::string>& opts,
    std::string_view algorithm) {
  const auto message =
      sha512_family_message_hex(required(opts, "--message-hex"));
  const auto input_visibility =
      sha512_family_input_visibility(opts, message.size());
  const CircuitType circuit(message.size(), input_visibility);
  const auto partitioned = circuit.partition_input(message);
  const auto private_packed =
      vole_circuits::pack_input_bits(partitioned.private_bits);
  const auto public_packed =
      vole_circuits::pack_input_bits(partitioned.public_bits);
  std::cout << "algorithm=" << algorithm << '\n'
            << "message_length=" << message.size() << '\n'
            << "sha2_blocks=" << circuit.block_count() << '\n'
            << "input_layout_bits="
            << input_visibility.canonical_specification() << '\n'
            << "private_input_bits=" << partitioned.private_bits.size()
            << '\n'
            << "public_input_bits=" << partitioned.public_bits.size()
            << '\n'
            << "private_input_hex=" << to_hex(private_packed) << '\n'
            << "public_input_hex=" << to_hex(public_packed) << '\n'
            << "public_" << algorithm << '=' << to_hex(circuit.evaluate(message))
            << '\n';
  return 0;
}

int command_export_aes128_circuit(const std::map<std::string, std::string>& opts) {
  const vole_circuits::aes::Aes128Circuit frontend;
  const auto& circuit = frontend.binary_circuit();
  const auto encoded = vole_backend::serialize_vbc(circuit);
  write_file(required(opts, "--circuit"), encoded);
  const auto stats = circuit.statistics();
  std::cout << "circuit_bytes=" << encoded.size() << '\n'
            << "circuit_hash=" << to_hex(vole_backend::circuit_hash(encoded)) << '\n'
            << "private_input_bits=" << stats.private_inputs << '\n'
            << "public_input_bits=" << stats.public_inputs << '\n'
            << "outputs=" << circuit.outputs().size() << '\n'
            << "multiplication_gates=" << stats.multiplication_gates << '\n';
  return 0;
}

vole_circuits::aes::Aes128FaestRelation load_aes128_faest_relation(
    const std::map<std::string, std::string>& opts) {
  const auto bytes = read_file(required(opts, "--relation"));
  const auto decoded = vole_backend::deserialize_vqir(bytes);
  vole_circuits::aes::Aes128FaestRelation relation;
  if (vole_backend::serialize_vqir(decoded) != vole_backend::serialize_vqir(relation.ir()))
    throw std::invalid_argument("relation is not canonical AES-128 FAEST VQIR");
  return relation;
}

int command_export_aes128_faest_relation(const std::map<std::string, std::string>& opts) {
  const vole_circuits::aes::Aes128FaestRelation relation;
  const auto encoded = vole_backend::serialize_vqir(relation.ir());
  write_file(required(opts, "--relation"), encoded);
  std::cout << "relation_bytes=" << encoded.size() << '\n'
            << "relation_hash=" << to_hex(relation.id()) << '\n'
            << "private_input_bits=128\npublic_input_bits=128\noutputs=128\n"
            << "auxiliary_witness_bits=1152\nextended_witness_bits=1280\n"
            << "multiplication_constraints=200\n"
            << "proof_bytes=" << vole_backend::serialized_proof_bytes(relation) << '\n';
  return 0;
}

vole_backend::PublicStatement aes_faest_statement(
    const std::map<std::string, std::string>& opts) {
  return {packed_bits(opts, "--public-input-hex", 128, true),
          packed_bits(opts, "--expected-output-hex", 128, true)};
}

int command_aes128_faest_prove(const std::map<std::string, std::string>& opts) {
  const auto relation = load_aes128_faest_relation(opts);
  const auto proof = vole_backend::prove(
      relation, packed_bits(opts, "--private-input-hex", 128, true),
      aes_faest_statement(opts), context_bytes(opts), randomness(opts));
  write_file(required(opts, "--proof"), proof);
  std::cout << "relation_hash=" << to_hex(relation.id()) << '\n'
            << "proof_bytes=" << proof.size() << '\n'
            << "proof_sha256=" << to_hex(sha256(proof)) << '\n';
  return 0;
}

int command_aes128_faest_verify(const std::map<std::string, std::string>& opts) {
  const auto relation = load_aes128_faest_relation(opts);
  const bool accepted = vole_backend::verify(
      relation, aes_faest_statement(opts), context_bytes(opts),
      read_file(required(opts, "--proof")));
  std::cout << (accepted ? "VALID" : "INVALID") << '\n';
  return accepted ? 0 : 1;
}

int command_aes128_faest_benchmark(const std::map<std::string, std::string>& opts) {
  const auto relation = load_aes128_faest_relation(opts);
  const auto private_bits = packed_bits(opts, "--private-input-hex", 128, true);
  const auto statement = aes_faest_statement(opts);
  const auto context = context_bytes(opts);
  const auto found = opts.find("--iterations");
  const auto iterations = found == opts.end() ? 10UL : std::stoul(found->second);
  if (iterations == 0) throw std::invalid_argument("--iterations must be positive");
  std::vector<double> prove_samples, verify_samples;
  std::size_t proof_bytes = 0;
  for (unsigned long i = 0; i != iterations; ++i) {
    vole_backend::ProverRandomness rho{};
    if (RAND_bytes(rho.data(), rho.size()) != 1) throw std::runtime_error("RAND_bytes failed");
    const auto ps = std::chrono::steady_clock::now();
    const auto proof = vole_backend::prove(relation, private_bits, statement, context, rho);
    const auto pe = std::chrono::steady_clock::now();
    const auto vs = std::chrono::steady_clock::now();
    const bool accepted = vole_backend::verify(relation, statement, context, proof);
    const auto ve = std::chrono::steady_clock::now();
    if (!accepted) throw std::runtime_error("benchmark proof did not verify");
    prove_samples.push_back(millis(pe - ps)); verify_samples.push_back(millis(ve - vs));
    proof_bytes = proof.size();
  }
  const auto report = [](std::string_view name, const std::vector<double>& samples) {
    double sum = 0; for (const auto x : samples) sum += x;
    const auto [lo, hi] = std::minmax_element(samples.begin(), samples.end());
    std::cout << name << "_mean_ms=" << sum / samples.size() << '\n'
              << name << "_min_ms=" << *lo << '\n' << name << "_max_ms=" << *hi << '\n';
  };
  std::cout << "iterations=" << iterations << '\n'
            << "relation_hash=" << to_hex(relation.id()) << '\n'
            << "private_input_bits=128\npublic_input_bits=128\noutputs=128\n"
            << "auxiliary_witness_bits=1152\nextended_witness_bits=1280\n"
            << "multiplication_constraints=200\nproof_bytes=" << proof_bytes << '\n';
  report("prove", prove_samples); report("verify", verify_samples);
  return 0;
}

int command_circuit_inspect(const std::map<std::string, std::string>& opts) {
  const auto encoded = read_file(required(opts, "--circuit"));
  const auto circuit = vole_backend::deserialize_vbc(encoded);
  const auto stats = circuit.statistics();
  const auto security = generic_security(opts);
  std::cout << "circuit_bytes=" << encoded.size() << '\n'
            << "circuit_hash=" << to_hex(vole_backend::circuit_hash(encoded)) << '\n'
            << "nodes=" << stats.total_nodes << '\n'
            << "private_input_bits=" << stats.private_inputs << '\n'
            << "public_input_bits=" << stats.public_inputs << '\n'
            << "outputs=" << circuit.outputs().size() << '\n'
            << "xor_gates=" << stats.xor_gates << '\n'
            << "multiplication_gates=" << stats.multiplication_gates << '\n'
            << "security_bits=" << vole_backend::security_level_name(security) << '\n'
            << "proof_bytes=" << vole_backend::serialized_proof_bytes(circuit, security) << '\n';
  return 0;
}

vole_backend::PublicStatement generic_statement(const vole_backend::BinaryCircuit& circuit,
                                                const std::map<std::string, std::string>& opts) {
  const auto stats = circuit.statistics();
  return {packed_bits(opts, "--public-input-hex", stats.public_inputs, false),
          packed_bits(opts, "--expected-output-hex", circuit.outputs().size(), true)};
}

int command_circuit_prove(const std::map<std::string, std::string>& opts) {
  const auto circuit = load_circuit(opts);
  const vole_backend::PreparedBinaryCircuit prepared(circuit);
  const auto statement = generic_statement(circuit, opts);
  const auto private_bits = packed_bits(opts, "--private-input-hex",
                                        prepared.statistics().private_inputs, true);
  const auto security = generic_security(opts);
  const auto proof = vole_backend::prove(prepared, security, private_bits, statement,
                                         context_bytes(opts), randomness(opts));
  write_file(required(opts, "--proof"), proof);
  std::cout << "circuit_hash=" << to_hex(prepared.canonical_hash()) << '\n'
            << "security_bits=" << vole_backend::security_level_name(security) << '\n'
            << "proof_bytes=" << proof.size() << '\n'
            << "proof_sha256=" << to_hex(sha256(proof)) << '\n';
  return 0;
}

int command_circuit_verify(const std::map<std::string, std::string>& opts) {
  const auto circuit = load_circuit(opts);
  const vole_backend::PreparedBinaryCircuit prepared(circuit);
  const auto security = generic_security(opts);
  const auto accepted = vole_backend::verify(prepared, security,
                                             generic_statement(circuit, opts), context_bytes(opts),
                                             read_file(required(opts, "--proof")));
  std::cout << "security_bits=" << vole_backend::security_level_name(security) << '\n'
            << (accepted ? "VALID" : "INVALID") << '\n';
  return accepted ? 0 : 1;
}

int command_circuit_benchmark(const std::map<std::string, std::string>& opts) {
  // Loading/deserialization and input parsing deliberately precede all timing
  // boundaries so only the backend operations are measured.
  const auto circuit = load_circuit(opts);
  const vole_backend::PreparedBinaryCircuit prepared(circuit);
  const auto& stats = prepared.statistics();
  const auto statement = generic_statement(circuit, opts);
  const auto private_bits = packed_bits(opts, "--private-input-hex", stats.private_inputs, true);
  const auto context = context_bytes(opts);
  const auto security = generic_security(opts);
  const auto found = opts.find("--iterations");
  const auto iterations = found == opts.end() ? 10UL : std::stoul(found->second);
  if (iterations == 0) throw std::invalid_argument("--iterations must be positive");

  std::vector<double> prove_samples;
  std::vector<double> verify_samples;
  prove_samples.reserve(iterations);
  verify_samples.reserve(iterations);
  std::size_t proof_bytes = 0;

  for (unsigned long i = 0; i != iterations; ++i) {
    vole_backend::ProverRandomness rho{};
    if (RAND_bytes(rho.data(), rho.size()) != 1)
      throw std::runtime_error("OpenSSL RAND_bytes failed");

    const auto prove_start = std::chrono::steady_clock::now();
    const auto proof = vole_backend::prove(prepared, security, private_bits, statement, context, rho);
    const auto prove_end = std::chrono::steady_clock::now();
    const auto verify_start = std::chrono::steady_clock::now();
    const bool accepted = vole_backend::verify(prepared, security, statement, context, proof);
    const auto verify_end = std::chrono::steady_clock::now();
    if (!accepted) throw std::runtime_error("benchmark proof did not verify");

    prove_samples.push_back(millis(prove_end - prove_start));
    verify_samples.push_back(millis(verify_end - verify_start));
    if (i != 0 && proof_bytes != proof.size())
      throw std::runtime_error("benchmark proof size changed between iterations");
    proof_bytes = proof.size();
  }

  const auto report = [](std::string_view name, const std::vector<double>& samples) {
    double sum = 0;
    for (const auto sample : samples) sum += sample;
    const auto [minimum, maximum] = std::minmax_element(samples.begin(), samples.end());
    std::cout << name << "_mean_ms=" << sum / samples.size() << '\n'
              << name << "_min_ms=" << *minimum << '\n'
              << name << "_max_ms=" << *maximum << '\n';
  };

  std::cout << "iterations=" << iterations << '\n'
            << "circuit_hash=" << to_hex(prepared.canonical_hash()) << '\n'
            << "security_bits=" << vole_backend::security_level_name(security) << '\n'
            << "private_input_bits=" << stats.private_inputs << '\n'
            << "public_input_bits=" << stats.public_inputs << '\n'
            << "outputs=" << circuit.outputs().size() << '\n'
            << "xor_gates=" << stats.xor_gates << '\n'
            << "multiplication_gates=" << stats.multiplication_gates << '\n'
            << "proof_bytes=" << proof_bytes << '\n';
  report("prove", prove_samples);
  report("verify", verify_samples);
  return 0;
}

int command_prove(const std::map<std::string, std::string>& opts) {
  const auto [message, message_length] = message_hex(required(opts, "--message-hex"));
  const auto context = context_bytes(opts);
  const auto rho = randomness(opts);
  const Circuit circuit(message_length);
  const auto digest = circuit.evaluate(message);
  const auto proof = vole_sha256::prove(circuit, message, digest, context, rho);
  write_file(required(opts, "--proof"), proof);
  std::cout << "digest=" << to_hex(digest) << '\n'
            << "message_length=" << message_length << '\n'
            << "proof_bytes=" << proof.size() << '\n'
            << "proof_sha256=" << to_hex(sha256(proof)) << '\n';
  return 0;
}

int command_verify(const std::map<std::string, std::string>& opts) {
  const auto digest = fixed_hex<Digest>(required(opts, "--digest-hex"), "digest");
  const auto context = context_bytes(opts);
  const auto proof = read_file(required(opts, "--proof"));
  const auto message_length = std::stoul(required(opts, "--message-length"));
  const Circuit circuit(message_length);
  const bool accepted = vole_sha256::verify(circuit, digest, context, proof);
  std::cout << (accepted ? "VALID" : "INVALID") << '\n';
  return accepted ? 0 : 1;
}

int command_inspect(const std::map<std::string, std::string>& opts) {
  const auto proof = read_file(required(opts, "--proof"));
  const Circuit circuit(std::stoul(required(opts, "--message-length")));
  const auto expected_size = vole_sha256::serialized_proof_bytes(circuit);
  std::cout << "proof_bytes=" << proof.size() << '\n'
            << "expected_bytes=" << expected_size << '\n'
            << "proof_sha256=" << to_hex(sha256(proof)) << '\n';
  if (proof.size() == expected_size) {
    const std::size_t challenge_offset = expected_size - 36;
    const std::size_t counter_offset = expected_size - 4;
    const std::span<const std::uint8_t> challenge(proof.data() + challenge_offset, 16);
    const std::uint32_t counter = static_cast<std::uint32_t>(proof[counter_offset]) |
                                  (static_cast<std::uint32_t>(proof[counter_offset + 1]) << 8) |
                                  (static_cast<std::uint32_t>(proof[counter_offset + 2]) << 16) |
                                  (static_cast<std::uint32_t>(proof[counter_offset + 3]) << 24);
    std::cout << "challenge_3=" << to_hex(challenge) << '\n' << "counter=" << counter << '\n';
  }
  return proof.size() == expected_size ? 0 : 1;
}

int command_benchmark(const std::map<std::string, std::string>& opts) {
  Message message{};
  std::size_t message_length = 55;
  const auto message_option = opts.find("--message-hex");
  if (message_option != opts.end()) {
    const auto parsed = message_hex(message_option->second);
    message = parsed.first;
    message_length = parsed.second;
  } else {
    const auto length_option = opts.find("--message-bytes");
    if (length_option != opts.end()) message_length = std::stoul(length_option->second);
    if (message_length > faest::sha256_circuit::max_message_bytes) {
      throw std::invalid_argument("--message-bytes exceeds 550");
    }
    for (std::size_t i = 0; i != message_length; ++i) message[i] = static_cast<std::uint8_t>(i);
  }
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
  const Circuit circuit(message_length);
  const auto circuit_end = std::chrono::steady_clock::now();

  double prove_ms = 0;
  double verify_ms = 0;
  double witness_ms = 0;
  std::size_t proof_size = 0;
  const auto layout = vole_sha256::witness_layout(circuit);
  for (unsigned int i = 0; i != iterations; ++i) {
    if (random_messages) {
      static constexpr std::string_view alphabet =
          "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
      std::array<std::uint8_t, faest::sha256_circuit::max_message_bytes> random_bytes{};
      if (RAND_bytes(random_bytes.data(), message_length) != 1) {
        throw std::runtime_error("OpenSSL RAND_bytes failed");
      }
      for (std::size_t j = 0; j != message_length; ++j) {
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
                << std::string(message.begin(), message.begin() + static_cast<std::ptrdiff_t>(message_length)) << '\n'
                << "secret_input_hex=" << to_hex(std::span(message.data(), message_length)) << '\n'
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
            << "message_length=" << message_length << '\n'
            << "sha256_blocks=" << circuit.block_count() << '\n'
            << "multiplication_gates=" << circuit.statistics().multiplication_gates << '\n'
            << "logical_witness_bits=" << layout.logical_bits << '\n'
            << "vole_witness_bytes=" << layout.vole_bytes << '\n'
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
    if (command == "export-sha256-circuit") return command_export_sha256_circuit(opts);
    if (command == "sha256-partition-input") return command_sha256_partition_input(opts);
    if (command == "export-sha384-circuit")
      return command_export_sha512_family_circuit<
          vole_circuits::sha2::Sha384Circuit>(opts, "sha384");
    if (command == "sha384-partition-input")
      return command_sha512_family_partition_input<
          vole_circuits::sha2::Sha384Circuit>(opts, "sha384");
    if (command == "export-sha512-circuit")
      return command_export_sha512_family_circuit<
          vole_circuits::sha2::Sha512Circuit>(opts, "sha512");
    if (command == "sha512-partition-input")
      return command_sha512_family_partition_input<
          vole_circuits::sha2::Sha512Circuit>(opts, "sha512");
    if (command == "export-aes128-circuit") return command_export_aes128_circuit(opts);
    if (command == "export-aes128-faest-relation") return command_export_aes128_faest_relation(opts);
    if (command == "json-to-vbc") return command_json_to_vbc(opts);
    if (command == "circuit-inspect") return command_circuit_inspect(opts);
    if (command == "circuit-prove") return command_circuit_prove(opts);
    if (command == "circuit-verify") return command_circuit_verify(opts);
    if (command == "circuit-benchmark") return command_circuit_benchmark(opts);
    if (command == "aes128-faest-prove") return command_aes128_faest_prove(opts);
    if (command == "aes128-faest-verify") return command_aes128_faest_verify(opts);
    if (command == "aes128-faest-benchmark") return command_aes128_faest_benchmark(opts);
    usage();
    return 2;
  } catch (const std::exception& error) {
    std::cerr << "error: " << error.what() << '\n';
    return 2;
  }
}
