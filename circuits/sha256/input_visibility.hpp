/* SPDX-License-Identifier: MIT */
#ifndef VOLE_CIRCUITS_SHA256_INPUT_VISIBILITY_HPP
#define VOLE_CIRCUITS_SHA256_INPUT_VISIBILITY_HPP

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace faest::sha256_circuit {

enum class InputVisibility : std::uint8_t { Secret = 0, Public = 1 };

struct VisibilityRange {
  InputVisibility visibility;
  std::size_t begin_bit;
  std::size_t end_bit;
};

struct PartitionedInput {
  // Bits are ordered exactly as the corresponding PrivateInput/PublicInput
  // nodes occur in the generated BinaryCircuit.
  std::vector<std::uint8_t> private_bits;
  std::vector<std::uint8_t> public_bits;
};

class InputVisibilityLayout {
public:
  static InputVisibilityLayout all_secret(std::size_t message_bits);
  static InputVisibilityLayout from_ranges(
      std::size_t message_bits, std::span<const VisibilityRange> ranges);
  static InputVisibilityLayout parse(std::size_t message_bits,
                                     std::string_view specification);

  std::size_t message_bits() const { return visibility_.size(); }
  std::size_t private_bits() const { return private_bits_; }
  std::size_t public_bits() const { return public_bits_; }
  InputVisibility visibility_at(std::size_t message_bit) const;
  const std::vector<VisibilityRange>& ranges() const { return ranges_; }
  std::string canonical_specification() const;

  // Range indices use the SHA/FIPS bitstream convention: message bit zero is
  // the most-significant bit of the first byte. This helper translates that
  // convention to the circuit's existing LSB-first per-byte wire order.
  PartitionedInput partition(std::span<const std::uint8_t> message) const;

private:
  std::vector<InputVisibility> visibility_;
  std::vector<VisibilityRange> ranges_;
  std::size_t private_bits_ = 0;
  std::size_t public_bits_ = 0;
};

std::vector<std::uint8_t> pack_input_bits(std::span<const std::uint8_t> bits);

} // namespace faest::sha256_circuit

#endif
