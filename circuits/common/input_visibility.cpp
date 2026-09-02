/* SPDX-License-Identifier: MIT */

#include "input_visibility.hpp"

#include <algorithm>
#include <charconv>
#include <stdexcept>

namespace vole_circuits {
namespace {

std::string_view trim(std::string_view value) {
  while (!value.empty() && (value.front() == ' ' || value.front() == '\t'))
    value.remove_prefix(1);
  while (!value.empty() && (value.back() == ' ' || value.back() == '\t'))
    value.remove_suffix(1);
  return value;
}

std::size_t parse_index(std::string_view value) {
  value = trim(value);
  if (value.empty()) throw std::invalid_argument("empty visibility range index");
  std::size_t result = 0;
  const auto parsed = std::from_chars(value.data(), value.data() + value.size(), result);
  if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size())
    throw std::invalid_argument("invalid visibility range index");
  return result;
}

VisibilityRange parse_range(std::string_view token) {
  token = trim(token);
  const auto first = token.find(':');
  const auto second = first == std::string_view::npos
                          ? std::string_view::npos
                          : token.find(':', first + 1);
  if (first == std::string_view::npos || second == std::string_view::npos ||
      token.find(':', second + 1) != std::string_view::npos)
    throw std::invalid_argument(
        "visibility range must be secret:BEGIN:END or public:BEGIN:END");
  const auto kind = trim(token.substr(0, first));
  InputVisibility visibility;
  if (kind == "secret")
    visibility = InputVisibility::Secret;
  else if (kind == "public")
    visibility = InputVisibility::Public;
  else
    throw std::invalid_argument("visibility must be secret or public");
  return {visibility, parse_index(token.substr(first + 1, second - first - 1)),
          parse_index(token.substr(second + 1))};
}

} // namespace

InputVisibilityLayout InputVisibilityLayout::all_secret(
    std::size_t message_bits) {
  if (message_bits == 0) return {};
  const VisibilityRange range{InputVisibility::Secret, 0, message_bits};
  return from_ranges(message_bits, std::span(&range, 1));
}

InputVisibilityLayout InputVisibilityLayout::from_ranges(
    std::size_t message_bits, std::span<const VisibilityRange> ranges) {
  InputVisibilityLayout result;
  result.visibility_.resize(message_bits);
  if (message_bits == 0) {
    if (!ranges.empty())
      throw std::invalid_argument("empty message must have an empty visibility layout");
    return result;
  }
  if (ranges.empty()) throw std::invalid_argument("visibility layout is empty");

  std::size_t cursor = 0;
  for (const auto& range : ranges) {
    if (range.visibility != InputVisibility::Secret &&
        range.visibility != InputVisibility::Public)
      throw std::invalid_argument("unsupported input visibility value");
    if (range.begin_bit != cursor)
      throw std::invalid_argument(
          "visibility ranges must be ordered and cover every input bit");
    if (range.end_bit <= range.begin_bit || range.end_bit > message_bits)
      throw std::invalid_argument("invalid or out-of-range visibility interval");
    std::fill(result.visibility_.begin() +
                  static_cast<std::ptrdiff_t>(range.begin_bit),
              result.visibility_.begin() +
                  static_cast<std::ptrdiff_t>(range.end_bit),
              range.visibility);
    const auto count = range.end_bit - range.begin_bit;
    if (range.visibility == InputVisibility::Secret)
      result.private_bits_ += count;
    else
      result.public_bits_ += count;
    if (!result.ranges_.empty() &&
        result.ranges_.back().visibility == range.visibility) {
      result.ranges_.back().end_bit = range.end_bit;
    } else {
      result.ranges_.push_back(range);
    }
    cursor = range.end_bit;
  }
  if (cursor != message_bits)
    throw std::invalid_argument(
        "visibility layout does not cover the complete message");
  return result;
}

InputVisibilityLayout InputVisibilityLayout::parse(
    std::size_t message_bits, std::string_view specification) {
  specification = trim(specification);
  if (message_bits == 0) {
    if (!specification.empty())
      throw std::invalid_argument(
          "empty message must have an empty visibility layout");
    return {};
  }
  if (specification.empty())
    throw std::invalid_argument("visibility layout is empty");
  std::vector<VisibilityRange> ranges;
  while (!specification.empty()) {
    const auto comma = specification.find(',');
    const auto token = comma == std::string_view::npos
                           ? specification
                           : specification.substr(0, comma);
    if (trim(token).empty())
      throw std::invalid_argument("empty visibility range");
    ranges.push_back(parse_range(token));
    if (comma == std::string_view::npos) break;
    if (comma + 1 == specification.size())
      throw std::invalid_argument("visibility layout has a trailing comma");
    specification.remove_prefix(comma + 1);
  }
  return from_ranges(message_bits, ranges);
}

InputVisibility InputVisibilityLayout::visibility_at(
    std::size_t message_bit) const {
  if (message_bit >= visibility_.size())
    throw std::out_of_range("message bit is outside visibility layout");
  return visibility_[message_bit];
}

std::string InputVisibilityLayout::canonical_specification() const {
  std::string result;
  for (const auto& range : ranges_) {
    if (!result.empty()) result.push_back(',');
    result += range.visibility == InputVisibility::Secret ? "secret:"
                                                          : "public:";
    result += std::to_string(range.begin_bit);
    result.push_back(':');
    result += std::to_string(range.end_bit);
  }
  return result;
}

PartitionedInput InputVisibilityLayout::partition(
    std::span<const std::uint8_t> message) const {
  if (message.size() * 8 != message_bits())
    throw std::invalid_argument("message size does not match visibility layout");
  PartitionedInput result;
  result.private_bits.reserve(private_bits_);
  result.public_bits.reserve(public_bits_);
  for (std::size_t byte = 0; byte != message.size(); ++byte) {
    for (std::size_t storage_bit = 0; storage_bit != 8; ++storage_bit) {
      const auto fips_bit = 8 * byte + (7 - storage_bit);
      const auto value = static_cast<std::uint8_t>(
          (message[byte] >> storage_bit) & 1U);
      if (visibility_[fips_bit] == InputVisibility::Secret)
        result.private_bits.push_back(value);
      else
        result.public_bits.push_back(value);
    }
  }
  return result;
}

std::vector<std::uint8_t> pack_input_bits(
    std::span<const std::uint8_t> bits) {
  if (std::any_of(bits.begin(), bits.end(),
                  [](std::uint8_t bit) { return bit > 1; }))
    throw std::invalid_argument("input contains a non-binary value");
  std::vector<std::uint8_t> packed((bits.size() + 7) / 8, 0);
  for (std::size_t i = 0; i != bits.size(); ++i)
    packed[i / 8] |= static_cast<std::uint8_t>(bits[i] << (i % 8));
  return packed;
}

} // namespace vole_circuits
