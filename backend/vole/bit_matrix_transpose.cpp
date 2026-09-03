/* SPDX-License-Identifier: MIT */

#include "bit_matrix_transpose.hpp"

#include <algorithm>
#include <stdexcept>

#if (defined(__i386__) || defined(__x86_64__)) && \
    (defined(__GNUC__) || defined(__clang__))
#include <immintrin.h>
#define VOLE_HAVE_RUNTIME_AVX2 1
#define VOLE_TARGET_AVX2 __attribute__((target("avx2")))
#endif

namespace vole_backend {
namespace {

std::uint64_t reverse_bits(std::uint64_t value) {
  value = ((value & UINT64_C(0x5555555555555555)) << 1) |
          ((value >> 1) & UINT64_C(0x5555555555555555));
  value = ((value & UINT64_C(0x3333333333333333)) << 2) |
          ((value >> 2) & UINT64_C(0x3333333333333333));
  value = ((value & UINT64_C(0x0f0f0f0f0f0f0f0f)) << 4) |
          ((value >> 4) & UINT64_C(0x0f0f0f0f0f0f0f0f));
  value = ((value & UINT64_C(0x00ff00ff00ff00ff)) << 8) |
          ((value >> 8) & UINT64_C(0x00ff00ff00ff00ff));
  value = ((value & UINT64_C(0x0000ffff0000ffff)) << 16) |
          ((value >> 16) & UINT64_C(0x0000ffff0000ffff));
  return (value << 32) | (value >> 32);
}

std::uint64_t load_partial_le(const std::uint8_t* input, std::size_t bytes) {
  std::uint64_t result = 0;
  for (std::size_t i = 0; i != bytes; ++i)
    result |= std::uint64_t{input[i]} << (8 * i);
  return result;
}

void store_le(std::uint8_t* output, std::uint64_t value) {
  for (std::size_t i = 0; i != 8; ++i)
    output[i] = static_cast<std::uint8_t>(value >> (8 * i));
}

#if defined(VOLE_HAVE_RUNTIME_AVX2)
/* Transpose two, three, or four 64x64 column groups in parallel. Each AVX2
 * lane carries the same column from one security-level field, so the exact
 * scalar transpose is applied to every group with one vector instruction. */
VOLE_TARGET_AVX2
void transpose_column_groups_avx2(
    std::span<std::uint8_t* const> columns, std::size_t row_offset,
    std::size_t row_count, std::span<std::uint8_t> packed_rows,
    std::size_t row_stride) {
  const auto groups = columns.size() / 64;
  const auto input_bytes = (row_count + 7) / 8;
  __m256i block[64];
  for (std::size_t column = 0; column != 64; ++column) {
    std::uint64_t lanes[4] = {0, 0, 0, 0};
    for (std::size_t group = 0; group != groups; ++group) {
      lanes[group] = load_partial_le(
          columns[group * 64 + column] + row_offset / 8, input_bytes);
      if (row_count != 64)
        lanes[group] &= (UINT64_C(1) << row_count) - 1;
    }
    block[column] = _mm256_set_epi64x(
        static_cast<long long>(lanes[3]), static_cast<long long>(lanes[2]),
        static_cast<long long>(lanes[1]), static_cast<long long>(lanes[0]));
  }

  std::uint64_t mask = UINT64_C(0x00000000ffffffff);
  for (unsigned int shift = 32; shift != 0;) {
    const auto shift_vector = _mm256_set1_epi64x(shift);
    const auto mask_vector = _mm256_set1_epi64x(static_cast<long long>(mask));
    for (unsigned int i = 0; i != 64; i = (i + shift + 1) & ~shift) {
      const auto swap = _mm256_and_si256(
          _mm256_xor_si256(block[i],
                           _mm256_srlv_epi64(block[i + shift], shift_vector)),
          mask_vector);
      block[i] = _mm256_xor_si256(block[i], swap);
      block[i + shift] = _mm256_xor_si256(
          block[i + shift], _mm256_sllv_epi64(swap, shift_vector));
    }
    shift >>= 1;
    if (shift != 0) mask ^= mask << shift;
  }

  for (std::size_t row = 0; row != row_count; ++row) {
    alignas(32) std::uint64_t lanes[4];
    _mm256_store_si256(reinterpret_cast<__m256i*>(lanes), block[63 - row]);
    for (std::size_t group = 0; group != groups; ++group) {
      store_le(packed_rows.data() + row * row_stride + group * 8,
               reverse_bits(lanes[group]));
    }
  }
}
#endif

} // namespace

void transpose_64x64(std::array<std::uint64_t, 64>& block) {
  // Hacker's Delight butterfly transpose. Its native ordering reverses both
  // axes relative to FAEST's little-endian bit convention, corrected below.
  std::uint64_t mask = UINT64_C(0x00000000ffffffff);
  for (unsigned int shift = 32; shift != 0;) {
    for (unsigned int i = 0; i != 64; i = (i + shift + 1) & ~shift) {
      const auto swap = (block[i] ^ (block[i + shift] >> shift)) & mask;
      block[i] ^= swap;
      block[i + shift] ^= swap << shift;
    }
    shift >>= 1;
    if (shift != 0) mask ^= mask << shift;
  }

  std::array<std::uint64_t, 64> ordered{};
  for (std::size_t row = 0; row != 64; ++row)
    ordered[row] = reverse_bits(block[63 - row]);
  block = ordered;
}

void transpose_column_block(
    std::span<std::uint8_t* const> columns, std::size_t row_offset,
    std::size_t row_count, std::span<std::uint8_t> packed_rows,
    std::size_t row_stride) {
  if (row_offset % 64 != 0 || row_count > 64 || columns.size() % 64 != 0 ||
      row_stride < columns.size() / 8 || packed_rows.size() != row_count * row_stride)
    throw std::invalid_argument("invalid 64x64 transpose dimensions");

  std::fill(packed_rows.begin(), packed_rows.end(), std::uint8_t{0});
#if defined(VOLE_HAVE_RUNTIME_AVX2)
  if (columns.size() >= 128 && columns.size() <= 256 &&
      __builtin_cpu_supports("avx2")) {
    transpose_column_groups_avx2(columns, row_offset, row_count, packed_rows,
                                 row_stride);
    return;
  }
#endif
  const auto input_bytes = (row_count + 7) / 8;
  for (std::size_t column_base = 0; column_base != columns.size();
       column_base += 64) {
    std::array<std::uint64_t, 64> block{};
    for (std::size_t column = 0; column != 64; ++column) {
      block[column] = load_partial_le(
          columns[column_base + column] + row_offset / 8, input_bytes);
      if (row_count != 64 && row_count % 64 != 0)
        block[column] &= (UINT64_C(1) << row_count) - 1;
    }
    transpose_64x64(block);
    for (std::size_t row = 0; row != row_count; ++row)
      store_le(packed_rows.data() + row * row_stride + column_base / 8,
               block[row]);
  }
}

} // namespace vole_backend
