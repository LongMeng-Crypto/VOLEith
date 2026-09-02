/* SPDX-License-Identifier: MIT */

#include "../backend/vole/bit_matrix_transpose.hpp"

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace {

bool get_bit(const std::vector<std::uint8_t>& value, std::size_t bit) {
  return ((value[bit / 8] >> (bit % 8)) & 1U) != 0;
}

void set_bit(std::vector<std::uint8_t>& value, std::size_t bit, bool set) {
  if (set)
    value[bit / 8] |= static_cast<std::uint8_t>(1U << (bit % 8));
}

} // namespace

BOOST_AUTO_TEST_SUITE(bit_matrix_transpose_tests)

BOOST_AUTO_TEST_CASE(single_bit_orientation) {
  std::array<std::uint64_t, 64> block{};
  block[2] = UINT64_C(1) << 5;
  vole_backend::transpose_64x64(block);
  for (std::size_t row = 0; row != 64; ++row) {
    const auto expected = row == 5 ? UINT64_C(1) << 2 : 0;
    BOOST_TEST(block[row] == expected);
  }
}

BOOST_AUTO_TEST_CASE(blocked_matches_scalar_reference) {
  for (const std::size_t columns_count : {128, 192, 256}) {
    for (const std::size_t rows_count : {std::size_t{1}, std::size_t{7},
                                         std::size_t{63}, std::size_t{64},
                                         std::size_t{65}, std::size_t{129}}) {
      const auto column_bytes = (rows_count + 7) / 8;
      std::vector<std::vector<std::uint8_t>> storage(
          columns_count, std::vector<std::uint8_t>(column_bytes));
      std::uint64_t state = UINT64_C(0x6a09e667f3bcc909) ^ rows_count ^ columns_count;
      for (auto& column : storage) {
        for (auto& byte : column) {
          state ^= state << 13;
          state ^= state >> 7;
          state ^= state << 17;
          byte = static_cast<std::uint8_t>(state);
        }
      }
      std::vector<std::uint8_t*> columns;
      for (auto& column : storage) columns.push_back(column.data());

      const auto row_bytes = columns_count / 8;
      std::vector<std::uint8_t> actual(rows_count * row_bytes);
      for (std::size_t row_base = 0; row_base < rows_count; row_base += 64) {
        const auto block_rows = std::min<std::size_t>(64, rows_count - row_base);
        vole_backend::transpose_column_block(
            columns, row_base, block_rows,
            std::span<std::uint8_t>(actual).subspan(row_base * row_bytes,
                                                    block_rows * row_bytes),
            row_bytes);
      }

      std::vector<std::uint8_t> expected(rows_count * row_bytes);
      for (std::size_t row = 0; row != rows_count; ++row) {
        for (std::size_t column = 0; column != columns_count; ++column)
          set_bit(expected, row * columns_count + column,
                  get_bit(storage[column], row));
      }
      BOOST_TEST(actual == expected);
    }
  }
}

BOOST_AUTO_TEST_SUITE_END()
