/* SPDX-License-Identifier: MIT */
#ifndef VOLE_BACKEND_BIT_MATRIX_TRANSPOSE_HPP
#define VOLE_BACKEND_BIT_MATRIX_TRANSPOSE_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace vole_backend {

// Transpose one 64x64 bit matrix. Input word i contains column i, with row 0
// in its least-significant bit. Output word i contains row i, with column 0
// in its least-significant bit.
void transpose_64x64(std::array<std::uint64_t, 64>& block);

// Transpose up to 64 byte-aligned rows from a column-major VOLE matrix into a
// packed row-major buffer. The column count and row stride must be multiples
// of eight; the current protocol uses 128, 192, or 256 columns.
void transpose_column_block(
    std::span<std::uint8_t* const> columns, std::size_t row_offset,
    std::size_t row_count, std::span<std::uint8_t> packed_rows,
    std::size_t row_stride);

} // namespace vole_backend

#endif
