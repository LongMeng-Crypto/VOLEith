# Backend performance paths

The generic binary-circuit backend has optimized, portable execution paths for
the 128-, 192-, and 256-bit VOLEith parameter sets.

## Carry-less field multiplication

On x86 processors with PCLMULQDQ, multiplication in GF(2^192), GF(2^256),
GF(2^576), and GF(2^768) uses fixed-size carry-less limb multiplication and a
fixed descending polynomial-reduction pass. The irreducible polynomials and
field encodings are unchanged. Machines without PCLMULQDQ use the original
bit-serial constant-time implementation.

The optimized implementation has no secret-dependent loop bounds, memory
addresses, or branches. `tests/fields.cpp` compares it with an independent
bit-serial reference over randomized inputs.

Portable x86 builds no longer expose 32-byte compiler vector types without an
AVX ABI. This removes the GCC `-Wpsabi` calling-convention fixups seen in the
192-bit build while retaining vector types when the whole build explicitly
targets AVX.

## VOLE transpose

The VOLE column-to-row conversion is performed in 64x64 butterfly blocks.
This is solely a representation-preserving bit-matrix transpose: column `c`,
row `r` is still field bit `c` of row `r`. It does not change VOLE generation,
the field encoding, transcript inputs, or any challenge.

`tests/bit_matrix_transpose.cpp` compares all 128/192/256-column paths and
partial final blocks against the former scalar bit-by-bit definition. This
layout also provides a contained point for a future AVX2 implementation.

## PreparedBinaryCircuit

`PreparedBinaryCircuit` is an immutable view over a loaded `BinaryCircuit`.
It caches:

- circuit statistics and witness layout;
- the canonical VBC hash and the security-level-specific transcript IDs;
- traversal metadata mapping private inputs, public inputs, and AND outputs to
  their packed indices.

The CLI prepares a circuit before entering `circuit-benchmark` timing loops.
The prover evaluates the witness once and packs the multiplication outputs from
that same evaluation. No private input, public statement, evaluation, or VOLE
state is cached between proofs. The underlying `BinaryCircuit` must remain
unchanged while a prepared object is in use.

The deterministic proof KAT remains unchanged, so these optimizations do not
alter the proof format or Fiat-Shamir transcript.
