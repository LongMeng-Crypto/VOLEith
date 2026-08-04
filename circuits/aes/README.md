# AES-128 circuit frontend

`aes128_circuit.*` is the portable Boolean baseline. It proves
`AES-128(private_key, public_plaintext) = public_ciphertext`. It lowers the
complete key schedule and ten encryption rounds to the common XOR/AND
`BinaryCircuit` IR. Packed bits within each byte are least-significant-bit
first.

The S-box computes inversion in GF(2^8) followed by the AES affine map.
Squarings are linear and six field multiplications use 384 AND gates per
S-box. Encryption and key expansion together use 76,800 AND gates.

`third_party/faest/aes.c` has a different role: it is the upstream AES-based
PRG used internally by BAVC/VOLE, not the circuit being proved.

`aes128_faest_circuit.*` is the optimized extension-field frontend. It uses
the original FAEST-128s inverse-norm/conjugate QuickSilver traversal: 40 key
schedule S-box constraints plus 160 encryption S-box constraints. Its
committed witness is 1,280 bits and its proof is 4,514 bytes with the current
generic Fiat-Shamir framing. Both frontends are cross-checked against the same
FIPS-197 vector.
