# AES-128 FAEST relation

`aes128_faest_circuit.*` proves
`AES-128(private_key, public_plaintext) = public_ciphertext` using the native
FAEST GF(2^8) inverse-norm/conjugate QuickSilver relation.

The relation has 40 key-schedule S-box constraints and 160 encryption S-box
constraints, for 200 extension-field quadratic constraints in total. Its
committed witness is 1,280 bits: a 128-bit key plus 1,152 auxiliary bits.

Both FAEST-128s and FAEST-128f VOLE profiles are supported. The selected
profile is bound into the `VQRZK` v3 proof header and transcript. The removed
Boolean AES frontend is intentionally not a fallback: AES proofs must continue
to use this 200-constraint relation.
