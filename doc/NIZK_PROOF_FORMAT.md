# Fiat-Shamir transcript and proof format

This document first records the fixed-128 compatibility format used by the
SHA-256 convenience API. The generic `.vbc` API now uses the parameterized v2
format described in the final section.

## Transcript

The statement digest is

```text
mu = H2_0("VOLE-SHA256-GENERIC-NIZK-v2" || max_bytes || message_length ||
          digest || len(context) || context).
```

The prover derives the VOLE root key and IV preimage from the complete witness,
`mu`, and 32 bytes of caller-supplied randomness using `H3`.  The remaining
challenges follow the FAEST ordering:

```text
chall_1 = H2_1(mu || hcom || corrections || iv)
u_tilde = vole_hash(chall_1, u)
V_tilde[j] = vole_hash(chall_1, V[j])
chall_2 = H2_2(chall_1 || u_tilde || all V_tilde || d)
(a0,a1,a2) = SHA256-QuickSilver(chall_2)
chall_3 = H2_3(chall_2 || a0 || a1 || a2 || counter)
```

The prover grinds `counter` until the FAEST-128s grinding condition holds and
the BAVC challenge can be decoded and opened.  The verifier reconstructs `Q`
and `hcom`, recomputes `chall_1`, derives `Q_tilde`, reconstructs `a0`, and
finally recomputes `chall_3`.

## Serialization

The public message length determines the circuit, witness layout and expected
proof size. Integers are little-endian.

```text
field                    bytes
magic/version                8
VOLE corrections       10 * ell_hat_bytes
u_tilde                     18
masked witness d         ceil(ell/8)
a1                          16
a2                          16
BAVC opening             2,160
chall_3                     16
IV preimage                 16
grinding counter             4
--------------------------------
total                    derived from public length
```

Examples are 2,754 bytes for an empty message, 33,917 bytes for 55 bytes,
57,930 bytes for 56 bytes, and 287,665 bytes for the 550-byte maximum.

`a0` is intentionally absent: as in FAEST, the verifier reconstructs it from
`Q`, `d`, `a1`, `a2`, and the public SHA-256 statement.

The magic bytes contain both the protocol identifier and serialization
version. The verifier derives the expected size from the public length and
rejects an incorrect size or version before cryptographic processing.

## Parameterized generic VBC proof v2

For `vole_backend::prove(BinaryCircuit, SecurityLevel, ...)`, every occurrence
of 128 above is replaced by the selected `lambda` (128, 192, or 256), and the
corresponding FAEST-S VOLE/BAVC and `zk_hash_lambda` implementation is used.
The generic transcript domain is `VOLE-BINARY-CIRCUIT-NIZK-v2` followed by the
one-byte security-level code. Its relation identifier is a `2*lambda`-bit H2
digest of the canonical VBC bytes, domain, and security level.

```text
field                    bytes
magic/version/level          8
VOLE corrections       (tau - 1) * ell_hat_bytes
u_tilde                 lambda/8 + 2
masked witness d        ceil(ell/8)
a1                      lambda/8
a2                      lambda/8
BAVC opening            (3*tau + T_open) * lambda/8
chall_3                 lambda/8
IV preimage                 16
grinding counter             4
```

The header is `VBCZK`, version 2, security code 1/2/3, and one reserved zero
byte. A verifier is given an expected `SecurityLevel`; header mismatch, size
mismatch, or a transcript generated at another level is rejected. Exact
FAEST-S parameters are listed in `SECURITY_PARAMETERS.md`. For migration, only
the 128-bit generic verifier additionally recognizes the former generic v1
format; v1 is never interpreted as a 192- or 256-bit proof.
