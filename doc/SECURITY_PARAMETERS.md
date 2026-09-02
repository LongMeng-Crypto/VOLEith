# Parameterized VOLEith security levels

The generic `BinaryCircuit` backend supports three explicit security levels.
Each level selects a complete, internally consistent parameter set; it is not
only a label applied to a 128-bit proof.

| API value | FAEST VOLE/BAVC | QuickSilver field | lambda | tau | grinding bits | BAVC opening |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| `Bits128` | FAEST-128s | GF(2^128) | 128 | 11 | 7 | 2,160 bytes |
| `Bits192` | FAEST-192s | GF(2^192) | 192 | 16 | 12 | 5,040 bytes |
| `Bits256` | FAEST-256s | GF(2^256) | 256 | 22 | 6 | 9,952 bytes |

For a byte-rounded committed witness of `ell` bits:

```text
ell_hat              = ell + 3*lambda + 16
ell_hat_bytes        = ceil(ell_hat / 8)
VOLE corrections     = (tau - 1) * ell_hat_bytes
u_tilde              = lambda/8 + 2
QuickSilver a1,a2    = 2 * lambda/8
challenge_3          = lambda/8
BAVC opening         = (3*tau + T_open) * lambda/8
```

The v2 generic proof header is eight bytes:

```text
56 42 43 5a 4b 02 LL 00
 V  B  C  Z  K v2 level reserved
```

`LL` is 1, 2, or 3 for 128, 192, or 256 bits. The selected level is also
absorbed into the circuit identifier and Fiat-Shamir transcript. Proof length,
header, VOLE reconstruction, field traversal, and transcript recomputation must
all agree with the verifier's requested level. Consequently, changing only the
header or asking a 128-bit verifier to accept a 192-bit proof fails.

The circuit identifier is generated with FAEST H2 at the selected security
level and has `2*lambda` bits. It commits to the canonical VBC encoding and the
security level. The CLI's displayed `circuit_hash` remains the stable SHA-256
fingerprint of the VBC file and is separate from this transcript identifier.

The legacy SHA-256 convenience API and optimized AES-128 relation retain their
existing fixed FAEST-128s implementations. New binary-circuit applications
should call the overloads in `backend/generic_nizk.hpp` that take an explicit
`SecurityLevel`. The generic prover emits v2 proofs; the 128-bit verifier also
accepts pre-parameterization generic v1 proofs for migration. A v1 proof is
never accepted at 192 or 256 bits.

As a concrete size check, the existing 55-byte SHA-256 VBC has 440 private
input bits and 22,217 AND gates. The same circuit produces these exact sizes:

| Security level | Proof bytes |
| ---: | ---: |
| 128 | 33,917 |
| 192 | 51,604 |
| 256 | 74,494 |

The Boolean gate count is independent of the security level. Only the
cryptographic backend dimensions and serialized proof overhead change.
