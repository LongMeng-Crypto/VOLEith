# Parameterized VOLEith security and S/F profiles

The generic `BinaryCircuit` backend selects one complete FAEST VOLE/BAVC and
QuickSilver parameter set from a security level and an S/F profile.

| Security | Profile | FAEST | QuickSilver field | lambda | tau | grinding | BAVC opening |
| ---: | --- | --- | --- | ---: | ---: | ---: | ---: |
| 128 | s | FAEST-128s | GF(2^128) | 128 | 11 | 7 | 2,160 B |
| 128 | f | FAEST-128f | GF(2^128) | 128 | 16 | 8 | 2,528 B |
| 192 | s | FAEST-192s | GF(2^192) | 192 | 16 | 12 | 5,040 B |
| 192 | f | FAEST-192f | GF(2^192) | 192 | 24 | 8 | 5,640 B |
| 256 | s | FAEST-256s | GF(2^256) | 256 | 22 | 6 | 9,952 B |
| 256 | f | FAEST-256f | GF(2^256) | 256 | 32 | 8 | 10,944 B |

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

## v3 binding

The generic circuit proof header is:

```text
56 42 43 5a 4b 03 LL PP
 V  B  C  Z  K v3 level profile
```

`LL` is 1, 2, or 3 for 128, 192, or 256 bits. `PP` is 1 for small
and 2 for fast. Both values are absorbed into the circuit identifier and
Fiat--Shamir transcript and select the VOLE layout used by the prover and
verifier. Changing either byte, or invoking verification with a different
level/profile pair, fails.

The optimized AES relation has its own `VQRZK` v3 header to separate its
native GF(2^8) relation from the generic Boolean-circuit format. It supports
AES-128s and AES-128f only.

The CLI uses `--security 128|192|256 --profile s|f`. The C++ API uses
`SecurityLevel` and `VoleProfile`. Compatibility overloads without a profile
select `VoleProfile::Small`.
