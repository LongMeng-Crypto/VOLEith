> Corrected constraint encoding: see [the v1 fix](doc/SOUNDNESS_FIX_V1.md). Pre-fix Boolean proof timings/fingerprints are historical and do not establish soundness. Rebuild and regenerate proofs; old proof formats are rejected.

# VOLEith

VOLEith is the canonical generic VOLE-in-the-head/QuickSilver backend used by
the surrounding projects. Its maintained proof frontends are deliberately
small:

- SHA-256, SHA-384, and SHA-512 Boolean circuits, with arbitrary bit ranges
  assigned to either the private witness or the public statement;
- SHAKE256 Boolean circuits with arbitrary single-rate-block XOF outputs;
- one optimized AES-128 relation using the FAEST GF(2^8) construction with
  200 quadratic constraints.

The expanded 76,800-AND Boolean AES circuit is not part of this repository.

## Security levels and profiles

SHA-2 circuit proofs support 128-, 192-, and 256-bit VOLEith soundness and two
FAEST parameter profiles:

| CLI | FAEST family | Purpose |
| --- | --- | --- |
| `--profile s` | 128s / 192s / 256s | smaller proof |
| `--profile f` | 128f / 192f / 256f | faster prover, larger proof |

The AES relation proves AES-128 and therefore supports the 128s and 128f
profiles. It does not lower AES into tens of thousands of Boolean AND gates;
the witness and constraints use FAEST's native extension-field traversal.

New generic-circuit proofs use the `VBCZK` v4 format. Their security level and
S/F profile are bound into the header, circuit identifier, Fiat--Shamir
transcript, VOLE layout, and verifier API. AES-relation proofs use the separate
`VQRZK` v4 format; AES has a fixed 128-bit relation identifier, while its S/F
profile is bound into the header, transcript, VOLE layout, and verifier API.
A proof is rejected under the wrong profile. APIs without an explicit profile
remain only as compatibility wrappers and select `small`.

## Build and test

```sh
meson setup build-release --buildtype=release
meson compile -C build-release
meson test -C build-release --print-errorlogs
```

The tests include deterministic v4 proof KATs for all six generic
security/profile combinations and both AES-128 profiles, plus end-to-end S/F
tests for the SHA-2 frontends. They also compare
the PCLMUL/Karatsuba field arithmetic, batched AES-CTR PRG, AVX2 transpose,
and streaming ConvertToVOLE paths against portable reference implementations.

## SHA-2 proofs

First export one fixed circuit. `--input-layout-bits` is a complete partition
of the message's half-open bit ranges and may alternate between `secret` and
`public` at arbitrary bit positions.

```sh
build-release/vole-sha256 export-sha256-circuit \
  --message-length 48 \
  --input-layout-bits "secret:0:128,public:128:384" \
  --circuit /tmp/sha256-mixed.vbc

build-release/vole-sha256 sha256-partition-input \
  --message-hex <48-byte-complete-message> \
  --input-layout-bits "secret:0:128,public:128:384"
```

The partition command prints `private_input_hex`, `public_input_hex`, and the
public digest. Pass those values to the generic prover or benchmark:

```sh
build-release/vole-sha256 circuit-benchmark \
  --circuit /tmp/sha256-mixed.vbc \
  --private-input-hex <private_input_hex> \
  --public-input-hex <public_input_hex> \
  --expected-output-hex <public_sha256> \
  --security 128 --profile s --iterations 10
```

Replace the exporter/partition pair with
`export-sha384-circuit` + `sha384-partition-input`, or
`export-sha512-circuit` + `sha512-partition-input`. `circuit-prove` and
`circuit-verify` accept the same `--security` and `--profile` options.

The unified driver runs all three standard one-block DAA workloads:

```sh
scripts/benchmark_sha2.py --iterations 10 --vole-profile s
scripts/benchmark_sha2.py --iterations 10 --vole-profile f
```

Its `--profile daa|all-secret` option selects the message visibility workload;
`--vole-profile s|f` selects the cryptographic VOLE profile.

## SHAKE256 proofs

The SHAKE256 Boolean frontend supports one padded absorb block (0..1082 secret
input bits) and an arbitrary 1..1088-bit public XOF output. It supports the
same 128/192/256-bit security levels and s/f profiles as SHA-2.

```sh
build-release/vole-shake256 --input-bits 384 --output-bits 360 \
  --security 128 --profile s --iterations 20
python3 scripts/benchmark_shake256.py --iterations 20
```

See [SHAKE256 circuit and CLI](doc/SHAKE256_BINARY_CIRCUIT.md). The reusable
[mixed quadratic relation](doc/MIXED_QUADRATIC_RELATION.md) also supports
128-bit proofs combining authenticated Boolean wires with direct field equations.

## AES-128 proof

Export the canonical 200-constraint relation once:

```sh
build-release/vole-sha256 export-aes128-faest-relation \
  --relation /tmp/aes128-faest.vqir
```

Benchmark the FIPS-197 known-answer instance in both profiles:

```sh
for p in s f; do
  build-release/vole-sha256 aes128-faest-benchmark \
    --relation /tmp/aes128-faest.vqir \
    --private-input-hex 000102030405060708090a0b0c0d0e0f \
    --public-input-hex 00112233445566778899aabbccddeeff \
    --expected-output-hex 69c4e0d86a7b0430d8cdb78070b4c55a \
    --profile "$p" --iterations 10
done
```

The corresponding one-shot commands are `aes128-faest-prove` and
`aes128-faest-verify`.

## Generic API

```cpp
using vole_backend::SecurityLevel;
using vole_backend::VoleProfile;

vole_backend::PreparedBinaryCircuit prepared(circuit);
auto proof = vole_backend::prove(
    prepared, SecurityLevel::Bits192, VoleProfile::Fast,
    private_bits, statement, context, randomness);
bool ok = vole_backend::verify(
    prepared, SecurityLevel::Bits192, VoleProfile::Fast,
    statement, context, proof);
```

The SHA circuits and visibility syntax are documented in
[`doc/SHA256_INPUT_VISIBILITY.md`](doc/SHA256_INPUT_VISIBILITY.md) and
[`doc/SHA512_FAMILY_BINARY_CIRCUIT.md`](doc/SHA512_FAMILY_BINARY_CIRCUIT.md).
Proof parameters and layouts are documented in
[`doc/SECURITY_PARAMETERS.md`](doc/SECURITY_PARAMETERS.md).

## Optimized backend

The current backend includes runtime-dispatched AES-NI eight-way CTR,
PCLMUL field multiplication through GF(2^256), Karatsuba multiplication and
specialized reduction for GF(2^192)/GF(2^256), three-lane universal hashing,
AVX2 128/192/256-column transpose, streaming ConvertToVOLE scratch reuse, and
allocation reuse in QuickSilver row packing. These are implementation-only
optimizations; the first optimization commit is byte-for-byte compatible with
the preceding proof format.
