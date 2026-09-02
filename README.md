# VOLEith

An independent, circuit-oriented VOLE-in-the-head/QuickSilver proof system.
The repository separates a generic proof backend from SHA-256, SHA-384,
SHA-512, and AES-128 frontends, and retains only the minimal FAEST primitives
needed by the backend.

The current implementation contains:

- an algorithm-independent in-memory `BinaryCircuit` IR and builder;
- an optimized SHA-256 Boolean frontend with public-length-derived capacity;
- arbitrary bit-range SHA-256 input visibility layouts, with public bits in
  the statement and secret bits in the VOLE witness;
- a shared, composable SHA-512-family core with optimized SHA-384 and SHA-512
  wrappers and arbitrary bit-range input visibility;
- both portable Boolean and FAEST-style extension-field AES-128 frontends;
- generic private/public input QuickSilver and NIZK APIs;
- runtime-selectable 128-, 192-, and 256-bit soundness for every generic
  binary-circuit proof;
- canonical `.vbc` serialization with circuit-hash transcript binding;
- a public SHA-256 message length from 0 through 550 bytes, with secret message bytes;
- standard SHA-256 padding and chaining over one through nine blocks;
- public-length-derived witness and VOLE capacity: only actual message bits
  and actual circuit AND outputs are committed;
- a generic degree-2 QuickSilver algebra layer for `x*y+z=0` and public linear
  constraints;
- randomized constraint aggregation over the FAEST GF(2^128), GF(2^192), or
  GF(2^256) polynomial basis selected for the proof;
- full SHA-256 constraint traversal through FAEST's native
  `zk_hash_128_3`/`zk_hash_128` QuickSilver accumulators;
- vendored minimal FAEST `vole_commit`, BAVC, field and SHAKE primitives under
  `third_party/faest`, with upstream attribution and no external FAEST build;
- a complete Fiat-Shamir transcript binding length, digest and context, and a dynamically sized serialized
  non-interactive proof with public `prove`/`verify` APIs;
- a command-line prover/verifier, deterministic known-answer test, negative
  tests and release benchmark driver.

## Current reference results

Ten in-process iterations on the development machine produced the following
reference measurements. They are implementation baselines, not portable
performance guarantees.

| Relation | Nonlinear constraints | Proof bytes | Prover mean | Verifier mean |
| --- | ---: | ---: | ---: | ---: |
| SHA-256, 55-byte secret, one block | 22,217 GF(2) AND | 33,917 | 87.98 ms | 73.38 ms |
| AES-128 Boolean baseline | 76,800 GF(2) AND | 108,530 | 309.94 ms | 267.97 ms |
| AES-128 FAEST-style | 200 GF(2^8) quadratic | 4,514 | 18.72 ms | 14.71 ms |

The SHA-256 circuit uses one-AND full-adder carries and a one-AND `Maj`
identity. XOR gates remain linear and do not add committed multiplication
outputs. Full benchmark context and dynamic-size data are in
[`doc/BENCHMARK.md`](doc/BENCHMARK.md).

Build and test from a clean checkout:

```sh
meson setup build
meson compile -C build
meson test -C build --print-errorlogs
```

The command-line executable is still named `vole-sha256` for compatibility
with existing scripts, although the Meson project and repository are `VOLEith`.

Example CLI workflow:

```sh
build/vole-sha256 prove --message-hex <0..1100 hex chars> --proof proof.bin --context app-v2
build/vole-sha256 verify --digest-hex <64 hex chars> --message-length <0..550> --proof proof.bin --context app-v2
build/vole-sha256 inspect --message-length <0..550> --proof proof.bin
build/vole-sha256 benchmark --iterations 10
```

Generic circuit-file workflow:

```sh
build/vole-sha256 export-sha256-circuit --message-length 55 --circuit sha256-55.vbc
build/vole-sha256 export-sha384-circuit --message-length 72 \
  --input-layout-bits "secret:0:192,public:192:576" --circuit sha384.vbc
build/vole-sha256 export-sha512-circuit --message-length 96 \
  --input-layout-bits "secret:0:256,public:256:768" --circuit sha512.vbc
build/vole-sha256 export-aes128-circuit --circuit vole_aes/aes128.vbc
build/vole-sha256 export-aes128-faest-relation --relation vole_aes/aes128-faest.vqir
build/vole-sha256 json-to-vbc --json examples/and_xor.json --circuit and_xor.vbc
build/vole-sha256 circuit-inspect --circuit sha256-55.vbc --security 128
build/vole-sha256 circuit-prove --circuit sha256-55.vbc \
  --private-input-hex <packed private bits> \
  --expected-output-hex <packed public output bits> \
  --proof proof.bin --context app-v1 --security 128
build/vole-sha256 circuit-verify --circuit sha256-55.vbc \
  --expected-output-hex <packed public output bits> \
  --proof proof.bin --context app-v1 --security 128
build/vole-sha256 circuit-benchmark --circuit sha256-55.vbc \
  --private-input-hex <packed private bits> \
  --expected-output-hex <packed public output bits> \
  --context app-v1 --iterations 10 --security 128
```

`circuit-benchmark` deserializes the circuit and parses all inputs once, then
times only the in-process generic `prove()` and `verify()` calls. It reports
mean/min/max milliseconds, proof bytes, and XOR/AND gate counts.

Use `--security 128`, `--security 192`, or `--security 256` on all four
`circuit-*` commands. The default is 128 for command compatibility. The
selected level controls the FAEST-S VOLE/BAVC instance, number of VOLE columns,
extension field, all Fiat-Shamir output lengths, grinding condition, and proof
layout. It is encoded in the v2 proof header and transcript; a verifier invoked
at another level rejects the proof before reconstruction. The optimized
AES-128 FAEST relation remains intentionally fixed to FAEST-128s.

The optimized AES-128s relation uses extension-field quadratic constraints:

```sh
build/vole-sha256 aes128-faest-prove --relation vole_aes/aes128-faest.vqir \
  --private-input-hex <16-byte-key> --public-input-hex <16-byte-plaintext> \
  --expected-output-hex <16-byte-ciphertext> --proof vole_aes/aes128-faest.proof
build/vole-sha256 aes128-faest-verify --relation vole_aes/aes128-faest.vqir \
  --public-input-hex <16-byte-plaintext> \
  --expected-output-hex <16-byte-ciphertext> --proof vole_aes/aes128-faest.proof
```

The strict JSON compiler format is documented in
[`doc/JSON_CIRCUIT_FORMAT.md`](doc/JSON_CIRCUIT_FORMAT.md). Generic backend
implementation files live under `backend/`; hash and AES frontends live under
`circuits/sha256/`, `circuits/sha2/`, and `circuits/aes/`.

Mixed public/secret SHA-256 inputs use a complete range partition. For a
48-byte preimage whose first 128 bits are secret and remaining 256 bits are
public:

```sh
build/vole-sha256 export-sha256-circuit --message-length 48 \
  --input-layout-bits "secret:0:128,public:128:384" \
  --circuit sha256-mixed.vbc

build/vole-sha256 sha256-partition-input \
  --message-hex <48-byte-complete-message> \
  --input-layout-bits "secret:0:128,public:128:384"
```

The partition helper emits compact `private_input_hex`, `public_input_hex`,
and the public digest for `circuit-prove`. Ranges are half-open, may alternate
at arbitrary bit positions, and must cover the complete message. See
[`doc/SHA256_INPUT_VISIBILITY.md`](doc/SHA256_INPUT_VISIBILITY.md).

SHA-384 and SHA-512 use the same range syntax and a shared composable core.
For their construction, exact DAA-sized gate counts, VBC export commands, and
the direct digest-wire composition interface, see
[`doc/SHA512_FAMILY_BINARY_CIRCUIT.md`](doc/SHA512_FAMILY_BINARY_CIRCUIT.md).

`vole_sha256/`, `vole_aes/`, and `vole_TPM_sha2/` are experiment workspaces
containing reproducible commands for their frontends. Generated `.vbc`,
`.vqir`, `.proof`, and build files are deliberately not versioned;
authoritative frontend sources remain under `circuits/`.

To benchmark fresh random printable secrets and print every secret,
public digest, prover/verifier time and proof size:

```sh
scripts/benchmark_random.py --iterations 5 --message-bytes 550
```

For a unified SHA-256/SHA-384/SHA-512 benchmark with explicit visibility,
compression-block count, and 128/192/256-bit VOLEith soundness profiles:

```sh
scripts/benchmark_sha2.py --iterations 10
scripts/benchmark_sha2.py --profile all-secret --iterations 10
```

The first command runs the three mixed-input DAA profiles; the second runs all
three one-block all-secret profiles. Arbitrary single-algorithm message lengths,
bit-range layouts, and security overrides are supported. See
[`doc/SHA2_BENCHMARK_DRIVER.md`](doc/SHA2_BENCHMARK_DRIVER.md).

This script defaults to `build-release/vole-sha256`; use `--binary PATH` for
another build.  It delegates to the in-process C++ benchmark, so the reported
prover and verifier times exclude process startup and one-time circuit
construction.

For meaningful performance results, configure Meson with
`--buildtype=release`; the default developer build is unoptimized.
The measured baseline and reproduction command are in `doc/BENCHMARK.md`.

The integration tests establish `Q = V + Delta*u`, form `d = witness XOR u`,
and check that the verifier reconstructs the prover's `a0`.  They also reject
an incorrect public digest, an incorrect committed AND output, and a tampered
masked witness.

The algorithm-independent NIZK API is declared in `backend/generic_nizk.hpp`;
the SHA-256 convenience API is declared in `circuits/sha256/nizk.hpp`:

```cpp
auto proof = vole_sha256::prove(circuit, secret_message, public_digest,
                                application_context, randomness);
bool ok = vole_sha256::verify(circuit, public_digest,
                              application_context, proof);
```

The parameterized generic binary-circuit API is:

```cpp
using vole_backend::SecurityLevel;
auto proof = vole_backend::prove(circuit, SecurityLevel::Bits192,
                                 private_bits, statement, context, randomness);
bool ok = vole_backend::verify(circuit, SecurityLevel::Bits192,
                               statement, context, proof);
```

This is the interface used by the SHA-256/SHA-384/SHA-512 frontends and
intended for the forthcoming composed TPM relation. Parameter definitions and
proof-layout formulas are documented in
[`doc/SECURITY_PARAMETERS.md`](doc/SECURITY_PARAMETERS.md).
