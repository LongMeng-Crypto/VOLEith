# VOLEith TPM SHA-2 experiments

This workspace records the SHA-256/SHA-384/SHA-512 experiments that will be
composed into the TPM relation:

```text
slt = F(sk || lid)
et  = F(sk || gid)
hk  = F(s  || et)
```

The reusable frontend sources live under `circuits/sha256/` and
`circuits/sha2/`; the generic proof backend lives under `backend/`. Generated
`.vbc` and `.proof` files are intentionally not versioned.

The current individual DAA-shaped SHA-384 and SHA-512 circuits can be exported
with:

```sh
../build-release/vole-sha256 export-sha384-circuit \
  --message-length 72 \
  --input-layout-bits "secret:0:192,public:192:576" \
  --circuit sha384-sk-lid.vbc

../build-release/vole-sha256 export-sha512-circuit \
  --message-length 96 \
  --input-layout-bits "secret:0:256,public:256:768" \
  --circuit sha512-sk-lid.vbc
```

Run the corresponding partition helper on a complete message, then pass its
`private_input_hex`, `public_input_hex`, and public digest to
`circuit-prove`, `circuit-verify`, or `circuit-benchmark` with security 192 or
256, respectively. The next experiment layer will invoke the composable core
three times in one circuit, reuse the same `sk` wires, and feed the internal
`et` digest wires directly into the third hash.

Benchmark all three individual DAA-shaped hashes from the repository root:

```sh
scripts/benchmark_sha2.py --iterations 10
```

Benchmark the corresponding all-secret cases with:

```sh
scripts/benchmark_sha2.py --profile all-secret --iterations 10
```
