# Unified SHA-2 benchmark driver

`scripts/benchmark_sha2.py` benchmarks SHA-256, SHA-384, and SHA-512 through
the same generic VOLEith `circuit-benchmark` path. It reports the complete
message, visibility partition, compression block size and count, knowledge
soundness, circuit size, proof size, and in-process prover/verifier timings.

The script is for benchmark inputs only: it prints the complete message and
the packed private witness. Do not pass production secrets to it.

## Default DAA profile

Run all three intended DAA profiles with ten samples per circuit:

```sh
scripts/benchmark_sha2.py --iterations 10
scripts/benchmark_sha2.py --iterations 10 --vole-profile f
```

The defaults are:

| Algorithm | Message | Visibility | Blocks | VOLEith security |
| --- | ---: | --- | ---: | ---: |
| SHA-256 | 48 bytes | `secret:0:128,public:128:384` | 1 × 512-bit | 128 |
| SHA-384 | 72 bytes | `secret:0:192,public:192:576` | 1 × 1024-bit | 192 |
| SHA-512 | 96 bytes | `secret:0:256,public:256:768` | 1 × 1024-bit | 256 |

Each algorithm gets a fresh random complete message. The script computes its
digest independently with Python `hashlib`, invokes the frontend partition
helper, and stops if the circuit digest differs.

The default cryptographic profile is `--vole-profile s` (FAEST small). Use
`--vole-profile f` for the corresponding fast parameter set. This is separate
from `--profile daa|all-secret`, which selects only the benchmark input layout.

## All-secret profile

Run the established one-block all-secret cases:

```sh
scripts/benchmark_sha2.py --profile all-secret --iterations 10
```

This selects SHA-256/55 bytes, SHA-384/72 bytes, and SHA-512/96 bytes, with
visibility layouts `secret:0:440`, `secret:0:576`, and `secret:0:768`.

Run only one algorithm:

```sh
scripts/benchmark_sha2.py \
  --algorithm sha384 \
  --profile all-secret \
  --iterations 10
```

## Arbitrary visibility and block count

Message length, visibility, and security overrides are accepted in
single-algorithm mode. For example, a two-block SHA-256 circuit with a
128-bit secret prefix and a 320-bit public suffix is:

```sh
scripts/benchmark_sha2.py \
  --algorithm sha256 \
  --message-bytes 56 \
  --input-layout-bits "secret:0:128,public:128:448" \
  --security 192 \
  --iterations 10
```

Ranges may alternate and may end at non-byte-aligned positions. The frontend
partition helper performs the required packed-bit conversion. A fixed complete
message can be supplied with `--message-hex`; otherwise cryptographically
random bytes are generated.

The selected circuit always contains the exact padding-derived block count:

```text
SHA-256:     ceil((message_bits + 1 + 64)  / 512)
SHA-384/512: ceil((message_bits + 1 + 128) / 1024)
```

## Circuit artifacts and binaries

Generated VBC files normally live in a temporary directory and are deleted
after the run. Preserve them with:

```sh
scripts/benchmark_sha2.py \
  --profile daa \
  --iterations 10 \
  --artifacts-dir benchmark-artifacts
```

The default CLI is `build-release/vole-sha256`. Select another build with
`--binary PATH`.

For every case, circuit construction, VBC serialization, input partitioning,
and digest checking happen outside the reported timing interval. The C++
`circuit-benchmark` command loads the VBC once and measures only its in-process
`prove()` and `verify()` calls across the requested iterations.
