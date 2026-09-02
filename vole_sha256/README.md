# SHA-256 experiment workspace

This directory holds locally generated SHA-256 circuits and proofs. The
authoritative frontend sources remain in `circuits/sha256/`, while the generic
VOLE-in-the-head backend remains in `backend/`. Generated binary artifacts and
build directories are ignored by Git and can be reproduced with the commands
below.

The fixed test vector uses the 55-byte message `00 01 ... 36`:

```text
message:
000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
202122232425262728292a2b2c2d2e2f30313233343536

digest:
463eb28e72f82e0a96c0a4cc53690c571281131f672aa229e0d45ae59b598b59
```

From the repository root, export the optimized one-block circuit:

```sh
build-release/vole-sha256 export-sha256-circuit \
  --message-length 55 \
  --circuit vole_sha256/sha256-55.vbc
```

Generate and verify a generic circuit proof:

```sh
build-release/vole-sha256 circuit-prove \
  --circuit vole_sha256/sha256-55.vbc \
  --private-input-hex \
    000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30313233343536 \
  --expected-output-hex \
    463eb28e72f82e0a96c0a4cc53690c571281131f672aa229e0d45ae59b598b59 \
  --context sha256-optimized-v1 \
  --proof vole_sha256/sha256.proof

build-release/vole-sha256 circuit-verify \
  --circuit vole_sha256/sha256-55.vbc \
  --expected-output-hex \
    463eb28e72f82e0a96c0a4cc53690c571281131f672aa229e0d45ae59b598b59 \
  --context sha256-optimized-v1 \
  --proof vole_sha256/sha256.proof
```

Benchmark the same relation without process-startup or circuit-loading time:

```sh
build-release/vole-sha256 circuit-benchmark \
  --circuit vole_sha256/sha256-55.vbc \
  --private-input-hex \
    000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30313233343536 \
  --expected-output-hex \
    463eb28e72f82e0a96c0a4cc53690c571281131f672aa229e0d45ae59b598b59 \
  --context sha256-optimized-v1 \
  --iterations 10
```

For a different public message length from 0 through 550 bytes, export a
matching `.vbc`; the SHA-256 padding, block count, witness capacity, and proof
size are derived from that public length.
