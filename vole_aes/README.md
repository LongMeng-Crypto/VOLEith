# AES experiment workspace

This directory holds locally generated AES circuits, relations, and proofs.
The authoritative frontend sources remain in `circuits/aes/`, while the generic
VOLE-in-the-head backend remains in `backend/`. Generated binary artifacts are
ignored by Git and can always be reproduced with the commands below.

From the repository root, export the portable Boolean circuit:

```sh
build-release/vole-sha256 export-aes128-circuit \
  --circuit vole_aes/aes128.vbc
```

Prove and verify the FIPS-197 known-answer vector with the Boolean frontend:

```sh
build-release/vole-sha256 circuit-prove \
  --circuit vole_aes/aes128.vbc \
  --private-input-hex 000102030405060708090a0b0c0d0e0f \
  --public-input-hex 00112233445566778899aabbccddeeff \
  --expected-output-hex 69c4e0d86a7b0430d8cdb78070b4c55a \
  --context aes128-boolean-v1 \
  --proof vole_aes/aes128.proof

build-release/vole-sha256 circuit-verify \
  --circuit vole_aes/aes128.vbc \
  --public-input-hex 00112233445566778899aabbccddeeff \
  --expected-output-hex 69c4e0d86a7b0430d8cdb78070b4c55a \
  --context aes128-boolean-v1 \
  --proof vole_aes/aes128.proof
```

Export, prove, and verify the optimized FAEST-style relation:

```sh
build-release/vole-sha256 export-aes128-faest-relation \
  --relation vole_aes/aes128-faest.vqir

build-release/vole-sha256 aes128-faest-prove \
  --relation vole_aes/aes128-faest.vqir \
  --private-input-hex 000102030405060708090a0b0c0d0e0f \
  --public-input-hex 00112233445566778899aabbccddeeff \
  --expected-output-hex 69c4e0d86a7b0430d8cdb78070b4c55a \
  --context aes128-faest-v1 \
  --proof vole_aes/aes128-faest.proof

build-release/vole-sha256 aes128-faest-verify \
  --relation vole_aes/aes128-faest.vqir \
  --public-input-hex 00112233445566778899aabbccddeeff \
  --expected-output-hex 69c4e0d86a7b0430d8cdb78070b4c55a \
  --context aes128-faest-v1 \
  --proof vole_aes/aes128-faest.proof
```
