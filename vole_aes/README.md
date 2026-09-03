# AES-128 experiment workspace

This workspace is for generated artifacts from the single maintained AES
frontend: the FAEST GF(2^8), 200-constraint AES-128 relation. Generated
`.vqir` and proof files are ignored by Git.

```sh
build-release/vole-sha256 export-aes128-faest-relation \
  --relation vole_aes/aes128-faest.vqir

for p in s f; do
  build-release/vole-sha256 aes128-faest-benchmark \
    --relation vole_aes/aes128-faest.vqir \
    --private-input-hex 000102030405060708090a0b0c0d0e0f \
    --public-input-hex 00112233445566778899aabbccddeeff \
    --expected-output-hex 69c4e0d86a7b0430d8cdb78070b4c55a \
    --profile "$p" --iterations 10
done
```

Use `aes128-faest-prove` and `aes128-faest-verify` for one-shot proofs.
The old expanded Boolean AES circuit is intentionally absent.
