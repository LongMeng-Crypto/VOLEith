> Corrected constraint encoding: see [the v1 fix](SOUNDNESS_FIX_V1.md). Pre-fix Boolean proof timings/fingerprints are historical and do not establish soundness. Rebuild and regenerate proofs; old proof formats are rejected.

# VOLE-SHA256 generic proof KAT v2

```text
message:
000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
202122232425262728292a2b2c2d2e2f30313233343536

digest:
463eb28e72f82e0a96c0a4cc53690c571281131f672aa229e0d45ae59b598b59

context:
KAT-v2

randomness:
000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f

serialized proof bytes:
33917

SHA256(serialized proof):
b402d9e0cd15efea2896e679e0a091c63564cd653288f41533108e1bd1e38655

chall_3:
71863ae2a27ee51799ce54d11e9ce500

grinding counter:
3173
```

The regression suite regenerates the complete proof and checks its SHA-256
fingerprint.  This catches changes in the circuit, witness order, field
arithmetic, transcript ordering, VOLE parameters, BAVC serialization, or
proof layout.
