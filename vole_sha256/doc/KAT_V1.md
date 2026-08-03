# VOLE-SHA256 KAT v1

```text
message:
000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
202122232425262728292a2b2c2d2e2f30313233343536

digest:
463eb28e72f82e0a96c0a4cc53690c571281131f672aa229e0d45ae59b598b59

context:
KAT-v1

randomness:
000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f

serialized proof bytes:
57270

SHA256(serialized proof):
084927a0522379eea5a6560f2553aacb0720bdabea9c694eba90caa0a02843fe

chall_3:
19bc0647e928404215ea5bdb20e2ad01

grinding counter:
9201
```

The regression suite regenerates the complete proof and checks its SHA-256
fingerprint.  This catches changes in the circuit, witness order, field
arithmetic, transcript ordering, VOLE parameters, BAVC serialization, or
proof layout.
