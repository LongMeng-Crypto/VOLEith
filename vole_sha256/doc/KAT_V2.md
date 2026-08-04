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
57270

SHA256(serialized proof):
761c0fb1ae86dafbec492ff304dab050472ff05e92397259d026c9c9a11cc884

chall_3:
572dea5393c5797be1bd54061b410100

grinding counter:
747
```

The regression suite regenerates the complete proof and checks its SHA-256
fingerprint.  This catches changes in the circuit, witness order, field
arithmetic, transcript ordering, VOLE parameters, BAVC serialization, or
proof layout.
