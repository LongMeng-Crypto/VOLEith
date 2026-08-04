# VQIR extension-field quadratic relation format

VQIR v1 is the canonical descriptor for QuickSilver relations that are not
bit-blasted Boolean circuits. Its fixed 32-byte encoding contains:

- 8-byte `VQIR` magic/version;
- extension field identifier (`GF(2^8)` in the AES polynomial basis);
- quadratic constraint family (`AES inverse-norm`);
- private, public, output and auxiliary witness bit counts;
- number of field-level multiplication constraints.

All integers are unsigned 32-bit little-endian. Reserved bytes must be zero,
the decoder rejects any other size, and SHA-256 of the canonical encoding is
bound into the Fiat-Shamir statement transcript.

AES-128s uses 128 private key bits, 128 public plaintext bits, 128 public
ciphertext bits, 1,152 auxiliary bits, and 200 inverse-norm S-box constraints.
The committed extended witness is therefore exactly 1,280 bits.
