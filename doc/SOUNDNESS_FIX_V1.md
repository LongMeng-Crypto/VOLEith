# Corrected constraint encoding, research baseline v1

The pre-fix Boolean and mixed-quadratic adapters omitted the residual of a
quadratic constraint while the FAEST envelope transmitted a degree-2 check
coefficient. A malicious prover could absorb the residual hash into a2.
Honest input validation and ordinary proof-byte tampering tests did not detect
this attack. This is a local adapter error, not a change to SHAKE/SHA-2 or VOLE.

For E(X)=A0+X*A1+X^2*C, the corrected adapter checks X*E(X). Its coefficients
fed to the three-channel hasher are (0,A0,A1); the unsent degree-3 coefficient
is C. The two-lambda-bit mask polynomial has degree at most two, so changing
sent a1/a2 cannot cancel C*Delta^3. Public-output and transport-padding
constraints are raised in the same way. The verifier multiplies the complete
constraint hash by Delta before adding the unraised mask polynomial.
Field-linearity permits this lift after aggregation using two field
multiplications instead of one at every constraint.

VBCZK generic proofs, circuit-ID domain, and profiled VQRZK relation proofs
use version 4. The fixed-128 relation overload uses VQRZK version 4 with
level/profile bytes zero. Its old VBCZK-v1 fallback is removed. The separate
legacy SHA-256 convenience API uses VSH256 version 3. Old proof headers are
rejected; old fingerprints and pre-fix measurements are historical artifacts.
The serialized byte lengths, witnesses, 24 Keccak rounds, input visibility,
security/profile parameters, and GF(16)/GF(256) embeddings are unchanged.

The optimized native FAEST AES relation already raises its quadratic checks
and correctly handles its cubic checks. Its arithmetic is unchanged; its
shared relation envelope moves to v4. The standalone malicious-prover suite
checks wrong-ciphertext and coefficient-modification rejection as well as
valid AES constraints. Generic Boolean AES, if imported as a circuit, receives
the same fix as every other Boolean circuit.

Run `meson test -C build-release --print-errorlogs` after rebuilding.
`vole_soundness_tests` bypasses honest validation and tests a2 absorption for
false public outputs, false AND outputs, and nonzero padding at all six
profiles, plus historical forgeries with original and relabelled headers.
The main repository additionally tests an unsatisfiable mixed relation,
the legacy SHA-256 adapter and native AES. Protocol KATs were regenerated
only after the new prover's proofs passed the corresponding verifier.

This baseline keeps SHAKE as degree-2 per-AND constraints, homogeneously
lifted into the degree-3 FAEST envelope. It does not implement multi-round
high-degree SHAKE. The requested future optimization is baseline v2.
