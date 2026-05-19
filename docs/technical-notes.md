# Technical Notes

## Vulnerability Model

The PoC uses two address spaces:

- victim ASID: trains a branch whose direction depends on a secret bit;
- attacker ASID: executes the same virtual branch with a known not-taken input.

The attacker compares the timed branch against an untrained control branch.  If
the victim trained the branch as taken, the attacker's not-taken branch sees a
measurable penalty and decodes bit `1`; otherwise it decodes bit `0`.

The key property is that predictor state is observable across ASID separation
for colliding virtual branch PCs.

## Why This PoC Uses BPU State Directly

Experiments also attempted Spectre-style D-cache receivers using wrong-path
loads.  On the tested runner, the architectural cache receiver works, but
cross-ASID wrong-path loads did not leave a stable D-cache footprint.

Using BPU state as the receiver is more reliable and directly demonstrates
information leakage:

- single-bit leakage works;
- byte-level leakage works;
- repeated measurements can be majority-voted with `--repetitions`.

## Impact

This can leak secret-dependent control-flow decisions across address spaces.
The primitive is relevant when sensitive data influences victim branch direction,
for example:

- byte-by-byte secret comparisons with early exits;
- key-bit dependent branches;
- exponent-bit dependent branches;
- non-constant-time authorization or parser checks.

## Limitations

- The PoC does not demonstrate arbitrary memory disclosure.
- The PoC does not demonstrate architectural control-flow hijacking.
- The victim must execute a branch whose direction depends on sensitive data.
- The attacker needs a colliding virtual branch PC and a timing receiver.
- The exact threshold may need tuning for a different runner or configuration.

## Related Negative Result

Zicbop software prefetch instructions were not used as the final receiver.  They
follow special XiangShan paths and can confound reproduction of D-cache based
gadgets, so this repository focuses on the verified BPU-state receiver.
