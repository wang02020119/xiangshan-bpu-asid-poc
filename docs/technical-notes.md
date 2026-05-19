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

## Exploit Modes

### Impact 1: Covert Channel

`poc/bpu_covert_channel_poc.py` models two cooperating processes on the same
hart/core:

- ASID A sender encodes `1` by training a taken branch at `VA_PROBE`;
- ASID A sender encodes `0` by skipping that training window;
- ASID B receiver times its own not-taken branch at the same virtual address;
- ASID B compares that timing with an untrained control branch.

This is the most direct and stable primitive: branch predictor state becomes a
bit channel across ASID separation.

### Impact 2: Secret-Dependent Branch Leakage

`poc/bpu_branch_leak_poc.py` models a non-cooperating victim whose branch
direction depends on sensitive data.  The attacker decodes victim branch
direction from the same cross-ASID predictor effect.  The verified PoC leaks
byte `0xa5` bit-by-bit.

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
