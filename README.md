# XiangShan Cross-ASID BPU Leak PoC

Minimal proof of concept for a cross-ASID branch predictor state leak in
OpenXiangShan XiangShan.

The PoC demonstrates that branch predictor state trained by a victim address
space can be observed by an attacker address space with a different ASID when
the two execute a colliding virtual branch.  A victim secret bit controls the
victim branch direction; the attacker measures the same virtual branch with a
known not-taken input and decodes the secret from the timing effect.

This repository is intended as supporting code for vulnerability reporting and
CVE coordination.

## Tested Target

The byte-level result in `docs/results.md` was reproduced on:

- OpenXiangShan XiangShan branch: `kunminghu-v3`
- commit: `064f8462a6bfc13994099e2eb70c63fa5f63b85b`
- subject: `feat(ftq): drop resolve when no mispredict (#5759)`
- date: `2026-05-19T10:37:32+08:00`
- generated configuration: `TLMinimalConfig`
- runner type: Cascade vanilla no-trace Verilator runner

## Repository Contents

- `poc/bpu_branch_leak_poc.py`: self-contained PoC generator/runner.
- `poc/bpu_covert_channel_poc.py`: cross-ASID BPU covert-channel PoC.
- `docs/results.md`: verified reproduction output.
- `docs/technical-notes.md`: impact, assumptions, and limitations.

Generated ELFs, dumps, VCDs, logs, and local runner binaries are intentionally
not included.

## Prerequisites

You need:

- Python 3.10 or newer.
- `riscv64-unknown-elf-gcc`.
- `riscv64-unknown-elf-objdump`.
- A XiangShan `TLMinimalConfig` Verilator runner that accepts:
  - `SIMLEN`
  - `SIMSRAMELF`
  - `TRACEFILE`

The script can run directly on the host, or inside an existing Docker-based
Cascade mount setup.

## Reproduce Impact 1: Covert Channel

Host runner:

```bash
python3 poc/bpu_covert_channel_poc.py \
  --runner /absolute/path/to/Vtop_tiny_soc \
  --message 10 \
  --threshold 10 \
  --train-iters 32 \
  --simlen 60000 \
  --timeout 420
```

Expected successful output:

```text
RESULT idx=0 sent=1 votes=1 decoded=1
RESULT idx=1 sent=0 votes=0 decoded=0
DECODED=10
MATCH=1
```

## Reproduce Impact 2: Secret-Dependent Branch Leak

Host runner:

```bash
python3 poc/bpu_branch_leak_poc.py \
  --runner /absolute/path/to/Vtop_tiny_soc \
  --secret-hex a5 \
  --threshold 20 \
  --train-iters 32 \
  --simlen 60000 \
  --timeout 420
```

Equivalent environment-variable form for either script:

```bash
XS_RUNNER=/absolute/path/to/Vtop_tiny_soc \
python3 poc/bpu_branch_leak_poc.py --secret-hex a5 --threshold 20
```

Docker runner:

```bash
python3 poc/bpu_branch_leak_poc.py \
  --use-docker \
  --container codex_cascade_cpu_fuzzing \
  --host-base /absolute/host/mount \
  --container-base /cascade-mountdir \
  --runner /cascade-mountdir/path/to/Vtop_tiny_soc \
  --secret-hex a5 \
  --threshold 20
```

Expected successful output:

```text
SECRET_BITS=10100101
DECODED_SECRET=10100101
DECODED_HEX=a5
MATCH=1
```

## Security Interpretation

This is a cross-ASID microarchitectural information leak.  It is stronger than a
cooperative covert channel because the victim only needs to execute a
secret-dependent branch at a colliding virtual branch PC.  It is not an
architectural control-flow hijack, and the current PoC is not an arbitrary
memory read: sensitive data must influence victim control flow.

Practical examples of vulnerable victim behavior include non-constant-time
checks where key bits, comparison bytes, or exponent bits affect branch
direction.
