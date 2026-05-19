#!/usr/bin/env python3
"""Cross-ASID BPU covert-channel PoC for XiangShan.

Each bit is encoded by an ASID-A sender that either trains or skips training a
taken branch at VA_PROBE.  An ASID-B receiver then times a not-taken branch at
the same virtual address against an untrained ASID-B control branch.  The tiny
runner has no useful UART, so the ELF writes STOP_MMIO only when the receiver
decodes 1.  The Python wrapper decodes each bit from stop/SIMLEN.
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
.equ VA_PROBE,       0x40000000
.equ VA_CTRL,        0x40001000
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
.equ SATP_MODE_SV39, (8 << 60)
.equ ASID_A,         0x11
.equ ASID_B,         0x22

.section .text.init
.globl _start
_start:
  la sp, stack_top

  la t0, phase
  li t1, __PHASE_INIT__
  sd t1, 0(t0)
  la t0, poison_cycles
  sd x0, 0(t0)
  la t0, control_cycles
  sd x0, 0(t0)

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

  la t0, code_taken
  li t2, PTE_CODE
  call make_pte
  la t1, l0_a
  sd t0, 0(t1)

  la t0, code_not_taken
  li t2, PTE_CODE
  call make_pte
  la t1, l0_b
  sd t0, 0(t1)

  la t0, code_ctrl
  li t2, PTE_CODE
  call make_pte
  la t1, l0_b
  sd t0, 8(t1)

  sfence.vma x0, x0
  ld ra, 8(sp)
  addi sp, sp, 16
  ret

make_pte:
  srli t0, t0, 12
  slli t0, t0, 10
  or t0, t0, t2
  ret

make_satp_a:
  li a0, SATP_MODE_SV39
  li t0, ASID_A
  slli t0, t0, 44
  or a0, a0, t0
  la t1, root_a
  srli t1, t1, 12
  or a0, a0, t1
  ret

make_satp_b:
  li a0, SATP_MODE_SV39
  li t0, ASID_B
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
  bltu t1, t2, run_train_a
  beq t1, t2, run_poisoned_b
  addi t3, t2, 1
  beq t1, t3, run_control_b
  j finish_report

run_train_a:
  call make_satp_a
  li a1, VA_PROBE
  j enter_s_va

run_poisoned_b:
  call make_satp_b
  li a1, VA_PROBE
  j enter_s_va

run_control_b:
  call make_satp_b
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
code_taken:
  csrr a0, cycle
  beq x0, x0, 1f
  nop
1:
  csrr a1, cycle
  sub a0, a1, a0
  ecall

.align 12
code_not_taken:
  csrr a0, cycle
  bne x0, x0, 1f
  nop
1:
  csrr a1, cycle
  sub a0, a1, a0
  ecall

.align 12
code_ctrl:
  csrr a0, cycle
  bne x0, x0, 1f
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


def build_and_run_case(
    out_dir: pathlib.Path,
    bit_index: int,
    bit: str,
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
    case_name = f"bit_{bit_index}_{bit}"
    asm_path = src_dir / f"{case_name}.S"
    elf_path = build_dir / f"{case_name}.elf"
    dump_path = build_dir / f"{case_name}.dump"
    log_path = log_dir / f"{case_name}.log"

    phase_init = 0 if bit == "1" else train_iters
    asm_text = (
        ASM.replace("__TRAIN_ITERS__", str(train_iters))
        .replace("__THRESHOLD__", str(threshold))
        .replace("__PHASE_INIT__", str(phase_init))
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
    parser.add_argument("--message", default="10", help="bit string to send")
    parser.add_argument("--threshold", type=int, default=10)
    parser.add_argument("--train-iters", type=int, default=32)
    parser.add_argument("--repetitions", type=int, default=1)
    parser.add_argument("--simlen", type=int, default=60000)
    parser.add_argument("--timeout", type=int, default=360)
    parser.add_argument("--out-dir", default="")
    parser.add_argument("--runner", default=DEFAULT_RUNNER)
    parser.add_argument("--use-docker", action="store_true")
    parser.add_argument("--host-base", default=os.environ.get("XS_HOST_BASE", ""))
    parser.add_argument("--container-base", default=str(DEFAULT_CONTAINER_BASE))
    parser.add_argument("--container", default=DEFAULT_CONTAINER)
    args = parser.parse_args()

    if any(ch not in "01" for ch in args.message):
        raise SystemExit("--message must contain only 0/1 bits")
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
    out_dir = pathlib.Path(args.out_dir) if args.out_dir else pathlib.Path("runs") / f"covert_{stamp}"
    out_dir = out_dir.resolve()
    if args.use_docker:
        try:
            out_dir.relative_to(host_base)
        except ValueError as exc:
            raise SystemExit("--out-dir must be under --host-base when --use-docker is set") from exc
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"OUT_DIR={out_dir}", flush=True)

    rows = ["idx\trepetition\tsent\tdecoded\tfound_stop\treached_simlen\tlog\n"]
    decoded_bits: list[str] = []
    for idx, bit in enumerate(args.message):
        bit_decodes: list[str] = []
        for rep in range(args.repetitions):
            decoded, found_stop, reached_simlen, log_path = build_and_run_case(
                out_dir,
                idx,
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
            f"RESULT idx={idx} sent={bit} votes={''.join(bit_decodes)} decoded={decoded_bit}",
            flush=True,
        )

    decoded_msg = "".join(decoded_bits)
    ok = decoded_msg == args.message
    summary = out_dir / "summary.tsv"
    summary.write_text("".join(rows), encoding="utf-8")
    print(f"DECODED={decoded_msg}", flush=True)
    print(f"MATCH={int(ok)}", flush=True)
    print(f"SUMMARY={summary}", flush=True)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
