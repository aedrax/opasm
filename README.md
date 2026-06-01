# OpAsm

![possum](https://github.com/user-attachments/assets/08428fb0-c8f0-4ff6-a253-abd5913b9647)

An interactive assembly REPL built on Unicorn, Capstone, and Keystone. Type instructions, watch them execute, see registers change. Supports x86, x64, ARM, ARM64, MIPS32, MIPS64, PPC32, and PPC64.

## Install

```bash
# requires uv (https://docs.astral.sh/uv/)
uv sync
uv run opasm
```

Or without uv:

```bash
pip install -e .
opasm
```

## What it does

You type assembly. It runs. You see what happened.

```
opasm:x64> mov rax, 0x1234
opasm:x64> add rax, 0x5678
opasm:x64> push rax
opasm:x64> pop rbx
```

If it's not a command, it's treated as an instruction.

![image](https://github.com/user-attachments/assets/13d90e2d-50b1-4786-a105-74ec4f8807b7)

Changed values show up bold. The display adapts to your terminal height (registers only at 25+ lines, stack at 35+, code at 45+).

## Commands

```
arch [name]             switch or show architecture
registers / reg         dump all registers
memory <addr> [size]    hex dump
disasm [addr] [count]   disassemble
bp <addr>               set breakpoint
clear_bp <addr>         remove breakpoint
list_bp                 show breakpoints
step                    single-step
run [count]             run (stops at breakpoints)
set_reg <reg> <val>     write a register
set_mem <addr> <val>    write memory
load_asm <file> [addr]  assemble a file into memory
load_bin <file> [addr]  load raw bytes
dump_asm <file>         export instruction history
dump_mem <f> <a> <sz>   export memory
save <file>             save full state (JSON)
load <file>             restore state
toggle_display          auto-display on/off
toggle_direct           direct execution mode
? <expr>                calculator (supports $reg refs)
reset                   wipe state
quit / exit             done
```

Register dereferencing works anywhere you'd put an address: `memory $rsp`, `bp $rax`, etc.

## Direct execution mode

`toggle_direct` lets you run instructions without advancing the instruction pointer or modifying program memory. Useful for poking at registers without disturbing loaded code.

## Architectures

| Arch | Registers | Endian |
|------|-----------|--------|
| x86 | EAX-EDX, ESI, EDI, ESP, EBP, EIP, EFLAGS + sub-regs | little |
| x64 | RAX-RDX, RSI, RDI, RSP, RBP, RIP, RFLAGS, R8-R15 | little |
| arm | R0-R12, SP, LR, PC, CPSR | little |
| arm64 | X0-X30, SP, PC, NZCV | little |
| mips32 | $zero-$ra, PC, CP0_STATUS | big |
| mips64 | same as mips32, 64-bit | big |
| ppc32 | R0-R31, FPR0-FPR31, LR, CTR, XER, CR, PC | big |
| ppc64 | same as ppc32, 64-bit | big |

Switch at runtime with `arch arm64`, etc.

## State files

`save` and `load` persist everything like registers, memory, code history, breakpoints

## Development

```bash
uv run pytest           # run tests
uv run mypy opasm/      # type check
```

The package is split into focused modules: `architectures`, `engine`, `dispatcher`, `display`, `state`, `calculator`, `repl`, `exceptions`.

## License

GPL-2.0
