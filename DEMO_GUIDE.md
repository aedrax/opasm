# Opasm Demo Guide

This guide demonstrates how to load and use assembly files and binary blobs in the Assembly REPL.

## Files Created

1. **`demo.asm`** - Assembly source code file
2. **`demo.bin`** - Pre-compiled binary machine code
3. **`create_demo_binary.py`** - Script to generate the binary

## Demo 1: Loading Assembly File

### Start the REPL
```bash
python3 opasm.py
```

### Load the assembly file
```bash
asm-repl:x64> load_asm demo.asm
```

**Expected Output:**
```
Loading assembly file: demo.asm
    1: mov rax, 0x1234567890abcdef -> 48b8efcdab9078563412
    2: mov rbx, 0x1111 -> 48c7c311110000
    3: mov rcx, 0x2222 -> 48c7c122220000
    4: add rax, rbx -> 4801d8
    5: sub rcx, rbx -> 4829d9
    ...
Loaded 25 instructions (xxx bytes) at 0x400000
Set instruction pointer to 0x400000
```

### Execute step by step
```bash
# Execute first instruction and see registers change
asm-repl:x64> step
Stepping: 0x00400000 mov rax, 0x1234567890abcdef

# Registers will show with RAX and RIP in bold (changed)
# Continue stepping
asm-repl:x64> step
asm-repl:x64> step

# Or run multiple instructions
asm-repl:x64> run 5
```

### Examine memory and registers
```bash
# Show all registers
asm-repl:x64> registers

# Show memory at current instruction pointer
asm-repl:x64> memory $rip 64

# Show disassembly
asm-repl:x64> disasm $rip 10
```

## Demo 2: Loading Binary Blob

### Reset the environment
```bash
asm-repl:x64> reset
```

### Load the binary file
```bash
asm-repl:x64> load_bin demo.bin
```

**Expected Output:**
```
Loaded binary file: demo.bin
Loaded 45 bytes at 0x400000
Set instruction pointer to 0x400000

Disassembly preview:
┌─────────────┬──────────────────────────────────────┐
│ Address     │ Instruction                          │
├─────────────┼──────────────────────────────────────┤
│ 0x00400000: │ movabs rax, 0x4142434445464748       │
│ 0x0040000a: │ mov rbx, 0x1000                      │
│ 0x00400011: │ add rax, rbx                         │
│ 0x00400014: │ push rax                             │
│ 0x00400015: │ mov rcx, 0x200                       │
└─────────────┴──────────────────────────────────────┘
```

### Execute the binary code
```bash
# Step through each instruction
asm-repl:x64> step
# Watch RAX become 0x4142434445464748 (ASCII "ABCDEFGH")

asm-repl:x64> step  
# Watch RBX become 0x1000

asm-repl:x64> step
# Watch RAX become 0x4142434445465748 (original + 0x1000)

# Continue stepping to see all operations
asm-repl:x64> step
asm-repl:x64> step
```

## Demo 3: Advanced Usage

### Set breakpoints
```bash
# Set breakpoint at specific address
asm-repl:x64> bp 0x400014

# Run until breakpoint
asm-repl:x64> run 10
Hit breakpoint at 0x400014
```

### Use register dereferencing
```bash
# Show memory at current instruction pointer
asm-repl:x64> memory $rip 32

# Set memory at stack pointer
asm-repl:x64> set_mem $rsp 0xdeadbeef

# Show stack
asm-repl:x64> memory $rsp 64
```

### Save and restore state
```bash
# Save current state
asm-repl:x64> save my_session.json

# Reset and reload
asm-repl:x64> reset
asm-repl:x64> load my_session.json
```

## Demo 4: Interactive Assembly

### Mix loaded code with live assembly
```bash
# Load assembly file
asm-repl:x64> load_asm demo.asm

# Execute some instructions
asm-repl:x64> run 5

# Add your own instructions
asm-repl:x64> mov r15, 0xcafebabe
asm-repl:x64> xor rax, r15
asm-repl:x64> push r15
```

## Key Features Demonstrated

1. **Assembly File Loading**: Complete programs can be written in files and loaded
2. **Binary Blob Loading**: Pre-compiled machine code can be analyzed
3. **Real-time Execution**: Step through code with immediate visual feedback
4. **State Change Highlighting**: Changed registers/memory appear in bold
5. **Responsive Display**: Registers and stack auto-display based on terminal size
6. **Register Dereferencing**: Use `$register` syntax for dynamic addressing
7. **Mixed Execution**: Combine loaded code with interactive assembly

## Tips

- **Large Terminal**: You'll see automatic register and stack display with changes highlighted
- **Small Terminal**: Use manual commands like `registers` and `memory $rsp`
- **Tab Completion**: Press Tab while typing for instruction/register suggestions
- **Multiple Exits**: Use `quit`, `exit`, Ctrl+C, or Ctrl+D to exit
- **Help**: Type `help` for complete command reference

## Sample Assembly Programs

The `demo.asm` file includes examples of:
- Register initialization and manipulation
- Arithmetic operations (add, sub, multiply)
- Stack operations (push/pop)
- Logical operations (and, or, xor)
- Memory operations with addressing
- Bit manipulation (shift, rotate)
