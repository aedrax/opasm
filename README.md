# Opasm - Assembly REPL

A comprehensive assembly language REPL (Read-Eval-Print Loop) with professional debugging features, built with Capstone and Unicorn engines. This tool provides an interactive environment for assembly development, reverse engineering, and education with real-time visual feedback.

## Key Features

### **Interactive Assembly Development**
- **Direct Assembly Mode**: Type instructions without "asm" prefix - just `mov rax, 0x1234`
- **Real-time Execution**: Execute assembly instantly with immediate visual feedback
- **Multi-Architecture Support**: x86, x64, ARM, ARM64 with runtime switching
- **Context-Aware Autocompletion**: Smart tab completion for instructions, registers, and commands

### **Professional Debugging Interface**
- **Responsive Auto-Display**: Automatically shows registers, stack, and code based on terminal size
- **State Change Highlighting**: Changed values appear in **bold** for immediate visual feedback
- **GEF-style Register Display**: Clean, organized register view similar to GDB with GEF
- **Code Disassembly View**: Shows machine code bytes + disassembly around current instruction pointer
- **Register Dereferencing**: Use `$register` syntax for dynamic addressing

### **Code Loading & Analysis**
- **Assembly File Loading**: Load and assemble `.asm` files with syntax checking
- **Binary Blob Analysis**: Load pre-compiled machine code for reverse engineering
- **Automatic Disassembly**: Preview loaded binaries with immediate disassembly
- **State Management**: Save and restore complete CPU state to files

### **Advanced Debugging Tools**
- **Breakpoints**: Set and manage breakpoints with register dereferencing
- **Single Stepping**: Step through code with automatic display updates
- **Memory Inspection**: Rich hex dump display with ASCII representation
- **Multiple Exit Methods**: `quit`, `exit`, Ctrl+C, Ctrl+D

## Visual Experience

On larger terminals, the REPL automatically displays:

```bash
asm-repl:x64> mov rax, 0x1234

Executed: mov rax, 0x1234

┌─────────────── Registers (X64) ────────────────┐
│ **RAX  0x0000000000001234**  RBX  0x0000000000000000  RCX  0x0000000000000000 │
│ RDX  0x0000000000000000      RSI  0x0000000000000000  RDI  0x0000000000000000 │
│ **RSP  0x00007fff00080000**  RBP  0x0000000000000000  **RIP  0x0000000000400007** │
└─────────────────────────────────────────────────┘

┌──────────── Stack ─────────────┐
│ 0x7fff00080000:  0x0000000000000000  <-- SP │
│ 0x7fff00080008:  0x0000000000000000          │
└─────────────────────────────────┘

┌────────────────── Code ───────────────────┐
│ 0x00400000:  48 c7 c0 34 12 00 00  mov rax, 0x1234      │
│ **0x00400007:  48 c7 c3 11 11 00 00  mov rbx, 0x1111  <--** │  ← Current instruction
│ 0x0040000e:  48 c7 c1 22 22 00 00  mov rcx, 0x2222      │
└─────────────────────────────────────────────┘
```
*Changed values highlighted in **bold**, current instruction marked with `<--`*

## Installation

### Requirements
- Python 3.7+
- Terminal with color support (recommended: 45+ lines for full display)

### Quick Setup
```bash
# Clone repository
git clone <repository-url>
cd opasm

# Install dependencies
pip install -r requirements.txt

# Test installation
python test_install.py

# Start the REPL
python opasm.py
```

### Dependencies
```
unicorn>=2.0.0          # CPU emulator framework
capstone>=4.0.0         # Disassembly framework  
keystone-engine>=0.9.2  # Assembly framework
rich>=13.0.0            # Rich text and beautiful formatting
prompt-toolkit>=3.0.0   # Interactive command line interface
```

## Quick Start Guide

### Try the Demo Files
```bash
# Start REPL
python opasm.py

# Load demo assembly file
asm-repl:x64> load_asm demo.asm
Loading assembly file: demo.asm
Loaded 25 instructions (75 bytes) at 0x400000

# Step through with visual feedback
asm-repl:x64> step    # RAX becomes bold (changed)
asm-repl:x64> step    # RBX becomes bold  
asm-repl:x64> run 5   # Execute 5 instructions

# Load binary for analysis
asm-repl:x64> reset
asm-repl:x64> load_bin demo.bin
Loaded 45 bytes at 0x400000
# Shows automatic disassembly preview
```

### Interactive Assembly
```bash
# Direct assembly mode (no "asm" prefix needed!)
asm-repl:x64> mov rax, 0x1234
asm-repl:x64> add rax, 0x5678  
asm-repl:x64> push rax
asm-repl:x64> pop rbx

# Use register dereferencing
asm-repl:x64> memory $rip      # Show memory at instruction pointer
asm-repl:x64> bp $rax          # Set breakpoint at RAX value
asm-repl:x64> set_mem $rsp 0xdeadbeef
```

## Complete Command Reference

### **Architecture & Setup**
```bash
arch                    # Show current architecture
arch x64                # Switch to x64/x86/arm/arm64
reset                   # Reset CPU state and clear memory
toggle_display          # Enable/disable automatic display
```

### **Assembly & Execution**
```bash
mov rax, 0x1234         # Direct assembly (no prefix needed!)
step                    # Execute next instruction with visual feedback
run [count]             # Run multiple instructions (default: 10)
```

### **State Inspection**
```bash
registers               # Show all registers (full view)
memory <addr> <size>    # Show memory contents with hex dump
disasm <addr> [count]   # Disassemble instructions at address
regions                 # Show memory layout
```

### **Register Dereferencing**
```bash
memory $rip             # Show memory at instruction pointer
memory $rsp 64          # Show 64 bytes at stack pointer
bp $rax                 # Set breakpoint at RAX value
set_mem $rsp 0x1234     # Set memory at stack pointer
```

### **Code Loading**
```bash
load_asm <file> [addr]  # Load and assemble assembly file
load_bin <file> [addr]  # Load binary file into memory
```

### **Debugging**
```bash
bp <addr>               # Set breakpoint (supports register dereferencing)
clear_bp <addr>         # Clear breakpoint
list_bp                 # List all breakpoints
set_reg <reg> <value>   # Set register value
set_mem <addr> <value>  # Set memory value
```

### **File Operations**
```bash
save <file>             # Save complete state to JSON
load <file>             # Load state from JSON file
dump_asm <file>         # Export assembly history
dump_mem <file> <addr> <size>  # Export memory region
```

## Architecture Support

### **x86 (32-bit)**
- **Registers**: EAX, EBX, ECX, EDX, ESI, EDI, ESP, EBP, EIP, EFLAGS
- **Sub-registers**: AX, BX, CX, DX, AL, BL, CL, DL, AH, BH, CH, DH
- **Instructions**: Full x86 instruction set via Keystone

### **x64 (64-bit)**  
- **Registers**: RAX, RBX, RCX, RDX, RSI, RDI, RSP, RBP, RIP, RFLAGS
- **Extended**: R8-R15 + 32-bit views (EAX, EBX, etc.)
- **Instructions**: Full x86-64 instruction set

### **ARM (32-bit)**
- **Registers**: R0-R12, SP, LR, PC, CPSR
- **Instructions**: ARM instruction set with condition codes

### **ARM64 (64-bit)**
- **Registers**: X0-X30, SP, PC, NZCV  
- **Instructions**: AArch64 instruction set

## Responsive Interface

The REPL automatically adapts to your terminal size:

- **45+ lines**: Shows registers + stack + code disassembly (full experience)
- **35+ lines**: Shows registers + stack 
- **25+ lines**: Shows registers only
- **<25 lines**: Clean minimal interface (all features available via commands)

## Use Cases

### **Assembly Learning**
- Write assembly programs in files, load and execute with immediate feedback
- See exactly what each instruction does with state change highlighting
- Compare behavior across different CPU architectures

### **Reverse Engineering**
- Load unknown binaries and analyze step-by-step
- Machine code bytes help understand packing/obfuscation
- Set breakpoints and examine state changes

### **Development & Testing**
- Rapid prototyping of assembly routines
- Test instruction sequences with visual feedback
- Debug with professional-grade tools

### **Education & Research**
- Perfect for teaching assembly language concepts
- Visual connection between assembly and machine code
- Cross-architecture comparison capabilities

## Demo Workflow

```bash
# 1. Start with demo assembly file
python opasm.py
asm-repl:x64> load_asm demo.asm

# 2. Step through with visual feedback  
asm-repl:x64> step    # Watch registers change in bold
asm-repl:x64> step    # See stack operations
asm-repl:x64> step    # Monitor instruction pointer

# 3. Set breakpoints and run
asm-repl:x64> bp 0x400020
asm-repl:x64> run 10  # Runs until breakpoint

# 4. Analyze with register dereferencing
asm-repl:x64> memory $rip 32    # Code at current location
asm-repl:x64> memory $rsp 64    # Current stack contents

# 5. Load binary for reverse engineering
asm-repl:x64> load_bin demo.bin
asm-repl:x64> step              # Analyze unknown code

# 6. Save your session
asm-repl:x64> save my_analysis.json
```

## Advanced Features

### **Smart Autocompletion**
- Type `arch ` + Tab → Shows only architecture options
- Type `set_reg ` + Tab → Shows current architecture registers  
- Context-aware suggestions throughout

### **Professional Display**
- Rich tables with proper formatting
- Machine code bytes in disassembly
- ASCII representation in memory dumps
- Consistent color coding

### **State Management**
- Complete CPU state persistence
- Assembly history tracking
- Memory region snapshots
- Breakpoint preservation

## Contributing

Enhancement opportunities:
- Additional architectures (MIPS, RISC-V, PowerPC)
- Scripting and automation support
- Network analysis capabilities
- Integration with external debuggers
- Enhanced file format support

## License

This project is provided for educational and research purposes. See the individual component licenses for Unicorn, Capstone, and Keystone engines.

Otherwise GPL v2