#!/usr/bin/env python3
"""
Opasm Assembly REPL using Capstone and Unicorn engines
Supports multiple architectures, register manipulation, state management, and more.
"""

import sys
import json
import platform
from typing import Dict, List
from dataclasses import dataclass, asdict
from pathlib import Path

try:
    from unicorn import *
    from unicorn.x86_const import *
    from unicorn.arm_const import *
    from unicorn.arm64_const import *
    from unicorn.mips_const import *
    import capstone
    from capstone import *
    import keystone
    from keystone import *
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.columns import Columns
    from rich.syntax import Syntax
    from rich import box
    from prompt_toolkit import prompt
    from prompt_toolkit.completion import WordCompleter
    from prompt_toolkit.history import InMemoryHistory
    from prompt_toolkit.shortcuts import confirm
except ImportError as e:
    print(f"Missing required dependency: {e}")
    print("Please install requirements: pip install -r requirements.txt")
    sys.exit(1)

# Initialize rich console
console = Console()

@dataclass
class ArchConfig:
    """Configuration for different architectures"""
    name: str
    uc_arch: int
    uc_mode: int
    cs_arch: int
    cs_mode: int
    ks_arch: int
    ks_mode: int
    registers: Dict[str, int]
    instruction_pointer_register: int
    stack_pointer_register: int
    stack_base: int
    code_base: int
    data_base: int
    word_size: int

class AssemblyREPL:
    """Main Assembly REPL class"""
    
    # Architecture configurations
    ARCHITECTURES = {
        'x86': ArchConfig(
            name='x86',
            uc_arch=UC_ARCH_X86,
            uc_mode=UC_MODE_32,
            cs_arch=CS_ARCH_X86,
            cs_mode=CS_MODE_32,
            ks_arch=KS_ARCH_X86,
            ks_mode=KS_MODE_32,
            registers={
                'eax': UC_X86_REG_EAX, 'ebx': UC_X86_REG_EBX, 'ecx': UC_X86_REG_ECX, 'edx': UC_X86_REG_EDX,
                'esi': UC_X86_REG_ESI, 'edi': UC_X86_REG_EDI, 'esp': UC_X86_REG_ESP, 'ebp': UC_X86_REG_EBP,
                'eip': UC_X86_REG_EIP, 'eflags': UC_X86_REG_EFLAGS,
                'ax': UC_X86_REG_AX, 'bx': UC_X86_REG_BX, 'cx': UC_X86_REG_CX, 'dx': UC_X86_REG_DX,
                'al': UC_X86_REG_AL, 'bl': UC_X86_REG_BL, 'cl': UC_X86_REG_CL, 'dl': UC_X86_REG_DL,
                'ah': UC_X86_REG_AH, 'bh': UC_X86_REG_BH, 'ch': UC_X86_REG_CH, 'dh': UC_X86_REG_DH,
            },
            instruction_pointer_register=UC_X86_REG_EIP,
            stack_pointer_register=UC_X86_REG_ESP,
            stack_base=0x7fff0000,
            code_base=0x400000,
            data_base=0x10000000,
            word_size=4
        ),
        'x64': ArchConfig(
            name='x64',
            uc_arch=UC_ARCH_X86,
            uc_mode=UC_MODE_64,
            cs_arch=CS_ARCH_X86,
            cs_mode=CS_MODE_64,
            ks_arch=KS_ARCH_X86,
            ks_mode=KS_MODE_64,
            registers={
                'rax': UC_X86_REG_RAX, 'rbx': UC_X86_REG_RBX, 'rcx': UC_X86_REG_RCX, 'rdx': UC_X86_REG_RDX,
                'rsi': UC_X86_REG_RSI, 'rdi': UC_X86_REG_RDI, 'rsp': UC_X86_REG_RSP, 'rbp': UC_X86_REG_RBP,
                'rip': UC_X86_REG_RIP, 'rflags': UC_X86_REG_EFLAGS,
                'r8': UC_X86_REG_R8, 'r9': UC_X86_REG_R9, 'r10': UC_X86_REG_R10, 'r11': UC_X86_REG_R11,
                'r12': UC_X86_REG_R12, 'r13': UC_X86_REG_R13, 'r14': UC_X86_REG_R14, 'r15': UC_X86_REG_R15,
                'eax': UC_X86_REG_EAX, 'ebx': UC_X86_REG_EBX, 'ecx': UC_X86_REG_ECX, 'edx': UC_X86_REG_EDX,
            },
            instruction_pointer_register=UC_X86_REG_RIP,
            stack_pointer_register=UC_X86_REG_RSP,
            stack_base=0x7fff00000000,
            code_base=0x400000,
            data_base=0x10000000,
            word_size=8
        ),
        'arm': ArchConfig(
            name='arm',
            uc_arch=UC_ARCH_ARM,
            uc_mode=UC_MODE_ARM,
            cs_arch=CS_ARCH_ARM,
            cs_mode=CS_MODE_ARM,
            ks_arch=KS_ARCH_ARM,
            ks_mode=KS_MODE_ARM,
            registers={
                'r0': UC_ARM_REG_R0, 'r1': UC_ARM_REG_R1, 'r2': UC_ARM_REG_R2, 'r3': UC_ARM_REG_R3,
                'r4': UC_ARM_REG_R4, 'r5': UC_ARM_REG_R5, 'r6': UC_ARM_REG_R6, 'r7': UC_ARM_REG_R7,
                'r8': UC_ARM_REG_R8, 'r9': UC_ARM_REG_R9, 'r10': UC_ARM_REG_R10, 'r11': UC_ARM_REG_R11,
                'r12': UC_ARM_REG_R12, 'sp': UC_ARM_REG_SP, 'lr': UC_ARM_REG_LR, 'pc': UC_ARM_REG_PC,
                'cpsr': UC_ARM_REG_CPSR,
            },
            instruction_pointer_register=UC_ARM_REG_PC,
            stack_pointer_register=UC_ARM_REG_SP,
            stack_base=0x7fff0000,
            code_base=0x10000,
            data_base=0x20000000,
            word_size=4
        ),
        'arm64': ArchConfig(
            name='arm64',
            uc_arch=UC_ARCH_ARM64,
            uc_mode=UC_MODE_ARM,
            cs_arch=CS_ARCH_ARM64,
            cs_mode=CS_MODE_ARM,
            ks_arch=KS_ARCH_ARM64,
            ks_mode=KS_MODE_LITTLE_ENDIAN,
            registers={
                'x0': UC_ARM64_REG_X0, 'x1': UC_ARM64_REG_X1, 'x2': UC_ARM64_REG_X2, 'x3': UC_ARM64_REG_X3,
                'x4': UC_ARM64_REG_X4, 'x5': UC_ARM64_REG_X5, 'x6': UC_ARM64_REG_X6, 'x7': UC_ARM64_REG_X7,
                'x8': UC_ARM64_REG_X8, 'x9': UC_ARM64_REG_X9, 'x10': UC_ARM64_REG_X10, 'x11': UC_ARM64_REG_X11,
                'x12': UC_ARM64_REG_X12, 'x13': UC_ARM64_REG_X13, 'x14': UC_ARM64_REG_X14, 'x15': UC_ARM64_REG_X15,
                'x16': UC_ARM64_REG_X16, 'x17': UC_ARM64_REG_X17, 'x18': UC_ARM64_REG_X18, 'x19': UC_ARM64_REG_X19,
                'x20': UC_ARM64_REG_X20, 'x21': UC_ARM64_REG_X21, 'x22': UC_ARM64_REG_X22, 'x23': UC_ARM64_REG_X23,
                'x24': UC_ARM64_REG_X24, 'x25': UC_ARM64_REG_X25, 'x26': UC_ARM64_REG_X26, 'x27': UC_ARM64_REG_X27,
                'x28': UC_ARM64_REG_X28, 'x29': UC_ARM64_REG_X29, 'x30': UC_ARM64_REG_X30, 'sp': UC_ARM64_REG_SP,
                'pc': UC_ARM64_REG_PC, 'nzcv': UC_ARM64_REG_NZCV,
            },
            instruction_pointer_register=UC_ARM64_REG_PC,
            stack_pointer_register=UC_ARM64_REG_SP,
            stack_base=0x7fff00000000,
            code_base=0x400000,
            data_base=0x10000000,
            word_size=8
        ),
    }

    def __init__(self):
        self.current_arch = self._detect_system_arch()
        self.arch_config = self.ARCHITECTURES[self.current_arch]
        self.uc = None
        self.cs = None
        self.code_history = []
        self.memory_regions = {}
        self.breakpoints = set()
        self.history = InMemoryHistory()
        self.auto_display = True  # Enable automatic register/stack display
        self.previous_state = {}  # Track previous register/memory state
        self.direct_execution = False
        self.init_engine()
        
        # Command completions
        self.commands = [
            'help', 'arch', 'registers', 'reg', 'memory', 'mem', 'regions', 'assemble', 'asm',
            'disasm', 'step', 'run', 'reset', 'save', 'load', 'load_asm', 'load_bin', 
            'dump_asm', 'dump_mem', 'set_reg', 'set_mem', 'breakpoint', 'bp', 'clear_bp', 
            'list_bp', 'quit', 'exit', 'toggle_display', 'toggle_direct'
        ]
        self._update_completer()

    def _update_completer(self):
        """Update the completer with commands, registers, and assembly instructions"""
        # Create a custom completer that provides context-aware suggestions
        self.completer = self._create_context_completer()

    def _create_context_completer(self):
        """Create a context-aware completer"""
        from prompt_toolkit.completion import Completer, Completion
        
        class ContextAwareCompleter(Completer):
            def __init__(self, repl_instance):
                self.repl = repl_instance
                
            def get_completions(self, document, complete_event):
                # Get the current line and split into words
                text = document.text_before_cursor
                words = text.split()
                
                if not words:
                    # No words yet, show all commands
                    for cmd in self.repl.commands:
                        yield Completion(cmd, start_position=0)
                    return
                
                current_word = words[-1] if not text.endswith(' ') else ''
                
                # Context-aware completion based on the first word (command)
                if len(words) == 1 and not text.endswith(' '):
                    # Still typing the first word - show matching commands
                    for cmd in self.repl.commands:
                        if cmd.startswith(current_word.lower()):
                            yield Completion(cmd, start_position=-len(current_word))
                            
                elif len(words) >= 1:
                    command = words[0].lower()
                    
                    if command == 'arch' and (len(words) == 1 or (len(words) == 2 and not text.endswith(' '))):
                        # After 'arch' command, show architecture options
                        arch_options = list(self.repl.ARCHITECTURES.keys())
                        for arch in arch_options:
                            if arch.startswith(current_word.lower()):
                                yield Completion(arch, start_position=-len(current_word))
                    
                    elif command in ['set_reg', 'bp', 'memory', 'mem'] and len(words) == 2 and not text.endswith(' '):
                        # After register-related commands, show registers
                        for reg in self.repl.arch_config.registers.keys():
                            if reg.startswith(current_word.lower()):
                                yield Completion(reg, start_position=-len(current_word))
                    
                    elif command in ['load_asm', 'load_bin', 'save', 'load', 'dump_asm', 'dump_mem'] and len(words) == 2 and not text.endswith(' '):
                        # After file commands, we could show file completions
                        # For now, just don't show anything specific
                        pass
                    
                    else:
                        # For assembly instructions or unknown contexts, show assembly instructions and registers
                        assembly_instructions = self.repl._get_assembly_instructions()
                        all_suggestions = assembly_instructions + list(self.repl.arch_config.registers.keys())
                        
                        for suggestion in all_suggestions:
                            if suggestion.startswith(current_word.lower()):
                                yield Completion(suggestion, start_position=-len(current_word))
        
        return ContextAwareCompleter(self)
    
    def _get_assembly_instructions(self) -> List[str]:
        """Get common assembly instructions for the current architecture"""
        if self.current_arch in ['x86', 'x64']:
            return [
                # Data movement
                'mov', 'movsx', 'movzx', 'lea', 'xchg',
                # Arithmetic
                'add', 'sub', 'mul', 'imul', 'div', 'idiv', 'inc', 'dec', 'neg',
                # Logical
                'and', 'or', 'xor', 'not', 'shl', 'shr', 'sal', 'sar', 'rol', 'ror',
                # Comparison
                'cmp', 'test',
                # Control flow
                'jmp', 'je', 'jne', 'jz', 'jnz', 'jg', 'jge', 'jl', 'jle', 'ja', 'jae', 'jb', 'jbe',
                'call', 'ret', 'int', 'iret',
                # Stack operations
                'push', 'pop', 'pushf', 'popf',
                # String operations
                'movs', 'stos', 'lods', 'scas', 'cmps',
                # Other
                'nop', 'hlt', 'cld', 'std', 'cli', 'sti',
            ]
        elif self.current_arch == 'arm':
            return [
                # Data movement
                'mov', 'mvn', 'ldr', 'str', 'ldm', 'stm',
                # Arithmetic
                'add', 'sub', 'mul', 'mla', 'rsb', 'adc', 'sbc', 'rsc',
                # Logical
                'and', 'orr', 'eor', 'bic', 'lsl', 'lsr', 'asr', 'ror', 'rrx',
                # Comparison
                'cmp', 'cmn', 'tst', 'teq',
                # Control flow
                'b', 'bl', 'bx', 'blx', 'beq', 'bne', 'bcs', 'bcc', 'bmi', 'bpl',
                'bvs', 'bvc', 'bhi', 'bls', 'bge', 'blt', 'bgt', 'ble',
                # Other
                'nop', 'swi', 'mrs', 'msr',
            ]
        elif self.current_arch == 'arm64':
            return [
                # Data movement
                'mov', 'mvn', 'ldr', 'str', 'ldp', 'stp',
                # Arithmetic
                'add', 'sub', 'mul', 'madd', 'msub', 'adc', 'sbc', 'neg',
                # Logical
                'and', 'orr', 'eor', 'bic', 'lsl', 'lsr', 'asr', 'ror',
                # Comparison
                'cmp', 'cmn', 'tst',
                # Control flow
                'b', 'bl', 'br', 'blr', 'ret', 'b.eq', 'b.ne', 'b.cs', 'b.cc',
                'b.mi', 'b.pl', 'b.vs', 'b.vc', 'b.hi', 'b.ls', 'b.ge', 'b.lt',
                'b.gt', 'b.le',
                # Other
                'nop', 'svc', 'mrs', 'msr',
            ]
        else:
            return []

    def _detect_system_arch(self) -> str:
        """Detect the system architecture"""
        machine = platform.machine().lower()
        if machine in ['x86_64', 'amd64']:
            return 'x64'
        elif machine in ['i386', 'i686']:
            return 'x86'
        elif machine.startswith('arm') and '64' in machine:
            return 'arm64'
        elif machine.startswith('arm'):
            return 'arm'
        else:
            return 'x64'  # Default fallback

    def init_engine(self):
        """Initialize Unicorn and Capstone engines"""
        try:
            # Initialize Unicorn engine
            self.uc = Uc(self.arch_config.uc_arch, self.arch_config.uc_mode)
            
            # Initialize Capstone engine
            self.cs = Cs(self.arch_config.cs_arch, self.arch_config.cs_mode)
            
            # Map memory regions
            self._map_memory_regions()
            
            # Initialize stack and instruction pointers
            self._init_registers()
            
            console.print(f"[green]Initialized {self.arch_config.name} architecture[/green]")
            
        except Exception as e:
            console.print(f"[red]Error initializing engines: {e}[/red]")
            sys.exit(1)

    def _map_memory_regions(self):
        """Map memory regions for code, stack, and data"""
        regions = [
            ('code', self.arch_config.code_base, 0x100000),  # 1MB for code
            ('stack', self.arch_config.stack_base, 0x100000),  # 1MB for stack
            ('data', self.arch_config.data_base, 0x100000),   # 1MB for data
        ]
        
        for name, base, size in regions:
            try:
                self.uc.mem_map(base, size)
                self.memory_regions[name] = (base, size)
            except Exception as e:
                console.print(f"[red]Error mapping {name} memory: {e}[/red]")

    def _init_registers(self):
        """Initialize registers with default values"""
        try:
            # Set stack pointer
            self.uc.reg_write(self.arch_config.stack_pointer_register, self.arch_config.stack_base + 0x80000)
            
            # Set instruction pointer
            self.uc.reg_write(self.arch_config.instruction_pointer_register, self.arch_config.code_base)
                
        except Exception as e:
            console.print(f"[red]Error initializing registers: {e}[/red]")

    def print_banner(self):
        """Print welcome banner using rich"""
        banner_panel = Panel.fit(
            "[bold cyan]Opasm Assembly REPL v1.0[/bold cyan]\n"
            "[dim]Powered by Capstone & Unicorn[/dim]",
            border_style="cyan",
            padding=(1, 2)
        )
        console.print(banner_panel)
        console.print(f"\n[yellow]Current Architecture: {self.arch_config.name.upper()}[/yellow]")
        console.print("[dim]Type assembly instructions directly or 'help' for commands, 'quit' to exit[/dim]")

    def print_help(self):
        """Print help information using rich"""
        help_panel = Panel(
            """[bold cyan]Available Commands:[/bold cyan]

[bold green]Architecture & Setup:[/bold green]
  arch <name>            - Show current arch or switch to: x86, x64, arm, arm64
  reset                  - Reset CPU state and clear memory

[bold green]Assembly & Execution:[/bold green]
  asm <instruction>      - Assemble and execute instruction
  step                   - Execute next instruction
  run <count>            - Run multiple instructions (default: 10)
  toggle_direct          - Toggle direct execution mode (bypass memory loading)

[bold green]State Inspection:[/bold green]
  registers, reg         - Show all registers
  memory <addr> <size>   - Show memory contents (hex format)
  disasm <addr> <count>  - Disassemble instructions at address

[bold green]State Modification:[/bold green]
  set_reg <reg> <val>    - Set register value (hex or decimal)
  set_mem <addr> <val>   - Set memory value

[bold green]Debugging:[/bold green]
  bp <addr>              - Set breakpoint at address
  clear_bp <addr>        - Clear breakpoint
  list_bp                - List all breakpoints

[bold green]File Operations:[/bold green]
  save <file>            - Save current state to file
  load <file>            - Load state from file
  load_asm <file> <addr> - Load and assemble assembly file into memory
  load_bin <file> <addr> - Load binary file into memory
  dump_asm <file>        - Dump assembly history to file
  dump_mem <file> <addr> <size> - Dump memory region to file

[bold green]Display & Settings:[/bold green]
  toggle_display         - Toggle automatic register/stack display
  toggle_direct          - Toggle direct execution mode

[bold green]General:[/bold green]
  help                   - Show this help
  quit, exit             - Exit the REPL

[bold yellow]Execution Modes:[/bold yellow]
  Normal Mode (default): Instructions are loaded into memory before execution
  Direct Mode: Instructions execute without loading into memory first
  Use 'toggle_direct' to switch between modes

[bold yellow]Register Dereferencing:[/bold yellow]
  Use $ to reference register values:
  memory $rip            - Show memory at RIP address
  set_mem $rsp 0x1234    - Set memory at RSP address
  bp $rax                - Set breakpoint at RAX value

[bold yellow]Examples:[/bold yellow]
  mov eax, 0x1234
  set_reg eax 0x5678
  memory 0x400000 64
  memory $rip            - Show memory at current instruction pointer
  bp $rax                - Set breakpoint at RAX value
  toggle_direct          - Switch to direct execution mode""",
            title="Help",
            border_style="blue",
            padding=(1, 2)
        )
        console.print(help_panel)

    def show_registers(self, compact: bool = False, highlight_changes: set = None):
        """Display current register values using rich table"""
        if highlight_changes is None:
            highlight_changes = set()
            
        if compact:
            # Compact display for auto-display mode
            table = Table(title=f"Registers ({self.arch_config.name.upper()})", box=box.ROUNDED, show_header=False, padding=0)
            table.add_column("", style="cyan", min_width=8)
            table.add_column("", style="yellow", min_width=12)
            table.add_column("", style="cyan", min_width=8)
            table.add_column("", style="yellow", min_width=12)
            table.add_column("", style="cyan", min_width=8)
            table.add_column("", style="yellow", min_width=12)
            
            reg_data = []
            for reg_name, reg_id in self.arch_config.registers.items():
                try:
                    value = self.uc.reg_read(reg_id)
                    hex_val = f"0x{value:0{self.arch_config.word_size*2}x}"
                    
                    # Apply bold formatting if register changed
                    if reg_name in highlight_changes:
                        reg_name_display = f"[bold]{reg_name.upper()}[/bold]"
                        hex_val_display = f"[bold]{hex_val}[/bold]"
                    else:
                        reg_name_display = reg_name.upper()
                        hex_val_display = hex_val
                    
                    reg_data.append([reg_name_display, hex_val_display])
                except:
                    reg_data.append([reg_name.upper(), "N/A"])
            
            # Split into 3 columns for compact display
            third = len(reg_data) // 3
            col1 = reg_data[:third]
            col2 = reg_data[third:third*2]
            col3 = reg_data[third*2:]
            
            for i in range(max(len(col1), len(col2), len(col3))):
                c1 = col1[i] if i < len(col1) else ["", ""]
                c2 = col2[i] if i < len(col2) else ["", ""]
                c3 = col3[i] if i < len(col3) else ["", ""]
                table.add_row(c1[0], c1[1], c2[0], c2[1], c3[0], c3[1])
        else:
            # Full display for manual register command
            table = Table(title=f"Registers ({self.arch_config.name.upper()})", box=box.ROUNDED)
            table.add_column("Register", style="cyan", min_width=10)
            table.add_column("Hex Value", style="yellow", min_width=18)
            table.add_column("Decimal", style="green", min_width=15)
            table.add_column("Register", style="cyan", min_width=10)
            table.add_column("Hex Value", style="yellow", min_width=18)
            table.add_column("Decimal", style="green", min_width=15)
            
            reg_data = []
            for reg_name, reg_id in self.arch_config.registers.items():
                try:
                    value = self.uc.reg_read(reg_id)
                    hex_val = f"0x{value:0{self.arch_config.word_size*2}x}"
                    
                    # Apply bold formatting if register changed
                    if reg_name in highlight_changes:
                        reg_name_display = f"[bold]{reg_name.upper()}[/bold]"
                        hex_val_display = f"[bold]{hex_val}[/bold]"
                        decimal_display = f"[bold]{str(value)}[/bold]"
                    else:
                        reg_name_display = reg_name.upper()
                        hex_val_display = hex_val
                        decimal_display = str(value)
                    
                    reg_data.append([reg_name_display, hex_val_display, decimal_display])
                except:
                    reg_data.append([reg_name.upper(), "N/A", "N/A"])
            
            # Split into columns for better display
            mid = len(reg_data) // 2
            left_col = reg_data[:mid]
            right_col = reg_data[mid:]
            
            for i in range(max(len(left_col), len(right_col))):
                left = left_col[i] if i < len(left_col) else ["", "", ""]
                right = right_col[i] if i < len(right_col) else ["", "", ""]
                table.add_row(left[0], left[1], left[2], right[0], right[1], right[2])
        
        console.print(table)

    def show_stack(self, compact: bool = False, highlight_changes: set = None):
        """Display stack contents"""
        if highlight_changes is None:
            highlight_changes = set()
            
        try:
            # Get stack pointer
            sp_reg = self.arch_config.stack_pointer_register
            
            if not sp_reg:
                console.print("[red]No stack pointer register found[/red]")
                return
            
            sp_value = self.uc.reg_read(sp_reg)
            
            # Read stack data (64 bytes from stack pointer)
            stack_size = 32 if compact else 64
            data = self.uc.mem_read(sp_value, stack_size)
            
            if compact:
                table = Table(title="Stack", box=box.ROUNDED, show_header=False, padding=0)
                table.add_column("", style="yellow", min_width=12)
                table.add_column("", style="white", min_width=24)
                table.add_column("", style="green", min_width=8)
                
                for i in range(0, len(data), self.arch_config.word_size):
                    addr = sp_value + i
                    chunk = data[i:i+self.arch_config.word_size]
                    if len(chunk) >= self.arch_config.word_size:
                        value = int.from_bytes(chunk, 'little')
                        hex_val = f"0x{value:0{self.arch_config.word_size*2}x}"
                        
                        # Apply bold formatting if stack value changed
                        if addr in highlight_changes:
                            hex_val_display = f"[bold]{hex_val}[/bold]"
                            addr_display = f"[bold]0x{addr:08x}:[/bold]"
                        else:
                            hex_val_display = hex_val
                            addr_display = f"0x{addr:08x}:"
                        
                        marker = "<-- SP" if i == 0 else ""
                        table.add_row(addr_display, hex_val_display, marker)
            else:
                table = Table(title="Stack", box=box.ROUNDED)
                table.add_column("Address", style="yellow", min_width=12)
                table.add_column("Value", style="white", min_width=18)
                table.add_column("ASCII", style="green", min_width=8)
                table.add_column("", style="cyan", min_width=8)
                
                for i in range(0, len(data), self.arch_config.word_size):
                    addr = sp_value + i
                    chunk = data[i:i+self.arch_config.word_size]
                    if len(chunk) >= self.arch_config.word_size:
                        value = int.from_bytes(chunk, 'little')
                        hex_val = f"0x{value:0{self.arch_config.word_size*2}x}"
                        ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                        
                        # Apply bold formatting if stack value changed
                        if addr in highlight_changes:
                            addr_display = f"[bold]0x{addr:08x}[/bold]"
                            hex_val_display = f"[bold]{hex_val}[/bold]"
                            ascii_display = f"[bold]{ascii_str}[/bold]"
                        else:
                            addr_display = f"0x{addr:08x}"
                            hex_val_display = hex_val
                            ascii_display = ascii_str
                        
                        marker = "<-- SP" if i == 0 else ""
                        table.add_row(addr_display, hex_val_display, ascii_display, marker)
            
            console.print(table)
                
        except Exception as e:
            if compact:
                console.print(f"[red]Stack unavailable[/red]")
            else:
                console.print(f"[red]Error reading stack: {e}[/red]")

    def _check_screen_size(self) -> tuple[int, int]:
        """Check terminal size and determine what can be displayed"""
        try:
            size = console.size
            width, height = size.width, size.height
            return width, height
        except:
            return 80, 24  # Default fallback

    def _should_show_auto_display(self) -> tuple[bool, bool, bool]:
        """Determine if we should show registers, stack, and/or code based on screen size"""
        if not self.auto_display:
            return False, False, False
        
        width, height = self._check_screen_size()
        
        # Need at least 25 lines for compact registers
        show_registers = height >= 25
        
        # Need at least 35 lines for registers and stack
        show_stack = height >= 35
        
        # Need at least 45 lines for registers, stack, and code
        show_code = height >= 45
        
        return show_registers, show_stack, show_code

    def _capture_state(self):
        """Capture current register and memory state for change tracking"""
        state = {
            'registers': {},
            'stack': {}
        }
        
        # Capture register values
        for reg_name, reg_id in self.arch_config.registers.items():
            try:
                state['registers'][reg_name] = self.uc.reg_read(reg_id)
            except:
                state['registers'][reg_name] = None
        
        # Capture stack values
        try:
            sp_reg = self.arch_config.stack_pointer_register
            if sp_reg:
                sp_value = self.uc.reg_read(sp_reg)
                # Capture first 8 stack entries
                for i in range(8):
                    addr = sp_value + (i * self.arch_config.word_size)
                    try:
                        data = self.uc.mem_read(addr, self.arch_config.word_size)
                        value = int.from_bytes(data, 'little')
                        state['stack'][addr] = value
                    except:
                        state['stack'][addr] = None
        except:
            pass
        
        return state
    
    def _get_state_changes(self, previous_state):
        """Compare current state with previous state and return changes"""
        current_state = self._capture_state()
        changes = {
            'registers': set(),
            'stack': set()
        }
        
        # Check register changes
        for reg_name in current_state['registers']:
            prev_val = previous_state.get('registers', {}).get(reg_name)
            curr_val = current_state['registers'][reg_name]
            if prev_val is not None and curr_val is not None and prev_val != curr_val:
                changes['registers'].add(reg_name)
        
        # Check stack changes
        for addr in current_state['stack']:
            prev_val = previous_state.get('stack', {}).get(addr)
            curr_val = current_state['stack'][addr]
            if prev_val is not None and curr_val is not None and prev_val != curr_val:
                changes['stack'].add(addr)
        
        return changes

    def show_code(self, compact: bool = False):
        """Display code disassembly around current instruction pointer"""
        try:
            # Get current instruction pointer
            ip_reg = self.arch_config.instruction_pointer_register
            current_ip = self.uc.reg_read(ip_reg)
            
            # Try to find previous instructions by scanning backwards
            # This is approximate since instruction lengths vary
            scan_back = 64  # Scan back this many bytes to find previous instructions
            start_addr = max(current_ip - scan_back, self.arch_config.code_base)
            
            # Read memory for disassembly
            try:
                data = self.uc.mem_read(start_addr, scan_back + 64)
                instructions = list(self.cs.disasm(data, start_addr))
            except:
                # If we can't read that far back, just read forward from current IP
                data = self.uc.mem_read(current_ip, 64)
                instructions = list(self.cs.disasm(data, current_ip))
            
            # Find the current instruction and get context
            current_idx = None
            for i, insn in enumerate(instructions):
                if insn.address == current_ip:
                    current_idx = i
                    break
            
            if current_idx is None:
                # If we can't find current instruction, just show from current IP
                data = self.uc.mem_read(current_ip, 64)
                instructions = list(self.cs.disasm(data, current_ip, 6))
                current_idx = 0
            
            # Get context: 3 instructions before, current, and 2 after
            start_idx = max(0, current_idx - 3)
            end_idx = min(len(instructions), current_idx + 3)
            context_instructions = instructions[start_idx:end_idx]
            
            if compact:
                table = Table(title="Code", box=box.ROUNDED, show_header=False, padding=0)
                table.add_column("", style="yellow", min_width=12)
                table.add_column("", style="cyan", min_width=16)
                table.add_column("", style="white", min_width=20)
                table.add_column("", style="green", min_width=3)
            else:
                table = Table(title="Code Disassembly", box=box.ROUNDED)
                table.add_column("Address", style="yellow", min_width=12)
                table.add_column("Bytes", style="cyan", min_width=16)
                table.add_column("Instruction", style="white", min_width=20)
                table.add_column("", style="green", min_width=5)
            
            for insn in context_instructions:
                addr_str = f"0x{insn.address:08x}:"
                bytes_str = ' '.join(f'{b:02x}' for b in insn.bytes)
                insn_str = f"{insn.mnemonic} {insn.op_str}"
                
                # Highlight current instruction
                if insn.address == current_ip:
                    if compact:
                        addr_display = f"[bold green]{addr_str}[/bold green]"
                        bytes_display = f"[bold green]{bytes_str}[/bold green]"
                        insn_display = f"[bold green]{insn_str}[/bold green]"
                        marker = "[bold green]<--[/bold green]"
                    else:
                        addr_display = f"[bold green]{addr_str}[/bold green]"
                        bytes_display = f"[bold green]{bytes_str}[/bold green]"
                        insn_display = f"[bold green]{insn_str}[/bold green]"
                        marker = "[bold green]<-- IP[/bold green]"
                else:
                    addr_display = addr_str
                    bytes_display = bytes_str
                    insn_display = insn_str
                    marker = ""
                
                table.add_row(addr_display, bytes_display, insn_display, marker)
            
            console.print(table)
                
        except Exception as e:
            if compact:
                console.print(f"[red]Code unavailable[/red]")
            else:
                console.print(f"[red]Error reading code: {e}[/red]")

    def _display_auto_panels(self):
        """Display automatic register, stack, and code panels if screen is large enough"""
        show_regs, show_stack, show_code = self._should_show_auto_display()
        
        # Get state changes
        changes = self._get_state_changes(self.previous_state) if self.previous_state else {'registers': set(), 'stack': set()}
        
        if show_regs:
            console.print()  # Add spacing
            self.show_registers(compact=True, highlight_changes=changes['registers'])
        
        if show_stack:
            console.print()  # Add spacing  
            self.show_stack(compact=True, highlight_changes=changes['stack'])
        
        if show_code:
            console.print()  # Add spacing
            self.show_code(compact=True)
        
        # Update previous state for next comparison
        self.previous_state = self._capture_state()

    def show_memory_regions(self):
        """Display mapped memory regions"""
        table = Table(title="Memory Regions", box=box.ROUNDED)
        table.add_column("Region", style="cyan", min_width=10)
        table.add_column("Start Address", style="yellow", min_width=15)
        table.add_column("End Address", style="yellow", min_width=15)
        table.add_column("Size", style="green", min_width=10)
        table.add_column("Purpose", style="white", min_width=20)
        
        for name, (base, size) in self.memory_regions.items():
            end_addr = base + size - 1
            size_str = f"{size // 1024}KB" if size >= 1024 else f"{size}B"
            
            if name == 'code':
                purpose = "Executable code region"
            elif name == 'stack':
                purpose = "Stack memory region"
            elif name == 'data':
                purpose = "Data storage region"
            else:
                purpose = "Memory region"
                
            table.add_row(
                name.upper(),
                f"0x{base:08x}",
                f"0x{end_addr:08x}",
                size_str,
                purpose
            )
        
        console.print(table)

    def show_memory(self, address: int, size: int = 64):
        """Display memory contents using rich"""
        try:
            data = self.uc.mem_read(address, size)
            
            console.print(f"\n[cyan]Memory at 0x{address:x} ({size} bytes):[/cyan]")
            
            # Create memory dump table
            table = Table(box=box.ROUNDED)
            table.add_column("Address", style="yellow", min_width=12)
            table.add_column("Hex", style="white", min_width=48)
            table.add_column("ASCII", style="green", min_width=16)
            
            for i in range(0, len(data), 16):
                addr = address + i
                chunk = data[i:i+16]
                hex_str = ' '.join(f'{b:02x}' for b in chunk)
                ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                table.add_row(f"0x{addr:08x}:", hex_str, f"|{ascii_str}|")
                
            console.print(table)
                
        except Exception as e:
            if "UC_ERR_READ_UNMAPPED" in str(e):
                console.print(f"[red]Address 0x{address:x} is not mapped in memory[/red]")
                console.print("[yellow]Use 'regions' to see mapped memory regions[/yellow]")
            else:
                console.print(f"[red]Error reading memory: {e}[/red]")

    def assemble_and_execute(self, instruction: str):
        """Assemble instruction and execute it"""
        try:
            machine_code = self._simple_assemble(instruction)
            if not machine_code:
                console.print("[red]Failed to assemble instruction[/red]")
                return
            
            if self.direct_execution:
                # Direct execution mode - execute without loading into memory
                self._execute_direct(instruction, machine_code)
            else:
                # Normal mode - load into memory first, then execute
                self._execute_from_memory(instruction, machine_code)
            
        except Exception as e:
            console.print(f"[red]Error executing instruction: {e}[/red]")

    def _execute_direct(self, instruction: str, machine_code: bytes):
        """Execute instruction directly without loading into memory first"""
        try:
            # Create a temporary memory region for direct execution
            temp_addr = 0x50000000  # Use a different address space for direct execution
            temp_size = 0x1000  # 4KB should be enough for single instructions
            
            # Map temporary memory if not already mapped
            try:
                self.uc.mem_map(temp_addr, temp_size)
            except:
                # Memory might already be mapped, that's okay
                pass
            
            # Write machine code to temporary memory
            self.uc.mem_write(temp_addr, machine_code)
            
            # Save current instruction pointer
            ip_reg = self.arch_config.instruction_pointer_register
            original_ip = self.uc.reg_read(ip_reg)
            
            # Execute from temporary location
            self.uc.emu_start(temp_addr, temp_addr + len(machine_code))
            
            # Restore instruction pointer (don't advance it in direct mode)
            self.uc.reg_write(ip_reg, original_ip)
            
            # Add to history with special marking for direct execution
            self.code_history.append({
                'instruction': instruction,
                'address': temp_addr,
                'machine_code': machine_code.hex(),
                'direct_execution': True
            })
            
            console.print(f"[green]Executed (direct): {instruction}[/green]")
            
        except Exception as e:
            console.print(f"[red]Error in direct execution: {e}[/red]")

    def _execute_from_memory(self, instruction: str, machine_code: bytes):
        """Execute instruction from memory (normal mode)"""
        try:
            # Get current instruction pointer
            ip_reg = self.arch_config.instruction_pointer_register
            current_ip = self.uc.reg_read(ip_reg)
            
            # Write machine code to memory
            self.uc.mem_write(current_ip, machine_code)
            
            # Execute the instruction
            self.uc.emu_start(current_ip, current_ip + len(machine_code))
            
            # Add to history
            self.code_history.append({
                'instruction': instruction,
                'address': current_ip,
                'machine_code': machine_code.hex(),
                'direct_execution': False
            })
            
            console.print(f"[green]Executed: {instruction}[/green]")
            
        except Exception as e:
            console.print(f"[red]Error in memory execution: {e}[/red]")

    def _simple_assemble(self, instruction: str) -> bytes:
        """Assemble instruction using keystone-engine"""
        try:
            # Try keystone-engine first for full assembly support
            ks = Ks(self.arch_config.ks_arch, self.arch_config.ks_mode)
            encoding, count = ks.asm(instruction)
            if encoding:
                return bytes(encoding)
        except Exception as e:
            console.print(f"[yellow]Keystone assembly failed: {e}[/yellow]")
            console.print("[yellow]Warning: Using NOP for unsupported instruction[/yellow]")
            encoding, count = ks.asm('nop')
            if encoding:
                return bytes(encoding)
        # all else fails
        console.print("[red]Warning: instruction didn't work and neither did NOP[/red]")
        return b'\x00\x00\x00\x00'

    def disassemble(self, address: int, count: int = 10):
        """Disassemble instructions at given address"""
        try:
            data = self.uc.mem_read(address, count * 16)  # Read enough bytes
            instructions = list(self.cs.disasm(data, address, count))
            
            console.print(f"\n[cyan]Disassembly at 0x{address:x}:[/cyan]")
            
            table = Table(box=box.ROUNDED)
            table.add_column("Address", style="yellow", min_width=12)
            table.add_column("Instruction", style="white", min_width=30)
            
            for insn in instructions:
                table.add_row(f"0x{insn.address:08x}:", f"{insn.mnemonic} {insn.op_str}")
            
            console.print(table)
                
        except Exception as e:
            console.print(f"[red]Error disassembling: {e}[/red]")

    def set_register(self, reg_name: str, value: int):
        """Set register value"""
        reg_name = reg_name.lower()
        if reg_name in self.arch_config.registers:
            try:
                self.uc.reg_write(self.arch_config.registers[reg_name], value)
                console.print(f"[green]Set {reg_name.upper()} = 0x{value:x}[/green]")
            except Exception as e:
                console.print(f"[red]Error setting register: {e}[/red]")
        else:
            console.print(f"[red]Unknown register: {reg_name}[/red]")

    def set_memory(self, address: int, value: int, size: int = 4):
        """Set memory value"""
        try:
            data = value.to_bytes(size, 'little')
            self.uc.mem_write(address, data)
            console.print(f"[green]Set memory[0x{address:x}] = 0x{value:x}[/green]")
        except Exception as e:
            console.print(f"[red]Error setting memory: {e}[/red]")

    def save_state(self, filename: str):
        """Save current CPU state to file"""
        try:
            state = {
                'architecture': self.current_arch,
                'registers': {},
                'memory_regions': {},
                'code_history': self.code_history,
                'breakpoints': list(self.breakpoints)
            }
            
            # Save register values
            for reg_name, reg_id in self.arch_config.registers.items():
                try:
                    state['registers'][reg_name] = self.uc.reg_read(reg_id)
                except:
                    pass
            
            # Save memory contents
            for name, (base, size) in self.memory_regions.items():
                try:
                    data = self.uc.mem_read(base, size)
                    state['memory_regions'][name] = {
                        'base': base,
                        'size': size,
                        'data': data.hex()
                    }
                except:
                    pass
            
            with open(filename, 'w') as f:
                json.dump(state, f, indent=2)
            
            console.print(f"[green]State saved to {filename}[/green]")
            
        except Exception as e:
            console.print(f"[red]Error saving state: {e}[/red]")

    def load_state(self, filename: str):
        """Load CPU state from file"""
        try:
            with open(filename, 'r') as f:
                state = json.load(f)
            
            # Switch architecture if needed
            if state['architecture'] != self.current_arch:
                self.switch_architecture(state['architecture'])
            
            # Restore registers
            for reg_name, value in state['registers'].items():
                if reg_name in self.arch_config.registers:
                    self.uc.reg_write(self.arch_config.registers[reg_name], value)
            
            # Restore memory
            for name, mem_info in state['memory_regions'].items():
                if name in self.memory_regions:
                    data = bytes.fromhex(mem_info['data'])
                    self.uc.mem_write(mem_info['base'], data)
            
            # Restore history and breakpoints
            self.code_history = state.get('code_history', [])
            self.breakpoints = set(state.get('breakpoints', []))
            
            console.print(f"[green]State loaded from {filename}[/green]")
            
        except Exception as e:
            console.print(f"[red]Error loading state: {e}[/red]")

    def dump_assembly(self, filename: str):
        """Dump assembly history to file"""
        try:
            with open(filename, 'w') as f:
                f.write(f"; Assembly History - {self.arch_config.name.upper()}\n")
                f.write(f"; Generated by Assembly REPL\n\n")
                
                for entry in self.code_history:
                    f.write(f"; Address: 0x{entry['address']:x}\n")
                    f.write(f"; Machine Code: {entry['machine_code']}\n")
                    f.write(f"{entry['instruction']}\n\n")
            
            console.print(f"[green]Assembly history dumped to {filename}[/green]")
            
        except Exception as e:
            console.print(f"[red]Error dumping assembly: {e}[/red]")

    def dump_memory(self, filename: str, address: int, size: int):
        """Dump memory region to file"""
        try:
            data = self.uc.mem_read(address, size)
            with open(filename, 'wb') as f:
                f.write(data)
            
            console.print(f"[green]Memory dumped to {filename} (0x{address:x}, {size} bytes)[/green]")
            
        except Exception as e:
            console.print(f"[red]Error dumping memory: {e}[/red]")

    def load_assembly_file(self, filename: str, address: int = None):
        """Load and assemble assembly file into memory"""
        try:
            if address is None:
                address = self.arch_config.code_base
            
            with open(filename, 'r') as f:
                lines = f.readlines()
            
            # Initialize keystone assembler
            ks = Ks(self.arch_config.ks_arch, self.arch_config.ks_mode)
            
            total_code = b''
            instruction_count = 0
            current_addr = address
            
            console.print(f"[cyan]Loading assembly file: {filename}[/cyan]")
            
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith(';') or line.startswith('#'):
                    continue
                
                try:
                    # Assemble the instruction
                    encoding, count = ks.asm(line)
                    if encoding:
                        machine_code = bytes(encoding)
                        total_code += machine_code
                        
                        # Add to history
                        self.code_history.append({
                            'instruction': line,
                            'address': current_addr,
                            'machine_code': machine_code.hex()
                        })
                        
                        instruction_count += 1
                        current_addr += len(machine_code)
                        
                        console.print(f"[dim]  {line_num:3d}: {line} -> {machine_code.hex()}[/dim]")
                    else:
                        console.print(f"[yellow]  {line_num:3d}: Warning: Could not assemble '{line}'[/yellow]")
                        
                except Exception as e:
                    console.print(f"[red]  {line_num:3d}: Error assembling '{line}': {e}[/red]")
            
            if total_code:
                # Write all assembled code to memory
                self.uc.mem_write(address, total_code)
                
                # Set instruction pointer to start of loaded code
                ip_reg = self.arch_config.instruction_pointer_register
                self.uc.reg_write(ip_reg, address)
                
                console.print(f"[green]Loaded {instruction_count} instructions ({len(total_code)} bytes) at 0x{address:x}[/green]")
                console.print(f"[green]Set instruction pointer to 0x{address:x}[/green]")
            else:
                console.print("[yellow]No valid instructions found in file[/yellow]")
                
        except FileNotFoundError:
            console.print(f"[red]File not found: {filename}[/red]")
        except Exception as e:
            console.print(f"[red]Error loading assembly file: {e}[/red]")

    def load_binary_file(self, filename: str, address: int = None):
        """Load binary file into memory"""
        try:
            if address is None:
                address = self.arch_config.code_base
            
            with open(filename, 'rb') as f:
                data = f.read()
            
            if not data:
                console.print("[yellow]Binary file is empty[/yellow]")
                return
            
            # Write binary data to memory
            self.uc.mem_write(address, data)
            
            # Set instruction pointer to start of loaded binary
            ip_reg = self.arch_config.instruction_pointer_register
            self.uc.reg_write(ip_reg, address)
            
            console.print(f"[green]Loaded binary file: {filename}[/green]")
            console.print(f"[green]Loaded {len(data)} bytes at 0x{address:x}[/green]")
            console.print(f"[green]Set instruction pointer to 0x{address:x}[/green]")
            
            # Show disassembly of first few instructions
            console.print("\n[cyan]Disassembly preview:[/cyan]")
            self.disassemble(address, 5)
                
        except FileNotFoundError:
            console.print(f"[red]File not found: {filename}[/red]")
        except Exception as e:
            console.print(f"[red]Error loading binary file: {e}[/red]")

    def switch_architecture(self, arch_name: str):
        """Switch to different architecture"""
        if arch_name not in self.ARCHITECTURES:
            console.print(f"[red]Unknown architecture: {arch_name}[/red]")
            console.print(f"Available: {', '.join(self.ARCHITECTURES.keys())}")
            return
        
        self.current_arch = arch_name
        self.arch_config = self.ARCHITECTURES[arch_name]
        self.init_engine()
        self.code_history.clear()
        self.breakpoints.clear()
        
        # Update completer for new architecture
        self._update_completer()
        
        console.print(f"[green]Switched to {arch_name.upper()} architecture[/green]")

    def parse_value(self, value_str: str) -> int:
        """Parse integer value from string (supports hex, decimal, and register dereferencing)"""
        value_str = value_str.strip()
        
        # Handle register dereferencing with $ syntax
        if value_str.startswith('$'):
            reg_name = value_str[1:].lower()
            if reg_name in self.arch_config.registers:
                try:
                    reg_value = self.uc.reg_read(self.arch_config.registers[reg_name])
                    console.print(f"[dim]${reg_name} = 0x{reg_value:x}[/dim]")
                    return reg_value
                except Exception as e:
                    console.print(f"[red]Error reading register {reg_name}: {e}[/red]")
                    return 0
            else:
                console.print(f"[red]Unknown register: {reg_name}[/red]")
                return 0
        
        # Handle hex values
        elif value_str.startswith('0x') or value_str.startswith('0X'):
            return int(value_str, 16)
        
        # Handle decimal values
        else:
            return int(value_str, 0)

    def run_repl(self):
        """Main REPL loop"""
        self.print_banner()
        
        while True:
            try:
                user_input = prompt(
                    f"asm-repl:{self.current_arch}> ",
                    completer=self.completer,
                    history=self.history
                ).strip()
                
                if not user_input:
                    continue
                
                parts = user_input.split()
                command = parts[0].lower()
                
                # Check if it's a known command first
                if command in ['quit', 'exit']:
                    console.print("[yellow]Goodbye![/yellow]")
                    break
                
                elif command == 'help':
                    self.print_help()
                
                elif command == 'arch':
                    if len(parts) > 1:
                        self.switch_architecture(parts[1])
                    else:
                        console.print(f"[green]Current architecture: {self.current_arch.upper()}[/green]")
                        console.print(f"Available: {', '.join(self.ARCHITECTURES.keys())}")
                
                elif command in ['registers', 'reg']:
                    self.show_registers()
                
                elif command in ['memory', 'mem']:
                    if len(parts) < 2:
                        console.print("[red]Usage: memory <address> [size][/red]")
                    else:
                        addr = self.parse_value(parts[1])
                        size = self.parse_value(parts[2]) if len(parts) > 2 else 64
                        self.show_memory(addr, size)
                
                elif command == 'regions':
                    self.show_memory_regions()
                
                elif command in ['assemble', 'asm']:
                    if len(parts) < 2:
                        console.print("[red]Usage: asm <instruction>[/red]")
                    else:
                        instruction = ' '.join(parts[1:])
                        self.assemble_and_execute(instruction)
                
                elif command == 'disasm':
                    if len(parts) < 2:
                        ip_reg = self.arch_config.instruction_pointer_register
                        addr = self.uc.reg_read(ip_reg)
                    else:
                        addr = self.parse_value(parts[1])
                    count = self.parse_value(parts[2]) if len(parts) > 2 else 10
                    self.disassemble(addr, count)
                
                elif command == 'set_reg':
                    if len(parts) < 3:
                        console.print("[red]Usage: set_reg <register> <value>[/red]")
                    else:
                        reg_name = parts[1]
                        value = self.parse_value(parts[2])
                        self.set_register(reg_name, value)
                
                elif command == 'set_mem':
                    if len(parts) < 3:
                        console.print("[red]Usage: set_mem <address> <value> [size][/red]")
                    else:
                        addr = self.parse_value(parts[1])
                        value = self.parse_value(parts[2])
                        size = self.parse_value(parts[3]) if len(parts) > 3 else 4
                        self.set_memory(addr, value, size)
                
                elif command in ['breakpoint', 'bp']:
                    if len(parts) < 2:
                        console.print("[red]Usage: bp <address>[/red]")
                    else:
                        addr = self.parse_value(parts[1])
                        self.breakpoints.add(addr)
                        console.print(f"[green]Breakpoint set at 0x{addr:x}[/green]")
                
                elif command == 'clear_bp':
                    if len(parts) < 2:
                        console.print("[red]Usage: clear_bp <address>[/red]")
                    else:
                        addr = self.parse_value(parts[1])
                        if addr in self.breakpoints:
                            self.breakpoints.remove(addr)
                            console.print(f"[green]Breakpoint cleared at 0x{addr:x}[/green]")
                        else:
                            console.print(f"[red]No breakpoint at 0x{addr:x}[/red]")
                
                elif command == 'list_bp':
                    if self.breakpoints:
                        console.print("[cyan]Breakpoints:[/cyan]")
                        for addr in sorted(self.breakpoints):
                            console.print(f"  0x{addr:x}")
                    else:
                        console.print("[yellow]No breakpoints set[/yellow]")
                
                elif command == 'reset':
                    self.init_engine()
                    self.code_history.clear()
                    self.breakpoints.clear()
                    console.print("[green]CPU state reset[/green]")
                
                elif command == 'step':
                    try:
                        ip_reg = self.arch_config.instruction_pointer_register
                        current_ip = self.uc.reg_read(ip_reg)
                        
                        # Read instruction at current IP
                        data = self.uc.mem_read(current_ip, 16)
                        instructions = list(self.cs.disasm(data, current_ip, 1))
                        
                        if instructions:
                            insn = instructions[0]
                            console.print(f"[cyan]Stepping: 0x{insn.address:08x} {insn.mnemonic} {insn.op_str}[/cyan]")
                            self.uc.emu_start(current_ip, current_ip + insn.size)
                        else:
                            console.print("[red]No instruction found at current IP[/red]")
                    except Exception as e:
                        console.print(f"[red]Error stepping: {e}[/red]")
                
                elif command == 'run':
                    count = self.parse_value(parts[1]) if len(parts) > 1 else 10
                    try:
                        ip_reg = self.arch_config.instruction_pointer_register
                        for i in range(count):
                            current_ip = self.uc.reg_read(ip_reg)
                            
                            # Check for breakpoints
                            if current_ip in self.breakpoints:
                                console.print(f"[yellow]Hit breakpoint at 0x{current_ip:x}[/yellow]")
                                break
                            
                            # Read and execute instruction
                            data = self.uc.mem_read(current_ip, 16)
                            instructions = list(self.cs.disasm(data, current_ip, 1))
                            
                            if instructions:
                                insn = instructions[0]
                                self.uc.emu_start(current_ip, current_ip + insn.size)
                            else:
                                console.print(f"[red]No instruction found at 0x{current_ip:x}[/red]")
                                break
                        
                        console.print(f"[green]Executed {count} instructions[/green]")
                    except Exception as e:
                        console.print(f"[red]Error running: {e}[/red]")
                
                elif command == 'save':
                    if len(parts) < 2:
                        console.print("[red]Usage: save <filename>[/red]")
                    else:
                        self.save_state(parts[1])
                
                elif command == 'load':
                    if len(parts) < 2:
                        console.print("[red]Usage: load <filename>[/red]")
                    else:
                        self.load_state(parts[1])
                
                elif command == 'load_asm':
                    if len(parts) < 2:
                        console.print("[red]Usage: load_asm <filename> [address][/red]")
                    else:
                        filename = parts[1]
                        address = self.parse_value(parts[2]) if len(parts) > 2 else None
                        self.load_assembly_file(filename, address)
                
                elif command == 'load_bin':
                    if len(parts) < 2:
                        console.print("[red]Usage: load_bin <filename> [address][/red]")
                    else:
                        filename = parts[1]
                        address = self.parse_value(parts[2]) if len(parts) > 2 else None
                        self.load_binary_file(filename, address)
                
                elif command == 'dump_asm':
                    if len(parts) < 2:
                        console.print("[red]Usage: dump_asm <filename>[/red]")
                    else:
                        self.dump_assembly(parts[1])
                
                elif command == 'dump_mem':
                    if len(parts) < 4:
                        console.print("[red]Usage: dump_mem <filename> <address> <size>[/red]")
                    else:
                        filename = parts[1]
                        addr = self.parse_value(parts[2])
                        size = self.parse_value(parts[3])
                        self.dump_memory(filename, addr, size)
                
                elif command == 'toggle_display':
                    self.auto_display = not self.auto_display
                    status = "enabled" if self.auto_display else "disabled"
                    console.print(f"[green]Auto-display {status}[/green]")
                
                elif command == 'toggle_direct':
                    self.direct_execution = not self.direct_execution
                    status = "enabled" if self.direct_execution else "disabled"
                    mode_desc = "Direct execution mode" if self.direct_execution else "Normal execution mode"
                    console.print(f"[green]{mode_desc} {status}[/green]")
                    if self.direct_execution:
                        console.print("[yellow]Instructions will execute without loading into memory first[/yellow]")
                    else:
                        console.print("[yellow]Instructions will be loaded into memory before execution[/yellow]")
                
                else:
                    # If it's not a known command, treat it as an assembly instruction
                    self.assemble_and_execute(user_input)
                    # Show auto panels after executing assembly
                    self._display_auto_panels()
                    continue
                
                # Show auto panels after most commands (except help, quit, etc.)
                if command not in ['help', 'quit', 'exit', 'toggle_display']:
                    self._display_auto_panels()
            
            except KeyboardInterrupt:
                console.print("\n[yellow]Use 'quit' or 'exit' to leave the REPL[/yellow]")
            except EOFError:
                console.print("\n[yellow]Goodbye![/yellow]")
                break
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")


def main():
    """Main entry point"""
    try:
        repl = AssemblyREPL()
        repl.run_repl()
    except KeyboardInterrupt:
        console.print("\n[yellow]Goodbye![/yellow]")
    except Exception as e:
        console.print(f"[red]Fatal error: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
