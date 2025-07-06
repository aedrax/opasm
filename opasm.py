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
    from unicorn.ppc_const import *
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

def print_info(message: str):
    """Print informational messages in green"""
    console.print(f"[green]{message}[/green]")

def print_error(message: str):
    """Print error messages in red"""
    console.print(f"[red]error: {message}[/red]")

def print_warning(message: str):
    """Print warning messages in yellow"""
    console.print(f"[yellow]warning: {message}[/yellow]")

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
    is_little_endian: bool
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
            is_little_endian=True,
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
            is_little_endian=True,
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
            is_little_endian=True,
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
            is_little_endian=True,
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
        'mips32': ArchConfig(
            name='mips32',
            uc_arch=UC_ARCH_MIPS,
            uc_mode=UC_MODE_MIPS32,
            cs_arch=CS_ARCH_MIPS,
            cs_mode=CS_MODE_MIPS32,
            ks_arch=KS_ARCH_MIPS,
            ks_mode=KS_MODE_MIPS32,
            is_little_endian=True,
            registers={
                'r0 (zero)': UC_MIPS_REG_ZERO,
                'r1 (at)': UC_MIPS_REG_AT,
                'r2 (v0)': UC_MIPS_REG_V0,
                'r3 (v1)': UC_MIPS_REG_V1,
                'r4 (a0)': UC_MIPS_REG_A0,
                'r5 (a1)': UC_MIPS_REG_A1,
                'r6 (a2)': UC_MIPS_REG_A2,
                'r7 (a3)': UC_MIPS_REG_A3,
                'r8 (t0)': UC_MIPS_REG_T0,
                'r9 (t1)': UC_MIPS_REG_T1,
                'r10 (t2)': UC_MIPS_REG_T2,
                'r11 (t3)': UC_MIPS_REG_T3,
                'r12 (t4)': UC_MIPS_REG_T4,
                'r13 (t5)': UC_MIPS_REG_T5,
                'r14 (t6)': UC_MIPS_REG_T6,
                'r15 (t7)': UC_MIPS_REG_T7,
                'r16 (s0)': UC_MIPS_REG_S0,
                'r17 (s1)': UC_MIPS_REG_S1,
                'r18 (s2)': UC_MIPS_REG_S2,
                'r19 (s3)': UC_MIPS_REG_S3,
                'r20 (s4)': UC_MIPS_REG_S4,
                'r21 (s5)': UC_MIPS_REG_S5,
                'r22 (s6)': UC_MIPS_REG_S6,
                'r23 (s7)': UC_MIPS_REG_S7,
                'r24 (t8)': UC_MIPS_REG_T8,
                'r25 (t9)': UC_MIPS_REG_T9,
                'r26 (k0)': UC_MIPS_REG_K0,
                'r27 (k1)': UC_MIPS_REG_K1,
                'r28 (gp)': UC_MIPS_REG_GP,
                'r29 (sp)': UC_MIPS_REG_SP,
                'r30 (fp)': UC_MIPS_REG_FP,
                'r31 (ra)': UC_MIPS_REG_RA,
                'pc': UC_MIPS_REG_PC,
                'sp': UC_MIPS_REG_SP,
            },
            instruction_pointer_register=UC_MIPS_REG_PC,
            stack_pointer_register=UC_MIPS_REG_SP,
            stack_base=0x7fff0000,
            code_base=0x400000,
            data_base=0x10000000,
            word_size=4
        ),
        'mips64': ArchConfig(
            name='mips64',
            uc_arch=UC_ARCH_MIPS,
            uc_mode=UC_MODE_MIPS64,
            cs_arch=CS_ARCH_MIPS,
            cs_mode=CS_MODE_MIPS64,
            ks_arch=KS_ARCH_MIPS,
            ks_mode=KS_MODE_MIPS64,
            is_little_endian=False,
            registers={
                'r0 (zero)': UC_MIPS_REG_ZERO,
                'r1 (at)': UC_MIPS_REG_AT,
                'r2 (v0)': UC_MIPS_REG_V0,
                'r3 (v1)': UC_MIPS_REG_V1,
                'r4 (a0)': UC_MIPS_REG_A0,
                'r5 (a1)': UC_MIPS_REG_A1,
                'r6 (a2)': UC_MIPS_REG_A2,
                'r7 (a3)': UC_MIPS_REG_A3,
                'r8 (t0)': UC_MIPS_REG_T0,
                'r9 (t1)': UC_MIPS_REG_T1,
                'r10 (t2)': UC_MIPS_REG_T2,
                'r11 (t3)': UC_MIPS_REG_T3,
                'r12 (t4)': UC_MIPS_REG_T4,
                'r13 (t5)': UC_MIPS_REG_T5,
                'r14 (t6)': UC_MIPS_REG_T6,
                'r15 (t7)': UC_MIPS_REG_T7,
                'r16 (s0)': UC_MIPS_REG_S0,
                'r17 (s1)': UC_MIPS_REG_S1,
                'r18 (s2)': UC_MIPS_REG_S2,
                'r19 (s3)': UC_MIPS_REG_S3,
                'r20 (s4)': UC_MIPS_REG_S4,
                'r21 (s5)': UC_MIPS_REG_S5,
                'r22 (s6)': UC_MIPS_REG_S6,
                'r23 (s7)': UC_MIPS_REG_S7,
                'r24 (t8)': UC_MIPS_REG_T8,
                'r25 (t9)': UC_MIPS_REG_T9,
                'r26 (k0)': UC_MIPS_REG_K0,
                'r27 (k1)': UC_MIPS_REG_K1,
                'r28 (gp)': UC_MIPS_REG_GP,
                'r29 (sp)': UC_MIPS_REG_SP,
                'r30 (fp)': UC_MIPS_REG_FP,
                'r31 (ra)': UC_MIPS_REG_RA,
                'pc': UC_MIPS_REG_PC,
                'sp': UC_MIPS_REG_SP,
            },
            instruction_pointer_register=UC_MIPS_REG_PC,
            stack_pointer_register=UC_MIPS_REG_SP,
            stack_base=0x7fff00000000,
            code_base=0x400000,
            data_base=0x10000000,
            word_size=8
        ),
        'ppc32': ArchConfig(
            name='ppc32',
            uc_arch=UC_ARCH_PPC,
            uc_mode=UC_MODE_PPC32,
            cs_arch=CS_ARCH_PPC,
            cs_mode=CS_MODE_32,
            ks_arch=KS_ARCH_PPC,
            ks_mode=KS_MODE_PPC32,
            is_little_endian=False,
            registers = {
                "r0": UC_PPC_REG_0,
                "r1": UC_PPC_REG_1,
                "r2": UC_PPC_REG_2,
                "r3": UC_PPC_REG_3,
                "r4": UC_PPC_REG_4,
                "r5": UC_PPC_REG_5,
                "r6": UC_PPC_REG_6,
                "r7": UC_PPC_REG_7,
                "r8": UC_PPC_REG_8,
                "r9": UC_PPC_REG_9,
                "r10": UC_PPC_REG_10,
                "r11": UC_PPC_REG_11,
                "r12": UC_PPC_REG_12,
                "r13": UC_PPC_REG_13,
                "r14": UC_PPC_REG_14,
                "r15": UC_PPC_REG_15,
                "r16": UC_PPC_REG_16,
                "r17": UC_PPC_REG_17,
                "r18": UC_PPC_REG_18,
                "r19": UC_PPC_REG_19,
                "r20": UC_PPC_REG_20,
                "r21": UC_PPC_REG_21,
                "r22": UC_PPC_REG_22,
                "r23": UC_PPC_REG_23,
                "r24": UC_PPC_REG_24,
                "r25": UC_PPC_REG_25,
                "r26": UC_PPC_REG_26,
                "r27": UC_PPC_REG_27,
                "r28": UC_PPC_REG_28,
                "r29": UC_PPC_REG_29,
                "r30": UC_PPC_REG_30,
                "r31": UC_PPC_REG_31,
                "fpr0": UC_PPC_REG_FPR0,
                "fpr1": UC_PPC_REG_FPR1,
                "fpr2": UC_PPC_REG_FPR2,
                "fpr3": UC_PPC_REG_FPR3,
                "fpr4": UC_PPC_REG_FPR4,
                "fpr5": UC_PPC_REG_FPR5,
                "fpr6": UC_PPC_REG_FPR6,
                "fpr7": UC_PPC_REG_FPR7,
                "fpr8": UC_PPC_REG_FPR8,
                "fpr9": UC_PPC_REG_FPR9,
                "fpr10": UC_PPC_REG_FPR10,
                "fpr11": UC_PPC_REG_FPR11,
                "fpr12": UC_PPC_REG_FPR12,
                "fpr13": UC_PPC_REG_FPR13,
                "fpr14": UC_PPC_REG_FPR14,
                "fpr15": UC_PPC_REG_FPR15,
                "fpr16": UC_PPC_REG_FPR16,
                "fpr17": UC_PPC_REG_FPR17,
                "fpr18": UC_PPC_REG_FPR18,
                "fpr19": UC_PPC_REG_FPR19,
                "fpr20": UC_PPC_REG_FPR20,
                "fpr21": UC_PPC_REG_FPR21,
                "fpr22": UC_PPC_REG_FPR22,
                "fpr23": UC_PPC_REG_FPR23,
                "fpr24": UC_PPC_REG_FPR24,
                "fpr25": UC_PPC_REG_FPR25,
                "fpr26": UC_PPC_REG_FPR26,
                "fpr27": UC_PPC_REG_FPR27,
                "fpr28": UC_PPC_REG_FPR28,
                "fpr29": UC_PPC_REG_FPR29,
                "fpr30": UC_PPC_REG_FPR30,
                "fpr31": UC_PPC_REG_FPR31,
                "pc": UC_PPC_REG_PC,
                "lr": UC_PPC_REG_LR,
                "ctr": UC_PPC_REG_CTR,
                "xer": UC_PPC_REG_XER,
                "cr": UC_PPC_REG_CR,
            },
            instruction_pointer_register=UC_PPC_REG_PC,
            stack_pointer_register=UC_PPC_REG_1,
            stack_base=0x7fff0000,
            code_base=0x10000000,
            data_base=0x20000000,
            word_size=4
        ),
        'ppc64': ArchConfig(
            name='ppc64',
            uc_arch=UC_ARCH_PPC,
            uc_mode=UC_MODE_PPC64,
            cs_arch=CS_ARCH_PPC,
            cs_mode=CS_MODE_64,
            ks_arch=KS_ARCH_PPC,
            ks_mode=KS_MODE_PPC64,
            is_little_endian=False,
            registers = {
                "r0": UC_PPC_REG_0,
                "r1": UC_PPC_REG_1,
                "r2": UC_PPC_REG_2,
                "r3": UC_PPC_REG_3,
                "r4": UC_PPC_REG_4,
                "r5": UC_PPC_REG_5,
                "r6": UC_PPC_REG_6,
                "r7": UC_PPC_REG_7,
                "r8": UC_PPC_REG_8,
                "r9": UC_PPC_REG_9,
                "r10": UC_PPC_REG_10,
                "r11": UC_PPC_REG_11,
                "r12": UC_PPC_REG_12,
                "r13": UC_PPC_REG_13,
                "r14": UC_PPC_REG_14,
                "r15": UC_PPC_REG_15,
                "r16": UC_PPC_REG_16,
                "r17": UC_PPC_REG_17,
                "r18": UC_PPC_REG_18,
                "r19": UC_PPC_REG_19,
                "r20": UC_PPC_REG_20,
                "r21": UC_PPC_REG_21,
                "r22": UC_PPC_REG_22,
                "r23": UC_PPC_REG_23,
                "r24": UC_PPC_REG_24,
                "r25": UC_PPC_REG_25,
                "r26": UC_PPC_REG_26,
                "r27": UC_PPC_REG_27,
                "r28": UC_PPC_REG_28,
                "r29": UC_PPC_REG_29,
                "r30": UC_PPC_REG_30,
                "r31": UC_PPC_REG_31,
                "fpr0": UC_PPC_REG_FPR0,
                "fpr1": UC_PPC_REG_FPR1,
                "fpr2": UC_PPC_REG_FPR2,
                "fpr3": UC_PPC_REG_FPR3,
                "fpr4": UC_PPC_REG_FPR4,
                "fpr5": UC_PPC_REG_FPR5,
                "fpr6": UC_PPC_REG_FPR6,
                "fpr7": UC_PPC_REG_FPR7,
                "fpr8": UC_PPC_REG_FPR8,
                "fpr9": UC_PPC_REG_FPR9,
                "fpr10": UC_PPC_REG_FPR10,
                "fpr11": UC_PPC_REG_FPR11,
                "fpr12": UC_PPC_REG_FPR12,
                "fpr13": UC_PPC_REG_FPR13,
                "fpr14": UC_PPC_REG_FPR14,
                "fpr15": UC_PPC_REG_FPR15,
                "fpr16": UC_PPC_REG_FPR16,
                "fpr17": UC_PPC_REG_FPR17,
                "fpr18": UC_PPC_REG_FPR18,
                "fpr19": UC_PPC_REG_FPR19,
                "fpr20": UC_PPC_REG_FPR20,
                "fpr21": UC_PPC_REG_FPR21,
                "fpr22": UC_PPC_REG_FPR22,
                "fpr23": UC_PPC_REG_FPR23,
                "fpr24": UC_PPC_REG_FPR24,
                "fpr25": UC_PPC_REG_FPR25,
                "fpr26": UC_PPC_REG_FPR26,
                "fpr27": UC_PPC_REG_FPR27,
                "fpr28": UC_PPC_REG_FPR28,
                "fpr29": UC_PPC_REG_FPR29,
                "fpr30": UC_PPC_REG_FPR30,
                "fpr31": UC_PPC_REG_FPR31,
                "pc": UC_PPC_REG_PC,
                "lr": UC_PPC_REG_LR,
                "ctr": UC_PPC_REG_CTR,
                "xer": UC_PPC_REG_XER,
                "cr": UC_PPC_REG_CR,
            },
            instruction_pointer_register=UC_PPC_REG_PC,
            stack_pointer_register=UC_PPC_REG_1,
            stack_base=0x7fff00000000,
            code_base=0x10000000,
            data_base=0x20000000,
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
            'list_bp', 'quit', 'exit', 'toggle_display', 'toggle_direct', 'endian'
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
    
    def _get_keystone_engine(self):
        """Get the keystone-engine instance for assembly"""
        if self.arch_config.is_little_endian:
            ks_endian = KS_MODE_LITTLE_ENDIAN
        else:
            ks_endian = KS_MODE_BIG_ENDIAN
        ks = Ks(self.arch_config.ks_arch, self.arch_config.ks_mode | ks_endian)
        return ks

    def _get_capstone_engine(self):
        """Get the capstone-engine instance for disassembly"""
        if self.arch_config.is_little_endian:
            cs_endian = CS_MODE_LITTLE_ENDIAN
        else:
            cs_endian = CS_MODE_BIG_ENDIAN
        cs = Cs(self.arch_config.cs_arch, self.arch_config.cs_mode | cs_endian)
        return cs
    
    def _get_unicorn_engine(self):
        """Get the unicorn-engine instance for emulation"""
        if self.arch_config.is_little_endian:
            uc_endian = UC_MODE_LITTLE_ENDIAN
        else:
            uc_endian = UC_MODE_BIG_ENDIAN
        uc = Uc(self.arch_config.uc_arch, self.arch_config.uc_mode | uc_endian)
        return uc

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
        elif self.current_arch in ['mips32', 'mips64']:
            return [
                # Data movement
                'move', 'li', 'la',
                # Load/Store
                'lw', 'lh', 'lb', 'sw', 'sh', 'sb', 'lui',
                # Arithmetic
                'add', 'addu', 'addi', 'addiu', 'sub', 'subu',
                'mul', 'mult', 'multu', 'div', 'divu',
                # Logical
                'and', 'andi', 'or', 'ori', 'xor', 'xori', 'nor',
                'sll', 'srl', 'sra', 'sllv', 'srlv', 'srav',
                # Comparison
                'slt', 'slti', 'sltu', 'sltiu',
                # Control flow
                'j', 'jal', 'jr', 'jalr',
                'beq', 'bne', 'bgtz', 'bltz', 'bgez', 'blez',
                # Other
                'nop', 'syscall', 'break',
            ]
        elif self.current_arch in ['ppc32', 'ppc64']:
            return [
                # Data movement
                'li', 'lis', 'la', 'mr',
                # Load/Store
                'lwz', 'lwzu', 'lwzx', 'lhz', 'lha', 'lbz', 'stw', 'stwu', 'stwx', 'sth', 'stb',
                'ld', 'ldu', 'ldx', 'std', 'stdu', 'stdx',
                # Arithmetic
                'add', 'addi', 'addis', 'subf', 'subfic', 'mulld', 'mullw', 'divd', 'divw',
                # Logical
                'and', 'andi.', 'andis.', 'or', 'ori', 'oris', 'xor', 'xori', 'xoris',
                'sld', 'slw', 'srd', 'srw', 'srad', 'sraw',
                # Comparison
                'cmpd', 'cmpw', 'cmpi', 'cmpl', 'cmpli',
                # Control flow
                'b', 'bl', 'bctr', 'bctrl', 'blr', 'beq', 'bne', 'blt', 'bgt', 'ble', 'bge',
                # Other
                'nop', 'sc', 'sync', 'isync',
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
            self.uc = self._get_unicorn_engine()
            
            # Initialize Capstone engine
            self.cs = self._get_capstone_engine()

            # Initialize Keystone engine
            self.ks = self._get_keystone_engine()
            
            # Map memory regions
            self._map_memory_regions()
            
            # Initialize stack and instruction pointers
            self._init_registers()
            
            print_info(f"Initialized {self.arch_config.name} architecture")
            
        except Exception as e:
            print_error(f"Error initializing engines: {e}")
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
                print_error(f"Error mapping {name} memory: {e}")

    def _init_registers(self):
        """Initialize registers with default values"""
        try:
            # Set stack pointer
            self.uc.reg_write(self.arch_config.stack_pointer_register, self.arch_config.stack_base + 0x80000)
            
            # Set instruction pointer
            self.uc.reg_write(self.arch_config.instruction_pointer_register, self.arch_config.code_base)
                
        except Exception as e:
            print_error(f"Error initializing registers: {e}")

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
  arch <name>            - Show current arch or switch to: x86, x64, arm, arm64, mips, mips64, ppc32, ppc64
  endian <type>          - Set endianness to 'little' or 'big' (if supported)
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
                print_warning("No stack pointer register found")
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
                print_error(f"Stack unavailable")
            else:
                print_error(f"Error reading stack: {e}")

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
                print_error(f"Code unavailable")
            else:
                print_error(f"Error reading code: {e}")

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
                print_error(f"Address 0x{address:x} is not mapped in memory")
                print_warning("Use 'regions' to see mapped memory regions")
            else:
                print_error(f"Error reading memory: {e}")

    def assemble_and_execute(self, instruction: str):
        """Assemble instruction and execute it"""
        try:
            machine_code = self._simple_assemble(instruction)
            if not machine_code:
                print_error("Failed to assemble instruction")
                return
            
            if self.direct_execution:
                # Direct execution mode - execute without loading into memory
                self._execute_direct(instruction, machine_code)
            else:
                # Normal mode - load into memory first, then execute
                self._execute_from_memory(instruction, machine_code)
            
        except Exception as e:
            print_error(f"Error executing instruction: {e}")

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
            
            print_info(f"Executed (direct): {instruction}")
            
        except Exception as e:
            print_error(f"Error in direct execution: {e}")

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
            
            print_info(f"Executed: {instruction}")
            
        except Exception as e:
            print_error(f"Error in memory execution: {e}")

    def _simple_assemble(self, instruction: str) -> bytes:
        """Assemble instruction using keystone-engine"""
        try:
            # Try keystone-engine first for full assembly support
            ks = self._get_keystone_engine()
            encoding, count = ks.asm(instruction)
            if encoding:
                return bytes(encoding)
        except Exception as e:
            print_warning(f"Keystone assembly failed: {e}")
            print_warning("Using NOP for unsupported instruction")
            encoding, count = ks.asm('nop')
            if encoding:
                return bytes(encoding)
        # all else fails
        print_error("instruction didn't work and neither did NOP")
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
            print_error(f"Error disassembling: {e}")

    def set_register(self, reg_name: str, value: int):
        """Set register value"""
        reg_name = reg_name.lower()
        if reg_name in self.arch_config.registers:
            try:
                self.uc.reg_write(self.arch_config.registers[reg_name], value)
                print_info(f"Set {reg_name.upper()} = 0x{value:x}")
            except Exception as e:
                print_error(f"Error setting register: {e}")
        else:
            print_error(f"Unknown register: {reg_name}")

    def set_memory(self, address: int, value: int, size: int = 4):
        """Set memory value"""
        try:
            data = value.to_bytes(size, 'little')
            self.uc.mem_write(address, data)
            print_info(f"Set memory[0x{address:x}] = 0x{value:x}")
        except Exception as e:
            print_error(f"Error setting memory: {e}")

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
            
            print_info(f"State saved to {filename}")
            
        except Exception as e:
            print_error(f"Error saving state: {e}")

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
            
            print_info(f"State loaded from {filename}")
            
        except Exception as e:
            print_error(f"Error loading state: {e}")

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
            
            print_info(f"Assembly history dumped to {filename}")
            
        except Exception as e:
            print_error(f"Error dumping assembly: {e}")

    def dump_memory(self, filename: str, address: int, size: int):
        """Dump memory region to file"""
        try:
            data = self.uc.mem_read(address, size)
            with open(filename, 'wb') as f:
                f.write(data)
            
            print_info(f"Memory dumped to {filename} (0x{address:x}, {size} bytes)")
            
        except Exception as e:
            print_error(f"Error dumping memory: {e}")

    def load_assembly_file(self, filename: str, address: int = None):
        """Load and assemble assembly file into memory"""
        try:
            if address is None:
                address = self.arch_config.code_base
            
            with open(filename, 'r') as f:
                lines = f.readlines()
            
            # Initialize keystone assembler
            ks = self._get_keystone_engine()

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
                        print_warning(f"  {line_num:3d}: Could not assemble '{line}'")
                        
                except Exception as e:
                    print_error(f"  {line_num:3d}: Error assembling '{line}': {e}")
            
            if total_code:
                # Write all assembled code to memory
                self.uc.mem_write(address, total_code)
                
                # Set instruction pointer to start of loaded code
                ip_reg = self.arch_config.instruction_pointer_register
                self.uc.reg_write(ip_reg, address)
                
                print_info(f"Loaded {instruction_count} instructions ({len(total_code)} bytes) at 0x{address:x}")
                print_info(f"Set instruction pointer to 0x{address:x}")
            else:
                print_warning("No valid instructions found in file")
                
        except FileNotFoundError:
            print_error(f"File not found: {filename}")
        except Exception as e:
            print_error(f"Error loading assembly file: {e}")

    def load_binary_file(self, filename: str, address: int = None):
        """Load binary file into memory"""
        try:
            if address is None:
                address = self.arch_config.code_base
            
            with open(filename, 'rb') as f:
                data = f.read()
            
            if not data:
                print_warning("Binary file is empty")
                return
            
            # Write binary data to memory
            self.uc.mem_write(address, data)
            
            # Set instruction pointer to start of loaded binary
            ip_reg = self.arch_config.instruction_pointer_register
            self.uc.reg_write(ip_reg, address)
            
            print_info(f"Loaded binary file: {filename}")
            print_info(f"Loaded {len(data)} bytes at 0x{address:x}")
            print_info(f"Set instruction pointer to 0x{address:x}")
            
            # Show disassembly of first few instructions
            console.print("\n[cyan]Disassembly preview:[/cyan]")
            self.disassemble(address, 5)
                
        except FileNotFoundError:
            print_error(f"File not found: {filename}")
        except Exception as e:
            print_error(f"Error loading binary file: {e}")

    def switch_architecture(self, arch_name: str):
        """Switch to different architecture"""
        if arch_name not in self.ARCHITECTURES:
            print_error(f"Unknown architecture: {arch_name}")
            console.print(f"Available: {', '.join(self.ARCHITECTURES.keys())}")
            return
        
        self.current_arch = arch_name
        self.arch_config = self.ARCHITECTURES[arch_name]
        self.init_engine()
        self.code_history.clear()
        self.breakpoints.clear()
        
        # Update completer for new architecture
        self._update_completer()
        
        print_info(f"Switched to {arch_name.upper()} architecture")

    def set_endian(self, endian_str: str):
        """Set the endianness for the current architecture"""
        endian_str = endian_str.lower()
        if endian_str not in ['little', 'big']:
            print_error("Invalid endianness. Use 'little' or 'big'.")
            return

        if self.current_arch.startswith('x86') and endian_str == 'big':
            print_warning("x86 architectures are little-endian only.")
            return
        
        # Check if endianness actually changed
        if self.arch_config.is_little_endian and endian_str == 'little' or \
            not self.arch_config.is_little_endian and endian_str == 'big':
            print_warning(f"Endianness is already set to {endian_str}-endian.")
            return
        
        self.arch_config.is_little_endian = (endian_str == 'little')

        print_info(f"Switched to {endian_str}-endian.")
        self.init_engine()

    def show_endian(self):
        """Show the current endianness"""
        endian = "Little-endian" if self.arch_config.is_little_endian else "Big-endian"
        print_info(f"Current endianness: {endian}")

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
                    print_error(f"Error reading register {reg_name}: {e}")
                    return 0
            else:
                print_error(f"Unknown register: {reg_name}")
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
                    print_warning("Goodbye!")
                    break
                
                elif command == 'help':
                    self.print_help()
                
                elif command == 'arch':
                    if len(parts) > 1:
                        self.switch_architecture(parts[1])
                    else:
                        print_info(f"Current architecture: {self.current_arch.upper()}")
                        console.print(f"Available: {', '.join(self.ARCHITECTURES.keys())}")
                
                elif command == 'endian':
                    if len(parts) > 1:
                        self.set_endian(parts[1])
                    else:
                        self.show_endian()

                elif command in ['registers', 'reg']:
                    self.show_registers()
                
                elif command in ['memory', 'mem']:
                    if len(parts) < 2:
                        print_error("Usage: memory <address> [size]")
                    else:
                        addr = self.parse_value(parts[1])
                        size = self.parse_value(parts[2]) if len(parts) > 2 else 64
                        self.show_memory(addr, size)
                
                elif command == 'regions':
                    self.show_memory_regions()
                
                elif command in ['assemble', 'asm']:
                    if len(parts) < 2:
                        print_error("Usage: asm <instruction>")
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
                        print_error("Usage: set_reg <register> <value>")
                    else:
                        reg_name = parts[1]
                        value = self.parse_value(parts[2])
                        self.set_register(reg_name, value)
                
                elif command == 'set_mem':
                    if len(parts) < 3:
                        print_error("Usage: set_mem <address> <value> [size]")
                    else:
                        addr = self.parse_value(parts[1])
                        value = self.parse_value(parts[2])
                        size = self.parse_value(parts[3]) if len(parts) > 3 else 4
                        self.set_memory(addr, value, size)
                
                elif command in ['breakpoint', 'bp']:
                    if len(parts) < 2:
                        print_error("Usage: bp <address>")
                    else:
                        addr = self.parse_value(parts[1])
                        self.breakpoints.add(addr)
                        print_info(f"Breakpoint set at 0x{addr:x}")
                
                elif command == 'clear_bp':
                    if len(parts) < 2:
                        print_error("Usage: clear_bp <address>")
                    else:
                        addr = self.parse_value(parts[1])
                        if addr in self.breakpoints:
                            self.breakpoints.remove(addr)
                            print_info(f"Breakpoint cleared at 0x{addr:x}")
                        else:
                            print_error(f"No breakpoint at 0x{addr:x}")
                
                elif command == 'list_bp':
                    if self.breakpoints:
                        console.print("[cyan]Breakpoints:[/cyan]")
                        for addr in sorted(self.breakpoints):
                            console.print(f"  0x{addr:x}")
                    else:
                        print_warning("No breakpoints set")
                
                elif command == 'reset':
                    self.init_engine()
                    self.code_history.clear()
                    self.breakpoints.clear()
                    print_info("CPU state reset")
                
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
                            print_error("No instruction found at current IP")
                    except Exception as e:
                        print_error(f"Error stepping: {e}")
                
                elif command == 'run':
                    count = self.parse_value(parts[1]) if len(parts) > 1 else 10
                    try:
                        ip_reg = self.arch_config.instruction_pointer_register
                        for i in range(count):
                            current_ip = self.uc.reg_read(ip_reg)
                            
                            # Check for breakpoints
                            if current_ip in self.breakpoints:
                                print_warning(f"Hit breakpoint at 0x{current_ip:x}")
                                break
                            
                            # Read and execute instruction
                            data = self.uc.mem_read(current_ip, 16)
                            instructions = list(self.cs.disasm(data, current_ip, 1))
                            
                            if instructions:
                                insn = instructions[0]
                                self.uc.emu_start(current_ip, current_ip + insn.size)
                            else:
                                print_error(f"No instruction found at 0x{current_ip:x}")
                                break
                        
                        print_info(f"Executed {count} instructions")
                    except Exception as e:
                        print_error(f"Error running: {e}")
                
                elif command == 'save':
                    if len(parts) < 2:
                        print_error("Usage: save <filename>")
                    else:
                        self.save_state(parts[1])
                
                elif command == 'load':
                    if len(parts) < 2:
                        print_error("Usage: load <filename>")
                    else:
                        self.load_state(parts[1])
                
                elif command == 'load_asm':
                    if len(parts) < 2:
                        print_error("Usage: load_asm <filename> [address]")
                    else:
                        filename = parts[1]
                        address = self.parse_value(parts[2]) if len(parts) > 2 else None
                        self.load_assembly_file(filename, address)
                
                elif command == 'load_bin':
                    if len(parts) < 2:
                        print_error("Usage: load_bin <filename> [address]")
                    else:
                        filename = parts[1]
                        address = self.parse_value(parts[2]) if len(parts) > 2 else None
                        self.load_binary_file(filename, address)
                
                elif command == 'dump_asm':
                    if len(parts) < 2:
                        print_error("Usage: dump_asm <filename>")
                    else:
                        self.dump_assembly(parts[1])
                
                elif command == 'dump_mem':
                    if len(parts) < 4:
                        print_error("Usage: dump_mem <filename> <address> <size>")
                    else:
                        filename = parts[1]
                        addr = self.parse_value(parts[2])
                        size = self.parse_value(parts[3])
                        self.dump_memory(filename, addr, size)
                
                elif command == 'toggle_display':
                    self.auto_display = not self.auto_display
                    status = "enabled" if self.auto_display else "disabled"
                    print_info(f"Auto-display {status}")
                
                elif command == 'toggle_direct':
                    self.direct_execution = not self.direct_execution
                    status = "enabled" if self.direct_execution else "disabled"
                    mode_desc = "Direct execution mode" if self.direct_execution else "Normal execution mode"
                    print_info(f"{mode_desc} {status}")
                    if self.direct_execution:
                        print_warning("Instructions will execute without loading into memory first")
                    else:
                        print_warning("Instructions will be loaded into memory before execution")
                
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
                print_warning("\nUse 'quit' or 'exit' to leave the REPL")
            except EOFError:
                print_warning("\nGoodbye!")
                break
            except Exception as e:
                print_error(f"{e}")


def main():
    """Main entry point"""
    try:
        repl = AssemblyREPL()
        repl.run_repl()
    except KeyboardInterrupt:
        print_warning("\nGoodbye!")
    except Exception as e:
        print_error(f"{e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
