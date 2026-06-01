"""Opasm, an interactive assembly REPL for multi-architecture emulation.

This package provides a modular assembly development environment supporting
x86, x64, ARM, ARM64, MIPS32, MIPS64, PPC32, and PPC64 architectures.

Public modules:
    architectures - Architecture configuration registry
    engine - Unicorn/Capstone/Keystone engine lifecycle management
    dispatcher - Command registration and routing
    display - Rich-based terminal rendering
    state - CPU/memory state capture and serialization
    calculator - Expression evaluation with register substitution
    repl - REPL loop and orchestration
    exceptions - Custom exception hierarchy
"""

__version__ = "1.2.0"
__all__ = [
    "architectures",
    "calculator",
    "dispatcher",
    "display",
    "engine",
    "exceptions",
    "repl",
    "state",
]
