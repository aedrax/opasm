"""REPL loop and orchestration for Opasm.

Provides the top-level OpasmREPL class that wires together all sub-modules
(EngineManager, DisplayRenderer, StateManager, Calculator, CommandDispatcher)
and implements the interactive prompt_toolkit loop with context-aware
completion and all command handlers.

Public classes:
    OpasmREPL - Top-level REPL orchestrator.

Public functions:
    main - Entry point for the Opasm application.
"""

from __future__ import annotations

import sys
from typing import Any, List

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import Completer, Completion, WordCompleter

from opasm.architectures import ARCHITECTURES, get_architecture, list_architectures
from opasm.calculator import Calculator, CalculationError
from opasm.dispatcher import CommandContext, CommandDispatcher
from opasm.display import DisplayRenderer
from opasm.engine import EngineManager
from opasm.exceptions import (
    AssemblyError,
    EngineInitError,
    FileOperationError,
    MemoryAccessError,
    OpasmError,
)
from opasm.state import StateManager


class OpasmREPL:
    """Top-level REPL orchestrator.

    Creates and wires together all sub-modules, registers command handlers,
    and runs the interactive prompt loop. Implements the CommandContext
    protocol so that it can be passed directly to the CommandDispatcher.
    """

    def __init__(self) -> None:
        """Initialize the REPL with default x64 architecture."""
        arch_config = get_architecture("x64")
        self._engine: EngineManager = EngineManager(arch_config)
        self._engine.initialize()

        self._display: DisplayRenderer = DisplayRenderer()
        self._state_mgr: StateManager = StateManager(self._engine)
        self._calculator: Calculator = Calculator()

        self._auto_display: bool = True
        self._direct_mode: bool = False
        self._previous_state: dict[str, Any] = {}

        self._dispatcher: CommandDispatcher = CommandDispatcher(
            context=self,
            assembly_handler=self._assembly_handler,
        )

        self._register_commands()

    # ------------------------------------------------------------------
    # CommandContext protocol properties
    # ------------------------------------------------------------------

    @property
    def engine(self) -> EngineManager:
        """The EngineManager instance."""
        return self._engine

    @property
    def display(self) -> DisplayRenderer:
        """The DisplayRenderer instance."""
        return self._display

    @property
    def state_mgr(self) -> StateManager:
        """The StateManager instance."""
        return self._state_mgr

    @property
    def calculator(self) -> Calculator:
        """The Calculator instance."""
        return self._calculator

    # ------------------------------------------------------------------
    # Command registration
    # ------------------------------------------------------------------

    def _register_commands(self) -> None:
        """Register all REPL commands with the dispatcher."""
        reg = self._dispatcher.register

        reg("help", self._cmd_help, aliases=[], usage="Show available commands")
        reg(
            "arch",
            self._cmd_arch,
            aliases=[],
            usage="arch [name] - Show or switch architecture",
        )
        reg("endian", self._cmd_endian, aliases=[], usage="Show endianness info")
        reg(
            "registers",
            self._cmd_registers,
            aliases=["reg"],
            usage="Show all registers",
        )
        reg(
            "memory",
            self._cmd_memory,
            aliases=["mem"],
            usage="memory <addr> [size] - Show memory",
        )
        reg("regions", self._cmd_regions, aliases=[], usage="Show memory regions")
        reg(
            "assemble",
            self._cmd_assemble,
            aliases=["asm"],
            usage="asm <instruction> - Assemble and execute",
        )
        reg(
            "disasm",
            self._cmd_disasm,
            aliases=[],
            usage="disasm [addr] [count] - Disassemble",
        )
        reg(
            "set_reg",
            self._cmd_set_reg,
            aliases=[],
            usage="set_reg <reg> <value> - Set register",
        )
        reg(
            "set_mem",
            self._cmd_set_mem,
            aliases=[],
            usage="set_mem <addr> <value> [size] - Set memory",
        )
        reg(
            "breakpoint",
            self._cmd_breakpoint,
            aliases=["bp"],
            usage="bp <addr> - Add breakpoint",
        )
        reg(
            "clear_bp",
            self._cmd_clear_bp,
            aliases=[],
            usage="clear_bp <addr> - Clear breakpoint",
        )
        reg("list_bp", self._cmd_list_bp, aliases=[], usage="List all breakpoints")
        reg("reset", self._cmd_reset, aliases=[], usage="Reset emulator state")
        reg("step", self._cmd_step, aliases=[], usage="Step one instruction")
        reg(
            "run", self._cmd_run, aliases=[], usage="run [count] - Run until breakpoint"
        )
        reg(
            "save", self._cmd_save, aliases=[], usage="save <file> - Save state to file"
        )
        reg(
            "load",
            self._cmd_load,
            aliases=[],
            usage="load <file> - Load state from file",
        )
        reg(
            "load_asm",
            self._cmd_load_asm,
            aliases=[],
            usage="load_asm <file> [addr] - Load assembly file",
        )
        reg(
            "load_bin",
            self._cmd_load_bin,
            aliases=[],
            usage="load_bin <file> [addr] - Load binary file",
        )
        reg(
            "dump_asm",
            self._cmd_dump_asm,
            aliases=[],
            usage="dump_asm <file> - Dump assembly to file",
        )
        reg(
            "dump_mem",
            self._cmd_dump_mem,
            aliases=[],
            usage="dump_mem <file> <addr> <size> - Dump memory",
        )
        reg(
            "toggle_display",
            self._cmd_toggle_display,
            aliases=[],
            usage="Toggle auto display",
        )
        reg(
            "toggle_direct",
            self._cmd_toggle_direct,
            aliases=[],
            usage="Toggle direct execution mode",
        )
        reg(
            "?",
            self._cmd_calculate,
            aliases=["calculate", "calc"],
            usage="? <expr> - Evaluate expression",
        )
        reg("quit", self._cmd_quit, aliases=["exit"], usage="Exit the REPL")

    # ------------------------------------------------------------------
    # Assembly handler (fallback for non-command input)
    # ------------------------------------------------------------------

    def _assembly_handler(self, input_str: str) -> None:
        """Handle input that doesn't match any command - treat as assembly.

        Args:
            input_str: Raw user input to assemble and execute.
        """
        self._previous_state = self._state_mgr.capture()
        self._engine.assemble_and_execute(input_str, direct=self._direct_mode)
        self._display.print_info(
            f"{'Executed (direct)' if self._direct_mode else 'Executed'}: {input_str}"
        )
        self._display_auto_panels()

    # ------------------------------------------------------------------
    # REPL run loop
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Run the interactive REPL loop.

        Renders the banner, creates a PromptSession with context-aware
        completion, and enters the prompt loop. Catches EngineInitError
        at the top level and exits; all other recoverable errors are
        handled by the dispatcher.
        """
        try:
            self._display.render_banner(self._engine.current_arch_name)

            session: PromptSession[str] = PromptSession(
                completer=WordCompleter(
                    self._dispatcher.get_command_names(), ignore_case=True
                ),
            )

            while True:
                try:
                    user_input: str = session.prompt(
                        f"opasm:{self._engine.current_arch_name}> "
                    )
                    stripped = user_input.strip()
                    if not stripped:
                        continue

                    should_continue = self._dispatcher.dispatch(user_input)
                    if not should_continue:
                        break

                except KeyboardInterrupt:
                    self._display.print_warning(
                        "\nUse 'quit' or 'exit' to leave the REPL"
                    )
                except EOFError:
                    self._display.print_warning("\nGoodbye!")
                    break

        except EngineInitError as exc:
            self._display.print_error(str(exc))
            sys.exit(1)

    # ------------------------------------------------------------------
    # Auto-display panels
    # ------------------------------------------------------------------

    def _display_auto_panels(self) -> None:
        """Display register, stack, and code panels if auto-display is enabled."""
        show_regs, show_stack, show_code = self._display.should_show_panels(
            self._auto_display
        )

        if not any((show_regs, show_stack, show_code)):
            return

        # Get state changes
        if self._previous_state:
            changes = self._state_mgr.compare(self._previous_state)
        else:
            from opasm.state import StateChanges

            changes = StateChanges()

        if show_regs:
            snapshot = self._engine.get_register_snapshot()
            snapshot.changed = changes.changed_registers
            self._display.render_registers(snapshot, compact=True)

        if show_stack:
            try:
                stack_snap = self._engine.get_stack_snapshot(size=32)
                stack_snap.changed_addresses = changes.changed_stack_addresses
                self._display.render_stack(stack_snap, compact=True)
            except MemoryAccessError:
                pass

        if show_code:
            try:
                code_snap = self._engine.get_code_snapshot()
                self._display.render_code(code_snap, compact=True)
            except (MemoryAccessError, AssemblyError):
                pass

        # Update previous state for next comparison
        self._previous_state = self._state_mgr.capture()

    # ------------------------------------------------------------------
    # Helper: parse value (supports hex, decimal, register deref)
    # ------------------------------------------------------------------

    def _parse_value(self, value_str: str) -> int:
        """Parse a value string: hex, decimal, or $register reference.

        Args:
            value_str: String to parse.

        Returns:
            The parsed integer value.

        Raises:
            OpasmError: If parsing fails.
        """
        value_str = value_str.strip()

        if value_str.startswith("$"):
            reg_name = value_str[1:].lower()
            try:
                val = self._engine.read_register(reg_name)
                self._display.print_info(f"${reg_name} = 0x{val:x}")
                return val
            except KeyError:
                raise OpasmError(f"Unknown register: {reg_name}")

        try:
            if value_str.lower().startswith("0x"):
                return int(value_str, 16)
            return int(value_str, 0)
        except ValueError as exc:
            raise OpasmError(f"Cannot parse value: {value_str}") from exc

    # ------------------------------------------------------------------
    # Command handlers
    # ------------------------------------------------------------------

    def _cmd_help(self, context: CommandContext, args: List[str]) -> None:
        """Show the help table."""
        entries = self._dispatcher.get_help_entries()
        self._display.render_help(entries)

    def _cmd_arch(self, context: CommandContext, args: List[str]) -> None:
        """Show or switch architecture."""
        if args:
            arch_name = args[0].lower()
            if arch_name not in ARCHITECTURES:
                self._display.print_error(
                    f"Unknown architecture: {arch_name}. "
                    f"Available: {', '.join(list_architectures())}"
                )
                return
            new_config = get_architecture(arch_name)
            self._engine.switch_architecture(new_config)
            self._state_mgr = StateManager(self._engine)
            self._previous_state = {}
            self._display.print_info(f"Switched to {arch_name.upper()} architecture")
        else:
            self._display.print_info(
                f"Current architecture: {self._engine.current_arch_name.upper()}"
            )
            self._display.print_info(f"Available: {', '.join(list_architectures())}")

    def _cmd_endian(self, context: CommandContext, args: List[str]) -> None:
        """Show endianness info."""
        endian = (
            "Little-endian"
            if self._engine.arch_config.is_little_endian
            else "Big-endian"
        )
        self._display.print_info(f"Current endianness: {endian}")

    def _cmd_registers(self, context: CommandContext, args: List[str]) -> None:
        """Show all registers."""
        snapshot = self._engine.get_register_snapshot()
        self._display.render_registers(snapshot, compact=False)

    def _cmd_memory(self, context: CommandContext, args: List[str]) -> None:
        """Show memory at address."""
        if not args:
            self._display.print_error("Usage: memory <address> [size]")
            return
        addr = self._parse_value(args[0])
        size = self._parse_value(args[1]) if len(args) > 1 else 64
        data = self._engine.read_memory(addr, size)
        self._display.render_memory(addr, data)

    def _cmd_regions(self, context: CommandContext, args: List[str]) -> None:
        """Show memory regions."""
        regions = self._engine.get_memory_regions()
        self._display.render_memory_regions(regions)

    def _cmd_assemble(self, context: CommandContext, args: List[str]) -> None:
        """Assemble and execute instruction."""
        if not args:
            self._display.print_error("Usage: asm <instruction>")
            return
        instruction = " ".join(args)
        self._previous_state = self._state_mgr.capture()
        self._engine.assemble_and_execute(instruction, direct=self._direct_mode)
        self._display.print_info(
            f"{'Executed (direct)' if self._direct_mode else 'Executed'}: {instruction}"
        )
        self._display_auto_panels()

    def _cmd_disasm(self, context: CommandContext, args: List[str]) -> None:
        """Disassemble at address."""
        if args:
            addr = self._parse_value(args[0])
        else:
            addr = self._engine.read_register(
                next(
                    name
                    for name, reg_id in self._engine.arch_config.registers.items()
                    if reg_id == self._engine.arch_config.instruction_pointer_register
                )
            )
        count = self._parse_value(args[1]) if len(args) > 1 else 10
        entries = self._engine.disassemble(addr, count)
        from opasm.engine import CodeSnapshot

        snapshot = CodeSnapshot(instructions=entries, current_ip=addr)
        self._display.render_code(snapshot, compact=False)

    def _cmd_set_reg(self, context: CommandContext, args: List[str]) -> None:
        """Set register value."""
        if len(args) < 2:
            self._display.print_error("Usage: set_reg <register> <value>")
            return
        reg_name = args[0]
        value = self._parse_value(args[1])
        self._engine.write_register(reg_name, value)
        self._display.print_info(f"Set {reg_name.upper()} = 0x{value:x}")

    def _cmd_set_mem(self, context: CommandContext, args: List[str]) -> None:
        """Set memory value."""
        if len(args) < 2:
            self._display.print_error("Usage: set_mem <address> <value> [size]")
            return
        addr = self._parse_value(args[0])
        value = self._parse_value(args[1])
        size = self._parse_value(args[2]) if len(args) > 2 else 4
        byteorder = "little" if self._engine.arch_config.is_little_endian else "big"
        data = value.to_bytes(size, byteorder)
        self._engine.write_memory(addr, data)
        self._display.print_info(f"Set memory[0x{addr:x}] = 0x{value:x}")

    def _cmd_breakpoint(self, context: CommandContext, args: List[str]) -> None:
        """Add breakpoint."""
        if not args:
            self._display.print_error("Usage: bp <address>")
            return
        addr = self._parse_value(args[0])
        self._engine.add_breakpoint(addr)
        self._display.print_info(f"Breakpoint set at 0x{addr:x}")

    def _cmd_clear_bp(self, context: CommandContext, args: List[str]) -> None:
        """Clear breakpoint."""
        if not args:
            self._display.print_error("Usage: clear_bp <address>")
            return
        addr = self._parse_value(args[0])
        try:
            self._engine.remove_breakpoint(addr)
            self._display.print_info(f"Breakpoint cleared at 0x{addr:x}")
        except KeyError:
            self._display.print_error(f"No breakpoint at 0x{addr:x}")

    def _cmd_list_bp(self, context: CommandContext, args: List[str]) -> None:
        """List breakpoints."""
        bps = self._engine.breakpoints
        if bps:
            self._display.print_info("Breakpoints:")
            for addr in sorted(bps):
                self._display.print_info(f"  0x{addr:x}")
        else:
            self._display.print_warning("No breakpoints set")

    def _cmd_reset(self, context: CommandContext, args: List[str]) -> None:
        """Reset emulator."""
        self._engine.reset()
        self._previous_state = {}
        self._display.print_info("CPU state reset")

    def _cmd_step(self, context: CommandContext, args: List[str]) -> None:
        """Step one instruction."""
        self._previous_state = self._state_mgr.capture()
        self._engine.step()
        self._display.print_info("Stepped one instruction")
        self._display_auto_panels()

    def _cmd_run(self, context: CommandContext, args: List[str]) -> None:
        """Run until breakpoint."""
        count = self._parse_value(args[0]) if args else 10
        self._previous_state = self._state_mgr.capture()
        executed = self._engine.run(count)
        self._display.print_info(f"Executed {executed} instructions")
        self._display_auto_panels()

    def _cmd_save(self, context: CommandContext, args: List[str]) -> None:
        """Save state to file."""
        if not args:
            self._display.print_error("Usage: save <filename>")
            return
        self._state_mgr.save(args[0])
        self._display.print_info(f"State saved to {args[0]}")

    def _cmd_load(self, context: CommandContext, args: List[str]) -> None:
        """Load state from file."""
        if not args:
            self._display.print_error("Usage: load <filename>")
            return
        self._state_mgr.load(args[0])
        self._previous_state = {}
        self._display.print_info(f"State loaded from {args[0]}")

    def _cmd_load_asm(self, context: CommandContext, args: List[str]) -> None:
        """Load assembly from file."""
        if not args:
            self._display.print_error("Usage: load_asm <filename> [address]")
            return
        filename = args[0]
        address = (
            self._parse_value(args[1])
            if len(args) > 1
            else self._engine.arch_config.code_base
        )

        try:
            with open(filename, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except OSError as exc:
            raise FileOperationError(f"Cannot read file '{filename}': {exc}") from exc

        total_code = b""
        instruction_count = 0
        current_addr = address

        self._display.print_info(f"Loading assembly file: {filename}")

        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith(";") or line.startswith("#"):
                continue
            machine_code = self._engine.assemble(line)
            self._engine.append_code_history(
                {
                    "instruction": line,
                    "address": current_addr,
                    "machine_code": machine_code.hex(),
                    "direct_execution": False,
                }
            )
            total_code += machine_code
            instruction_count += 1
            current_addr += len(machine_code)

        if total_code:
            self._engine.write_memory(address, total_code)
            # Set IP to start of loaded code
            ip_name = next(
                name
                for name, reg_id in self._engine.arch_config.registers.items()
                if reg_id == self._engine.arch_config.instruction_pointer_register
            )
            self._engine.write_register(ip_name, address)
            self._display.print_info(
                f"Loaded {instruction_count} instructions ({len(total_code)} bytes) at 0x{address:x}"
            )
            self._display.print_info(f"Set instruction pointer to 0x{address:x}")
        else:
            self._display.print_warning("No valid instructions found in file")

    def _cmd_load_bin(self, context: CommandContext, args: List[str]) -> None:
        """Load binary from file."""
        if not args:
            self._display.print_error("Usage: load_bin <filename> [address]")
            return
        filename = args[0]
        address = (
            self._parse_value(args[1])
            if len(args) > 1
            else self._engine.arch_config.code_base
        )

        try:
            with open(filename, "rb") as f:
                data = f.read()
        except OSError as exc:
            raise FileOperationError(f"Cannot read file '{filename}': {exc}") from exc

        if not data:
            self._display.print_warning("Binary file is empty")
            return

        self._engine.write_memory(address, data)
        # Set IP to start of loaded binary
        ip_name = next(
            name
            for name, reg_id in self._engine.arch_config.registers.items()
            if reg_id == self._engine.arch_config.instruction_pointer_register
        )
        self._engine.write_register(ip_name, address)
        self._display.print_info(f"Loaded {len(data)} bytes at 0x{address:x}")
        self._display.print_info(f"Set instruction pointer to 0x{address:x}")

    def _cmd_dump_asm(self, context: CommandContext, args: List[str]) -> None:
        """Dump assembly to file."""
        if not args:
            self._display.print_error("Usage: dump_asm <filename>")
            return
        filename = args[0]
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(
                    f"; Assembly History - {self._engine.current_arch_name.upper()}\n"
                )
                f.write("; Generated by Opasm\n\n")
                for entry in self._engine.code_history:
                    f.write(f"; Address: 0x{entry['address']:x}\n")
                    f.write(f"; Machine Code: {entry['machine_code']}\n")
                    f.write(f"{entry['instruction']}\n\n")
        except OSError as exc:
            raise FileOperationError(f"Cannot write file '{filename}': {exc}") from exc

        self._display.print_info(f"Assembly history dumped to {filename}")

    def _cmd_dump_mem(self, context: CommandContext, args: List[str]) -> None:
        """Dump memory to file."""
        if len(args) < 3:
            self._display.print_error("Usage: dump_mem <filename> <address> <size>")
            return
        filename = args[0]
        addr = self._parse_value(args[1])
        size = self._parse_value(args[2])
        data = self._engine.read_memory(addr, size)
        try:
            with open(filename, "wb") as f:
                f.write(data)
        except OSError as exc:
            raise FileOperationError(f"Cannot write file '{filename}': {exc}") from exc

        self._display.print_info(
            f"Memory dumped to {filename} (0x{addr:x}, {size} bytes)"
        )

    def _cmd_toggle_display(self, context: CommandContext, args: List[str]) -> None:
        """Toggle auto display."""
        self._auto_display = not self._auto_display
        status = "enabled" if self._auto_display else "disabled"
        self._display.print_info(f"Auto-display {status}")

    def _cmd_toggle_direct(self, context: CommandContext, args: List[str]) -> None:
        """Toggle direct execution mode."""
        self._direct_mode = not self._direct_mode
        status = "enabled" if self._direct_mode else "disabled"
        mode_desc = (
            "Direct execution mode" if self._direct_mode else "Normal execution mode"
        )
        self._display.print_info(f"{mode_desc} {status}")
        if self._direct_mode:
            self._display.print_warning(
                "Instructions will execute without loading into memory first"
            )
        else:
            self._display.print_warning(
                "Instructions will be loaded into memory before execution"
            )

    def _cmd_calculate(self, context: CommandContext, args: List[str]) -> None:
        """Evaluate expression."""
        if not args:
            self._display.print_error("Usage: ? <expression> or calculate <expression>")
            self._display.print_info(
                "Examples: ? 1+2*3, ? $rax+0x100, calculate $eax&0xFF"
            )
            return
        expression = " ".join(args)
        # Build register dict for the calculator
        registers: dict[str, int] = {}
        for reg_name in self._engine.arch_config.registers:
            try:
                registers[reg_name] = self._engine.read_register(reg_name)
            except (KeyError, Exception):
                pass
        result = self._calculator.evaluate(expression, registers)
        self._display.render_calculation(
            result, expression, self._engine.arch_config.word_size
        )

    def _cmd_quit(self, context: CommandContext, args: List[str]) -> bool:  # type: ignore[return]
        """Exit REPL."""
        self._display.print_warning("Goodbye!")
        return False


def main() -> None:
    """Entry point for the Opasm application.

    Creates an OpasmREPL instance and starts the interactive loop.
    Catches EngineInitError for fatal initialization failures.
    """
    try:
        repl = OpasmREPL()
        repl.run()
    except EngineInitError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nGoodbye!")
