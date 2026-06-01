"""Display rendering for Opasm.

Rich-based terminal renderer that produces register tables, memory hex dumps,
stack panels, code disassembly, banner output, and help listings. This module
consumes structured snapshot dataclasses from the engine layer and has no
direct Unicorn, Capstone, or Keystone imports.

Public classes:
    DisplayRenderer - Rich-based terminal renderer.

Re-exported from opasm.engine for convenience:
    RegisterSnapshot, StackSnapshot, CodeSnapshot, DisasmEntry
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple

from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from opasm.engine import CodeSnapshot, DisasmEntry, RegisterSnapshot, StackSnapshot


# Re-export snapshot dataclasses for convenience
__all__ = [
    "DisplayRenderer",
    "RegisterSnapshot",
    "StackSnapshot",
    "CodeSnapshot",
    "DisasmEntry",
]


class DisplayRenderer:
    """Rich-based terminal renderer. No engine imports.

    Produces formatted terminal output for registers, stack, code disassembly,
    memory dumps, memory regions, calculations, banners, and help listings.

    Parameters:
        console: Optional Rich Console instance. If not provided, a default
                 Console is created.
    """

    def __init__(self, console: Optional[Console] = None) -> None:
        """Initialize the display renderer.

        Args:
            console: Optional Rich Console instance for output. If None,
                     a default Console is created.
        """
        self._console: Console = console if console is not None else Console()

    # ------------------------------------------------------------------
    # Banner and help
    # ------------------------------------------------------------------

    def render_banner(self, arch_name: str) -> None:
        """Render the Opasm banner with architecture info.

        Args:
            arch_name: Name of the current architecture (e.g., "x64").
        """
        banner_panel = Panel.fit(
            "[bold cyan]Opasm Assembly REPL v1.2[/bold cyan]\n"
            "[dim]Powered by Capstone & Unicorn[/dim]",
            border_style="cyan",
            padding=(1, 2),
        )
        self._console.print(banner_panel)
        self._console.print(
            f"\n[yellow]Current Architecture: {arch_name.upper()}[/yellow]"
        )
        self._console.print(
            "[dim]Type assembly instructions directly or 'help' for commands, "
            "'quit' to exit[/dim]"
        )

    def render_help(self, entries: List["CommandEntry"]) -> None:
        """Render the help table with command names, aliases, and usage.

        Args:
            entries: List of CommandEntry objects describing available commands.
        """
        table = Table(title="Available Commands", box=box.ROUNDED)
        table.add_column("Command", style="cyan", min_width=15)
        table.add_column("Aliases", style="yellow", min_width=15)
        table.add_column("Usage", style="white", min_width=40)

        for entry in entries:
            aliases_str = ", ".join(entry.aliases) if entry.aliases else ""
            table.add_row(entry.name, aliases_str, entry.usage)

        self._console.print(table)

    # ------------------------------------------------------------------
    # Registers
    # ------------------------------------------------------------------

    def render_registers(
        self, snapshot: RegisterSnapshot, compact: bool = False
    ) -> None:
        """Render register table, highlighting changed registers.

        Args:
            snapshot: RegisterSnapshot containing register values and change info.
            compact: If True, render in compact multi-column mode without headers.
        """
        if compact:
            table = Table(
                title=f"Registers ({snapshot.arch_name.upper()})",
                box=box.ROUNDED,
                show_header=False,
                padding=0,
            )
            table.add_column("", style="cyan", min_width=8)
            table.add_column("", style="yellow", min_width=12)
            table.add_column("", style="cyan", min_width=8)
            table.add_column("", style="yellow", min_width=12)
            table.add_column("", style="cyan", min_width=8)
            table.add_column("", style="yellow", min_width=12)

            reg_data: List[List[str]] = []
            for reg_name, value in snapshot.registers.items():
                hex_val = f"0x{value:0{snapshot.word_size * 2}x}"

                if reg_name in snapshot.changed:
                    reg_name_display = f"[bold]{reg_name.upper()}[/bold]"
                    hex_val_display = f"[bold]{hex_val}[/bold]"
                else:
                    reg_name_display = reg_name.upper()
                    hex_val_display = hex_val

                reg_data.append([reg_name_display, hex_val_display])

            # Split into 3 columns for compact display
            third = len(reg_data) // 3
            col1 = reg_data[:third]
            col2 = reg_data[third : third * 2]
            col3 = reg_data[third * 2 :]

            for i in range(max(len(col1), len(col2), len(col3))):
                c1 = col1[i] if i < len(col1) else ["", ""]
                c2 = col2[i] if i < len(col2) else ["", ""]
                c3 = col3[i] if i < len(col3) else ["", ""]
                table.add_row(c1[0], c1[1], c2[0], c2[1], c3[0], c3[1])
        else:
            # Full display for manual register command
            table = Table(
                title=f"Registers ({snapshot.arch_name.upper()})",
                box=box.ROUNDED,
            )
            table.add_column("Register", style="cyan", min_width=10)
            table.add_column("Hex Value", style="yellow", min_width=18)
            table.add_column("Decimal", style="green", min_width=15)
            table.add_column("Register", style="cyan", min_width=10)
            table.add_column("Hex Value", style="yellow", min_width=18)
            table.add_column("Decimal", style="green", min_width=15)

            reg_data_full: List[List[str]] = []
            for reg_name, value in snapshot.registers.items():
                hex_val = f"0x{value:0{snapshot.word_size * 2}x}"

                if reg_name in snapshot.changed:
                    reg_name_display = f"[bold]{reg_name.upper()}[/bold]"
                    hex_val_display = f"[bold]{hex_val}[/bold]"
                    decimal_display = f"[bold]{value}[/bold]"
                else:
                    reg_name_display = reg_name.upper()
                    hex_val_display = hex_val
                    decimal_display = str(value)

                reg_data_full.append(
                    [reg_name_display, hex_val_display, decimal_display]
                )

            # Split into two columns
            mid = len(reg_data_full) // 2
            left_col = reg_data_full[:mid]
            right_col = reg_data_full[mid:]

            for i in range(max(len(left_col), len(right_col))):
                left = left_col[i] if i < len(left_col) else ["", "", ""]
                right = right_col[i] if i < len(right_col) else ["", "", ""]
                table.add_row(left[0], left[1], left[2], right[0], right[1], right[2])

        self._console.print(table)

    # ------------------------------------------------------------------
    # Stack
    # ------------------------------------------------------------------

    def render_stack(self, snapshot: StackSnapshot, compact: bool = False) -> None:
        """Render stack hex dump.

        Args:
            snapshot: StackSnapshot containing stack memory data.
            compact: If True, render in compact mode without headers.
        """
        if compact:
            table = Table(title="Stack", box=box.ROUNDED, show_header=False, padding=0)
            table.add_column("", style="yellow", min_width=12)
            table.add_column("", style="white", min_width=24)
            table.add_column("", style="green", min_width=8)

            for i in range(0, len(snapshot.data), snapshot.word_size):
                addr = snapshot.sp_value + i
                chunk = snapshot.data[i : i + snapshot.word_size]
                if len(chunk) >= snapshot.word_size:
                    byteorder = "little" if snapshot.is_little_endian else "big"
                    value = int.from_bytes(chunk, byteorder)
                    hex_val = f"0x{value:0{snapshot.word_size * 2}x}"

                    if addr in snapshot.changed_addresses:
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

            for i in range(0, len(snapshot.data), snapshot.word_size):
                addr = snapshot.sp_value + i
                chunk = snapshot.data[i : i + snapshot.word_size]
                if len(chunk) >= snapshot.word_size:
                    byteorder = "little" if snapshot.is_little_endian else "big"
                    value = int.from_bytes(chunk, byteorder)
                    hex_val = f"0x{value:0{snapshot.word_size * 2}x}"
                    ascii_str = "".join(
                        chr(b) if 32 <= b <= 126 else "." for b in chunk
                    )

                    if addr in snapshot.changed_addresses:
                        addr_display = f"[bold]0x{addr:08x}[/bold]"
                        hex_val_display = f"[bold]{hex_val}[/bold]"
                        ascii_display = f"[bold]{ascii_str}[/bold]"
                    else:
                        addr_display = f"0x{addr:08x}"
                        hex_val_display = hex_val
                        ascii_display = ascii_str

                    marker = "<-- SP" if i == 0 else ""
                    table.add_row(addr_display, hex_val_display, ascii_display, marker)

        self._console.print(table)

    # ------------------------------------------------------------------
    # Code disassembly
    # ------------------------------------------------------------------

    def render_code(self, snapshot: CodeSnapshot, compact: bool = False) -> None:
        """Render disassembly with current IP highlighted.

        Args:
            snapshot: CodeSnapshot containing disassembled instructions.
            compact: If True, render in compact mode without headers.
        """
        if not snapshot.instructions:
            return

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

        for entry in snapshot.instructions:
            addr_str = f"0x{entry.address:08x}:"
            bytes_str = " ".join(f"{b:02x}" for b in entry.raw_bytes)
            insn_str = f"{entry.mnemonic} {entry.operands}"

            if entry.address == snapshot.current_ip:
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

        self._console.print(table)

    # ------------------------------------------------------------------
    # Memory
    # ------------------------------------------------------------------

    def render_memory(self, address: int, data: bytes) -> None:
        """Render memory hex dump.

        Args:
            address: Starting address of the memory region.
            data: Raw bytes to display.
        """
        self._console.print(
            f"\n[cyan]Memory at 0x{address:x} ({len(data)} bytes):[/cyan]"
        )

        table = Table(box=box.ROUNDED)
        table.add_column("Address", style="yellow", min_width=12)
        table.add_column("Hex", style="white", min_width=48)
        table.add_column("ASCII", style="green", min_width=16)

        for i in range(0, len(data), 16):
            addr = address + i
            chunk = data[i : i + 16]
            hex_str = " ".join(f"{b:02x}" for b in chunk)
            ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            table.add_row(f"0x{addr:08x}:", hex_str, f"|{ascii_str}|")

        self._console.print(table)

    def render_memory_regions(self, regions: Dict[str, Tuple[int, int]]) -> None:
        """Render memory region table.

        Args:
            regions: Mapping of region name to (base_address, size) tuple.
        """
        table = Table(title="Memory Regions", box=box.ROUNDED)
        table.add_column("Region", style="cyan", min_width=10)
        table.add_column("Start Address", style="yellow", min_width=15)
        table.add_column("End Address", style="yellow", min_width=15)
        table.add_column("Size", style="green", min_width=10)
        table.add_column("Purpose", style="white", min_width=20)

        for name, (base, size) in regions.items():
            end_addr = base + size - 1
            size_str = f"{size // 1024}KB" if size >= 1024 else f"{size}B"

            if name == "code":
                purpose = "Executable code region"
            elif name == "stack":
                purpose = "Stack memory region"
            elif name == "data":
                purpose = "Data storage region"
            else:
                purpose = "Memory region"

            table.add_row(
                name.upper(),
                f"0x{base:08x}",
                f"0x{end_addr:08x}",
                size_str,
                purpose,
            )

        self._console.print(table)

    # ------------------------------------------------------------------
    # Calculator
    # ------------------------------------------------------------------

    def render_calculation(self, result: int, expression: str, word_size: int) -> None:
        """Render calculation result in WinDbg style.

        Args:
            result: The computed integer result.
            expression: The original expression string.
            word_size: Architecture word size in bytes (4 or 8).
        """
        table = Table(title=f"Calculator: {expression}", box=box.ROUNDED)
        table.add_column("Format", style="cyan", min_width=12)
        table.add_column("Value", style="yellow", min_width=20)
        table.add_column("Format", style="cyan", min_width=12)
        table.add_column("Value", style="yellow", min_width=20)

        # Format in various representations
        hex_val = f"0x{result:x}" if result >= 0 else f"-0x{abs(result):x}"
        decimal_val = str(result)

        # Handle signed/unsigned representations
        max_val = (1 << (word_size * 8)) - 1

        if result < 0:
            unsigned_val = result + (1 << (word_size * 8))
            if unsigned_val > max_val:
                unsigned_val = result
        else:
            unsigned_val = result

        # Binary representation
        if result >= 0 and result <= max_val:
            binary_val = f"0b{result:b}"
        else:
            binary_val = f"0b{result & ((1 << (word_size * 8)) - 1):b}"

        # Octal representation
        octal_val = f"0o{result:o}" if result >= 0 else f"-0o{abs(result):o}"

        # ASCII representation
        ascii_val = ""
        if 0 <= result <= 127:
            if 32 <= result <= 126:
                ascii_val = f"'{chr(result)}'"
            else:
                ascii_val = f"'\\x{result:02x}'"

        # Add rows to table
        table.add_row("Decimal", decimal_val, "Hexadecimal", hex_val)

        if result != unsigned_val:
            binary_display = (
                binary_val[:50] + "..." if len(binary_val) > 50 else binary_val
            )
            table.add_row("Unsigned", str(unsigned_val), "Binary", binary_display)
        else:
            binary_display = (
                binary_val[:50] + "..." if len(binary_val) > 50 else binary_val
            )
            table.add_row("Octal", octal_val, "Binary", binary_display)

        if ascii_val:
            table.add_row("ASCII", ascii_val, "", "")

        self._console.print(table)

        # Show bit breakdown for interesting values
        if result != 0 and 0 < result <= 0xFFFFFFFF:
            self._render_bit_breakdown(result)

    # ------------------------------------------------------------------
    # Panel suppression logic
    # ------------------------------------------------------------------

    def should_show_panels(self, auto_display: bool) -> Tuple[bool, bool, bool]:
        """Determine which panels to show based on terminal height.

        Returns a tuple of (show_registers, show_stack, show_code) based
        on terminal height thresholds:
        - < 25 lines: (False, False, False) - no panels
        - 25-34 lines: (True, False, False) - registers only
        - 35-44 lines: (True, True, False) - registers + stack
        - >= 45 lines: (True, True, True) - all panels

        Args:
            auto_display: If False, returns (False, False, False) regardless.

        Returns:
            Tuple of three booleans indicating which panels to render.
        """
        if not auto_display:
            return (False, False, False)

        try:
            size = self._console.size
            height = size.height
        except Exception:
            height = 24  # Default fallback

        show_registers = height >= 25
        show_stack = height >= 35
        show_code = height >= 45

        return (show_registers, show_stack, show_code)

    # ------------------------------------------------------------------
    # Message output
    # ------------------------------------------------------------------

    def print_info(self, message: str) -> None:
        """Print informational message in green.

        Args:
            message: The message text to display.
        """
        self._console.print(f"[green]{message}[/green]")

    def print_error(self, message: str) -> None:
        """Print error message in red with 'error: ' prefix.

        Args:
            message: The error description to display.
        """
        self._console.print(f"[red]error: {message}[/red]")

    def print_warning(self, message: str) -> None:
        """Print warning message in yellow.

        Args:
            message: The warning text to display.
        """
        self._console.print(f"[yellow]warning: {message}[/yellow]")

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _render_bit_breakdown(self, value: int) -> None:
        """Render bit-by-bit breakdown of a value.

        Args:
            value: The integer value to break down into bits.
        """
        table = Table(title="Bit Breakdown", box=box.ROUNDED, show_header=False)
        table.add_column("", style="cyan", min_width=8)
        table.add_column("", style="yellow", min_width=50)

        set_bits: List[int] = []
        for i in range(32):
            if (value >> i) & 1:
                set_bits.append(i)

        if set_bits:
            bits_str = " + ".join([f"2^{bit}" for bit in set_bits])
            if len(bits_str) > 100:
                bits_str = bits_str[:100] + "..."
            table.add_row("Powers", bits_str)

            positions_str = " + ".join([f"bit{bit}" for bit in set_bits])
            if len(positions_str) > 100:
                positions_str = positions_str[:100] + "..."
            table.add_row("Positions", positions_str)

        self._console.print(table)
