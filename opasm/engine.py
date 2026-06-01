"""Engine lifecycle management for Opasm.

Manages Unicorn (emulation), Capstone (disassembly), and Keystone (assembly)
engine instances. Provides high-level methods for assembling, executing,
stepping, and inspecting CPU/memory state.

Public classes:
    EngineManager - Central engine lifecycle and execution manager.
    RegisterSnapshot - Structured register data for rendering.
    StackSnapshot - Structured stack data for rendering.
    CodeSnapshot - Structured code disassembly data for rendering.
    DisasmEntry - A single disassembled instruction.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from capstone import CS_MODE_BIG_ENDIAN, CS_MODE_LITTLE_ENDIAN, Cs
from keystone import KS_MODE_BIG_ENDIAN, KS_MODE_LITTLE_ENDIAN, Ks, KsError
from unicorn import UC_MODE_BIG_ENDIAN, UC_MODE_LITTLE_ENDIAN, Uc, UcError

from opasm.architectures import ArchConfig
from opasm.exceptions import AssemblyError, EngineInitError, MemoryAccessError


# ---------------------------------------------------------------------------
# Snapshot dataclasses - structured data transfer objects for display layer
# ---------------------------------------------------------------------------


@dataclass
class DisasmEntry:
    """A single disassembled instruction.

    Attributes:
        address: Memory address of the instruction.
        raw_bytes: Raw machine code bytes.
        mnemonic: Instruction mnemonic (e.g., "mov").
        operands: Operand string (e.g., "eax, 0x1").
    """

    address: int
    raw_bytes: bytes
    mnemonic: str
    operands: str


@dataclass
class RegisterSnapshot:
    """Structured register data for rendering.

    Attributes:
        arch_name: Architecture identifier (e.g., "x64").
        word_size: Word size in bytes (4 or 8).
        registers: Mapping of register name to current value.
        changed: Set of register names that changed since last snapshot.
        flag_register_name: Name of the flags register, or None.
        flags: Mapping of flag name to bit position, or None.
        flag_descriptions: Mapping of flag name to description, or None.
    """

    arch_name: str
    word_size: int
    registers: Dict[str, int]
    changed: Set[str] = field(default_factory=set)
    flag_register_name: Optional[str] = None
    flags: Optional[Dict[str, int]] = None
    flag_descriptions: Optional[Dict[str, str]] = None


@dataclass
class StackSnapshot:
    """Structured stack data for rendering.

    Attributes:
        sp_value: Current stack pointer value.
        word_size: Word size in bytes (4 or 8).
        is_little_endian: True if architecture uses little-endian byte order.
        data: Raw bytes read from the stack region.
        changed_addresses: Set of stack addresses whose values changed.
    """

    sp_value: int
    word_size: int
    is_little_endian: bool
    data: bytes
    changed_addresses: Set[int] = field(default_factory=set)


@dataclass
class CodeSnapshot:
    """Structured code disassembly data for rendering.

    Attributes:
        instructions: List of disassembled instructions around the IP.
        current_ip: Current instruction pointer value.
    """

    instructions: List[DisasmEntry]
    current_ip: int


# ---------------------------------------------------------------------------
# Memory region constants
# ---------------------------------------------------------------------------

_REGION_SIZE = 0x100000  # 1 MB per region
_STACK_OFFSET = 0x80000  # Initial SP offset within the stack region
_DIRECT_EXEC_ADDR = 0x50000000  # Temporary address for direct execution
_DIRECT_EXEC_SIZE = 0x1000  # 4 KB for direct execution buffer


# ---------------------------------------------------------------------------
# EngineManager
# ---------------------------------------------------------------------------


class EngineManager:
    """Manages Unicorn, Capstone, and Keystone engine lifecycle.

    Provides assembly, execution, register/memory access, disassembly,
    breakpoint management, and structured snapshot retrieval.

    Parameters:
        arch_config: Architecture configuration to initialize with.
    """

    def __init__(self, arch_config: ArchConfig) -> None:
        self._arch_config: ArchConfig = arch_config
        self._uc: Optional[Uc] = None
        self._cs: Optional[Cs] = None
        self._ks: Optional[Ks] = None
        self._memory_regions: Dict[str, Tuple[int, int]] = {}
        self._code_history: List[Dict[str, object]] = []
        self._breakpoints: Set[int] = set()
        self._direct_exec_mapped: bool = False

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def arch_config(self) -> ArchConfig:
        """Return the current architecture configuration."""
        return self._arch_config

    @property
    def current_arch_name(self) -> str:
        """Return the name of the current architecture."""
        return self._arch_config.name

    @property
    def code_history(self) -> List[Dict[str, object]]:
        """Return the list of executed instruction history entries."""
        return list(self._code_history)

    @code_history.setter
    def code_history(self, value: List[Dict[str, object]]) -> None:
        """Replace the code history with the given list."""
        self._code_history = list(value)

    def append_code_history(self, entry: Dict[str, object]) -> None:
        """Append a single entry to the code history.

        Parameters:
            entry: A dict with instruction, address, machine_code, and
                   direct_execution keys.
        """
        self._code_history.append(entry)

    @property
    def breakpoints(self) -> Set[int]:
        """Return the current set of breakpoint addresses."""
        return set(self._breakpoints)

    # ------------------------------------------------------------------
    # Initialization and lifecycle
    # ------------------------------------------------------------------

    def initialize(self) -> None:
        """Create engine instances and map memory regions.

        Creates Unicorn, Capstone, and Keystone engine instances for the
        current architecture configuration. Maps code, stack, and data
        memory regions (each 1 MB). Sets IP to code_base and SP to
        stack_base + 0x80000.

        Raises:
            EngineInitError: If any engine fails to initialize.
        """
        self._create_engines()
        self._map_memory_regions()
        self._init_registers()

    def switch_architecture(self, arch_config: ArchConfig) -> None:
        """Tear down current engines and reinitialize with a new architecture.

        Clears code history and breakpoints. The new architecture is fully
        initialized after this call.

        Parameters:
            arch_config: The new architecture configuration to switch to.

        Raises:
            EngineInitError: If the new engines fail to initialize.
        """
        self._arch_config = arch_config
        self._memory_regions.clear()
        self._code_history.clear()
        self._breakpoints.clear()
        self._direct_exec_mapped = False
        self._create_engines()
        self._map_memory_regions()
        self._init_registers()

    def reset(self) -> None:
        """Reset emulator state to initial conditions.

        Remaps all memory regions (clearing their contents), sets IP to
        code_base, SP to stack_base + 0x80000, and clears code history
        and breakpoints.

        Raises:
            EngineInitError: If engine re-creation fails.
        """
        self._memory_regions.clear()
        self._code_history.clear()
        self._breakpoints.clear()
        self._direct_exec_mapped = False
        self._create_engines()
        self._map_memory_regions()
        self._init_registers()

    # ------------------------------------------------------------------
    # Assembly
    # ------------------------------------------------------------------

    def assemble(self, instruction: str) -> bytes:
        """Assemble a single instruction into machine code bytes.

        Parameters:
            instruction: Assembly instruction text (e.g., "mov eax, 1").

        Returns:
            The assembled machine code as bytes.

        Raises:
            AssemblyError: If the instruction cannot be assembled.
        """
        try:
            encoding, _count = self._ks.asm(instruction)
            if encoding is None:
                raise AssemblyError(f"Failed to assemble instruction: {instruction}")
            return bytes(encoding)
        except KsError as exc:
            raise AssemblyError(f"Assembly failed for '{instruction}': {exc}") from exc

    def assemble_and_execute(self, instruction: str, direct: bool = False) -> None:
        """Assemble an instruction and execute it.

        In normal mode, writes machine code at the current IP and emulates
        one instruction, advancing IP. In direct mode, executes from a
        temporary buffer without advancing the main IP.

        Parameters:
            instruction: Assembly instruction text.
            direct: If True, use direct execution mode.

        Raises:
            AssemblyError: If the instruction cannot be assembled.
            MemoryAccessError: If memory access fails during execution.
        """
        machine_code = self.assemble(instruction)

        if direct:
            self._execute_direct(instruction, machine_code)
        else:
            self._execute_from_memory(instruction, machine_code)

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def step(self) -> None:
        """Execute one instruction at the current IP.

        Reads the instruction at the current instruction pointer, disassembles
        it to determine its size, then emulates exactly one instruction.

        Raises:
            MemoryAccessError: If the IP points to unmapped memory.
            AssemblyError: If no valid instruction is found at the current IP.
        """
        ip_reg = self._arch_config.instruction_pointer_register
        current_ip = self._uc.reg_read(ip_reg)

        try:
            data = bytes(self._uc.mem_read(current_ip, 16))
        except UcError as exc:
            raise MemoryAccessError(
                f"Cannot read memory at IP 0x{current_ip:x}: {exc}",
                address=current_ip,
                nearest_base=self._arch_config.code_base,
                nearest_size=_REGION_SIZE,
            ) from exc

        instructions = list(self._cs.disasm(data, current_ip, 1))
        if not instructions:
            raise AssemblyError(f"No valid instruction found at 0x{current_ip:x}")

        insn = instructions[0]
        try:
            self._uc.emu_start(current_ip, current_ip + insn.size)
        except UcError as exc:
            self._handle_uc_error(exc, current_ip)

    def run(self, count: int = 10) -> int:
        """Execute up to *count* instructions, stopping at breakpoints.

        Parameters:
            count: Maximum number of instructions to execute.

        Returns:
            The number of instructions actually executed.

        Raises:
            MemoryAccessError: If execution hits unmapped memory.
            AssemblyError: If no valid instruction is found.
        """
        ip_reg = self._arch_config.instruction_pointer_register
        executed = 0

        for _ in range(count):
            current_ip = self._uc.reg_read(ip_reg)

            # Check breakpoints
            if current_ip in self._breakpoints:
                break

            try:
                data = bytes(self._uc.mem_read(current_ip, 16))
            except UcError as exc:
                raise MemoryAccessError(
                    f"Cannot read memory at 0x{current_ip:x}: {exc}",
                    address=current_ip,
                    nearest_base=self._arch_config.code_base,
                    nearest_size=_REGION_SIZE,
                ) from exc

            instructions = list(self._cs.disasm(data, current_ip, 1))
            if not instructions:
                raise AssemblyError(f"No valid instruction found at 0x{current_ip:x}")

            insn = instructions[0]
            try:
                self._uc.emu_start(current_ip, current_ip + insn.size)
            except UcError as exc:
                self._handle_uc_error(exc, current_ip)

            executed += 1

        return executed

    # ------------------------------------------------------------------
    # Register access
    # ------------------------------------------------------------------

    def read_register(self, name: str) -> int:
        """Read a register value by name.

        Parameters:
            name: Register name (case-insensitive).

        Returns:
            The current integer value of the register.

        Raises:
            KeyError: If the register name is not valid for this architecture.
        """
        reg_name = name.lower()
        if reg_name not in self._arch_config.registers:
            raise KeyError(
                f"Unknown register '{name}' for architecture "
                f"'{self._arch_config.name}'"
            )
        reg_id = self._arch_config.registers[reg_name]
        return self._uc.reg_read(reg_id)

    def write_register(self, name: str, value: int) -> None:
        """Write a value to a register by name.

        Parameters:
            name: Register name (case-insensitive).
            value: Integer value to write.

        Raises:
            KeyError: If the register name is not valid for this architecture.
        """
        reg_name = name.lower()
        if reg_name not in self._arch_config.registers:
            raise KeyError(
                f"Unknown register '{name}' for architecture "
                f"'{self._arch_config.name}'"
            )
        reg_id = self._arch_config.registers[reg_name]
        self._uc.reg_write(reg_id, value)

    # ------------------------------------------------------------------
    # Memory access
    # ------------------------------------------------------------------

    def read_memory(self, address: int, size: int) -> bytes:
        """Read bytes from memory.

        Parameters:
            address: Start address to read from.
            size: Number of bytes to read.

        Returns:
            The memory contents as bytes.

        Raises:
            MemoryAccessError: If the address is unmapped.
        """
        try:
            return bytes(self._uc.mem_read(address, size))
        except UcError as exc:
            nearest_base, nearest_size = self._find_nearest_region(address)
            raise MemoryAccessError(
                f"Cannot read {size} bytes at address 0x{address:x}: {exc}",
                address=address,
                nearest_base=nearest_base,
                nearest_size=nearest_size,
            ) from exc

    def write_memory(self, address: int, data: bytes) -> None:
        """Write bytes to memory.

        Parameters:
            address: Start address to write to.
            data: Bytes to write.

        Raises:
            MemoryAccessError: If the address is unmapped.
        """
        try:
            self._uc.mem_write(address, data)
        except UcError as exc:
            nearest_base, nearest_size = self._find_nearest_region(address)
            raise MemoryAccessError(
                f"Cannot write {len(data)} bytes at address 0x{address:x}: {exc}",
                address=address,
                nearest_base=nearest_base,
                nearest_size=nearest_size,
            ) from exc

    # ------------------------------------------------------------------
    # Snapshots
    # ------------------------------------------------------------------

    def get_register_snapshot(self) -> RegisterSnapshot:
        """Capture a snapshot of all register values.

        Returns:
            A RegisterSnapshot containing all register values for the
            current architecture.
        """
        registers: Dict[str, int] = {}
        for reg_name, reg_id in self._arch_config.registers.items():
            try:
                registers[reg_name] = self._uc.reg_read(reg_id)
            except UcError:
                registers[reg_name] = 0

        flag_reg_name, flags, flag_descriptions = self._get_flags_info()

        return RegisterSnapshot(
            arch_name=self._arch_config.name,
            word_size=self._arch_config.word_size,
            registers=registers,
            flag_register_name=flag_reg_name,
            flags=flags,
            flag_descriptions=flag_descriptions,
        )

    def get_stack_snapshot(self, size: int = 64) -> StackSnapshot:
        """Capture a snapshot of stack memory.

        Parameters:
            size: Number of bytes to read from the stack pointer.

        Returns:
            A StackSnapshot containing the raw stack bytes.

        Raises:
            MemoryAccessError: If the stack region is not accessible.
        """
        sp_value = self._uc.reg_read(self._arch_config.stack_pointer_register)

        try:
            data = bytes(self._uc.mem_read(sp_value, size))
        except UcError as exc:
            raise MemoryAccessError(
                f"Cannot read stack at SP=0x{sp_value:x}: {exc}",
                address=sp_value,
                nearest_base=self._arch_config.stack_base,
                nearest_size=_REGION_SIZE,
            ) from exc

        return StackSnapshot(
            sp_value=sp_value,
            word_size=self._arch_config.word_size,
            is_little_endian=self._arch_config.is_little_endian,
            data=data,
        )

    def get_code_snapshot(self, context: int = 3) -> CodeSnapshot:
        """Capture a disassembly snapshot around the current IP.

        Disassembles instructions before and after the current instruction
        pointer for context display.

        Parameters:
            context: Number of instructions to show before and after IP.

        Returns:
            A CodeSnapshot with disassembled instructions and the current IP.
        """
        ip_reg = self._arch_config.instruction_pointer_register
        current_ip = self._uc.reg_read(ip_reg)

        # Try scanning backwards for context
        scan_back = 64
        start_addr = max(current_ip - scan_back, self._arch_config.code_base)

        try:
            data = bytes(self._uc.mem_read(start_addr, scan_back + 64))
            instructions = list(self._cs.disasm(data, start_addr))
        except UcError:
            # Fall back to reading from current IP forward
            try:
                data = bytes(self._uc.mem_read(current_ip, 64))
                instructions = list(self._cs.disasm(data, current_ip))
            except UcError:
                return CodeSnapshot(instructions=[], current_ip=current_ip)

        # Find current instruction index
        current_idx: Optional[int] = None
        for i, insn in enumerate(instructions):
            if insn.address == current_ip:
                current_idx = i
                break

        if current_idx is None:
            # Fall back: disassemble from current IP
            try:
                data = bytes(self._uc.mem_read(current_ip, 64))
                instructions = list(self._cs.disasm(data, current_ip, context * 2))
                current_idx = 0
            except UcError:
                return CodeSnapshot(instructions=[], current_ip=current_ip)

        # Extract context window
        start_idx = max(0, current_idx - context)
        end_idx = min(len(instructions), current_idx + context)
        context_insns = instructions[start_idx:end_idx]

        entries = [
            DisasmEntry(
                address=insn.address,
                raw_bytes=bytes(insn.bytes),
                mnemonic=insn.mnemonic,
                operands=insn.op_str,
            )
            for insn in context_insns
        ]

        return CodeSnapshot(instructions=entries, current_ip=current_ip)

    # ------------------------------------------------------------------
    # Disassembly
    # ------------------------------------------------------------------

    def disassemble(self, address: int, count: int = 10) -> List[DisasmEntry]:
        """Disassemble instructions at a given address.

        Parameters:
            address: Memory address to start disassembling from.
            count: Number of instructions to disassemble.

        Returns:
            List of DisasmEntry objects.

        Raises:
            MemoryAccessError: If the address is unmapped.
        """
        try:
            data = bytes(self._uc.mem_read(address, count * 16))
        except UcError as exc:
            nearest_base, nearest_size = self._find_nearest_region(address)
            raise MemoryAccessError(
                f"Cannot read memory for disassembly at 0x{address:x}: {exc}",
                address=address,
                nearest_base=nearest_base,
                nearest_size=nearest_size,
            ) from exc

        instructions = list(self._cs.disasm(data, address, count))
        return [
            DisasmEntry(
                address=insn.address,
                raw_bytes=bytes(insn.bytes),
                mnemonic=insn.mnemonic,
                operands=insn.op_str,
            )
            for insn in instructions
        ]

    # ------------------------------------------------------------------
    # Memory regions
    # ------------------------------------------------------------------

    def get_memory_regions(self) -> Dict[str, Tuple[int, int]]:
        """Return the mapped memory regions.

        Returns:
            Dict mapping region name (code, stack, data) to (base, size).
        """
        return dict(self._memory_regions)

    # ------------------------------------------------------------------
    # Breakpoint management
    # ------------------------------------------------------------------

    def add_breakpoint(self, address: int) -> None:
        """Add a breakpoint at the specified address.

        Parameters:
            address: Memory address to set the breakpoint at.
        """
        self._breakpoints.add(address)

    def remove_breakpoint(self, address: int) -> None:
        """Remove a breakpoint at the specified address.

        Parameters:
            address: Memory address to remove the breakpoint from.

        Raises:
            KeyError: If no breakpoint exists at the address.
        """
        if address not in self._breakpoints:
            raise KeyError(f"No breakpoint at 0x{address:x}")
        self._breakpoints.discard(address)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _create_engines(self) -> None:
        """Create Unicorn, Capstone, and Keystone engine instances."""
        config = self._arch_config

        # Determine endianness mode bits
        if config.is_little_endian:
            uc_endian = UC_MODE_LITTLE_ENDIAN
            cs_endian = CS_MODE_LITTLE_ENDIAN
            ks_endian = KS_MODE_LITTLE_ENDIAN
        else:
            uc_endian = UC_MODE_BIG_ENDIAN
            cs_endian = CS_MODE_BIG_ENDIAN
            ks_endian = KS_MODE_BIG_ENDIAN

        # Unicorn
        try:
            self._uc = Uc(config.uc_arch, config.uc_mode | uc_endian)
        except (UcError, Exception) as exc:
            raise EngineInitError(
                f"Failed to initialize Unicorn for {config.name}: {exc}",
                engine_name="unicorn",
                arch_config_name=config.name,
            ) from exc

        # Capstone
        try:
            self._cs = Cs(config.cs_arch, config.cs_mode | cs_endian)
        except Exception as exc:
            raise EngineInitError(
                f"Failed to initialize Capstone for {config.name}: {exc}",
                engine_name="capstone",
                arch_config_name=config.name,
            ) from exc

        # Keystone
        try:
            self._ks = Ks(config.ks_arch, config.ks_mode | ks_endian)
        except (KsError, Exception) as exc:
            raise EngineInitError(
                f"Failed to initialize Keystone for {config.name}: {exc}",
                engine_name="keystone",
                arch_config_name=config.name,
            ) from exc

    def _map_memory_regions(self) -> None:
        """Map code, stack, and data memory regions in Unicorn."""
        regions = [
            ("code", self._arch_config.code_base, _REGION_SIZE),
            ("stack", self._arch_config.stack_base, _REGION_SIZE),
            ("data", self._arch_config.data_base, _REGION_SIZE),
        ]

        for name, base, size in regions:
            try:
                self._uc.mem_map(base, size)
                self._memory_regions[name] = (base, size)
            except UcError as exc:
                raise EngineInitError(
                    f"Failed to map {name} memory at 0x{base:x}: {exc}",
                    engine_name="unicorn",
                    arch_config_name=self._arch_config.name,
                ) from exc

    def _init_registers(self) -> None:
        """Set IP to code_base and SP to stack_base + offset."""
        self._uc.reg_write(
            self._arch_config.instruction_pointer_register,
            self._arch_config.code_base,
        )
        self._uc.reg_write(
            self._arch_config.stack_pointer_register,
            self._arch_config.stack_base + _STACK_OFFSET,
        )

    def _execute_direct(self, instruction: str, machine_code: bytes) -> None:
        """Execute machine code in direct mode (temporary buffer)."""
        # Ensure the direct execution buffer is mapped
        if not self._direct_exec_mapped:
            try:
                self._uc.mem_map(_DIRECT_EXEC_ADDR, _DIRECT_EXEC_SIZE)
                self._direct_exec_mapped = True
            except UcError:
                # Already mapped (from a previous session); that's fine
                self._direct_exec_mapped = True

        # Write and execute
        self._uc.mem_write(_DIRECT_EXEC_ADDR, machine_code)
        ip_reg = self._arch_config.instruction_pointer_register
        original_ip = self._uc.reg_read(ip_reg)

        try:
            self._uc.emu_start(_DIRECT_EXEC_ADDR, _DIRECT_EXEC_ADDR + len(machine_code))
        except UcError as exc:
            # Restore IP before raising
            self._uc.reg_write(ip_reg, original_ip)
            self._handle_uc_error(exc, _DIRECT_EXEC_ADDR)

        # Restore original IP (direct mode doesn't advance IP)
        self._uc.reg_write(ip_reg, original_ip)

        self._code_history.append(
            {
                "instruction": instruction,
                "address": _DIRECT_EXEC_ADDR,
                "machine_code": machine_code.hex(),
                "direct_execution": True,
            }
        )

    def _execute_from_memory(self, instruction: str, machine_code: bytes) -> None:
        """Execute machine code from the code region (normal mode)."""
        ip_reg = self._arch_config.instruction_pointer_register
        current_ip = self._uc.reg_read(ip_reg)

        try:
            self._uc.mem_write(current_ip, machine_code)
        except UcError as exc:
            raise MemoryAccessError(
                f"Cannot write instruction at 0x{current_ip:x}: {exc}",
                address=current_ip,
                nearest_base=self._arch_config.code_base,
                nearest_size=_REGION_SIZE,
            ) from exc

        try:
            self._uc.emu_start(current_ip, current_ip + len(machine_code))
        except UcError as exc:
            self._handle_uc_error(exc, current_ip)

        self._code_history.append(
            {
                "instruction": instruction,
                "address": current_ip,
                "machine_code": machine_code.hex(),
                "direct_execution": False,
            }
        )

    def _handle_uc_error(self, exc: UcError, address: int) -> None:
        """Convert a UcError to the appropriate domain exception."""
        msg = str(exc)
        if "UNMAPPED" in msg.upper() or "READ" in msg.upper() or "WRITE" in msg.upper():
            nearest_base, nearest_size = self._find_nearest_region(address)
            raise MemoryAccessError(
                f"Memory access error at 0x{address:x}: {exc}",
                address=address,
                nearest_base=nearest_base,
                nearest_size=nearest_size,
            ) from exc
        # For other Unicorn errors, wrap as MemoryAccessError with context
        nearest_base, nearest_size = self._find_nearest_region(address)
        raise MemoryAccessError(
            f"Execution error at 0x{address:x}: {exc}",
            address=address,
            nearest_base=nearest_base,
            nearest_size=nearest_size,
        ) from exc

    def _find_nearest_region(self, address: int) -> Tuple[int, int]:
        """Find the nearest mapped memory region to an address.

        Returns:
            Tuple of (base, size) for the nearest region, or (0, 0) if
            no regions are mapped.
        """
        if not self._memory_regions:
            return (0, 0)

        nearest_base = 0
        nearest_size = 0
        nearest_dist = float("inf")

        for _name, (base, size) in self._memory_regions.items():
            # Distance is minimum of distance to start or end of region
            dist = min(abs(address - base), abs(address - (base + size)))
            if dist < nearest_dist:
                nearest_dist = dist
                nearest_base = base
                nearest_size = size

        return (nearest_base, nearest_size)

    def _get_flags_info(
        self,
    ) -> Tuple[Optional[str], Optional[Dict[str, int]], Optional[Dict[str, str]]]:
        """Return flag register info for the current architecture.

        Returns:
            Tuple of (flag_register_name, flags_dict, descriptions_dict).
            Any element may be None if the architecture has no flag info.
        """
        arch = self._arch_config.name

        if arch in ("x86", "x64"):
            flag_reg = "eflags" if arch == "x86" else "rflags"
            flags = {
                "CF": 0,
                "PF": 2,
                "AF": 4,
                "ZF": 6,
                "SF": 7,
                "TF": 8,
                "IF": 9,
                "DF": 10,
                "OF": 11,
                "NT": 14,
                "MD": 15,
                "RF": 16,
                "VM": 17,
                "AC": 18,
                "VIF": 19,
                "VIP": 20,
                "ID": 21,
            }
            descriptions = {
                "CF": "Carry",
                "PF": "Parity",
                "AF": "Auxiliary Carry",
                "ZF": "Zero",
                "SF": "Sign",
                "TF": "Trap",
                "IF": "Interrupt Enable",
                "DF": "Direction",
                "OF": "Overflow",
                "NT": "Nested Task",
                "MD": "Mode",
                "RF": "Resume",
                "VM": "Virtual 8086",
                "AC": "Alignment Check",
                "VIF": "Virtual Interrupt",
                "VIP": "Virtual Interrupt Pending",
                "ID": "ID",
            }
            return flag_reg, flags, descriptions

        if arch in ("arm", "arm64"):
            flag_reg = "cpsr" if arch == "arm" else "nzcv"
            flags = {"N": 31, "Z": 30, "C": 29, "V": 28}
            descriptions = {"N": "Negative", "Z": "Zero", "C": "Carry", "V": "Overflow"}
            return flag_reg, flags, descriptions

        if arch in ("mips32", "mips64"):
            flags = {
                "CU0": 28,
                "CU1": 29,
                "CU2": 30,
                "CU3": 31,
                "BEV": 22,
                "ITS": 21,
                "ERL": 2,
                "EXL": 1,
                "IE": 0,
            }
            descriptions = {
                "CU0": "Coprocessor 0 Usable",
                "CU1": "Coprocessor 1 Usable",
                "CU2": "Coprocessor 2 Usable",
                "CU3": "Coprocessor 3 Usable",
                "BEV": "Bootstrap Exception Vector",
                "ITS": "Instruction Trace Support",
                "ERL": "Error Level",
                "EXL": "Exception Level",
                "IE": "Interrupt Enable",
            }
            return "CP0_STATUS", flags, descriptions

        if arch in ("ppc32", "ppc64"):
            flags = {"SO": 31, "EQ": 30, "GT": 29, "LT": 28}
            descriptions = {
                "SO": "Summary Overflow",
                "EQ": "Equal",
                "GT": "Greater Than",
                "LT": "Less Than",
            }
            return "cr", flags, descriptions

        return None, None, None
