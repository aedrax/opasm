"""Integration tests for end-to-end command equivalence."""

import json
import os
import tempfile

import pytest

from opasm.architectures import get_architecture
from opasm.calculator import Calculator
from opasm.display import DisplayRenderer
from opasm.engine import EngineManager
from opasm.exceptions import (
    AssemblyError,
    FileOperationError,
    MemoryAccessError,
)
from opasm.state import StateManager


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def x64_engine():
    """Create an initialized x64 EngineManager."""
    arch = get_architecture("x64")
    engine = EngineManager(arch)
    engine.initialize()
    return engine


@pytest.fixture
def state_mgr(x64_engine):
    """Create a StateManager connected to the x64 engine."""
    return StateManager(x64_engine)


@pytest.fixture
def calculator():
    """Create a Calculator instance."""
    return Calculator()


@pytest.fixture
def display():
    """Create a DisplayRenderer instance."""
    from rich.console import Console

    console = Console(file=open(os.devnull, "w"))
    return DisplayRenderer(console=console)


# ---------------------------------------------------------------------------
# 1. Command execution through refactored modules
# ---------------------------------------------------------------------------


class TestAssembleAndExecute:
    """Test assembling and executing instructions via EngineManager."""

    def test_assemble_and_execute_mov_rax(self, x64_engine):
        """1a. Assemble 'mov rax, 42' and verify rax == 42."""
        x64_engine.assemble_and_execute("mov rax, 42")
        assert x64_engine.read_register("rax") == 42

    def test_assemble_and_execute_mov_rbx_hex(self, x64_engine):
        """Assemble 'mov rbx, 0xFF' and verify rbx == 255."""
        x64_engine.assemble_and_execute("mov rbx, 0xFF")
        assert x64_engine.read_register("rbx") == 255


class TestArchitectureSwitching:
    """Test architecture switching via EngineManager."""

    def test_switch_to_arm(self, x64_engine):
        """1b. Switch to ARM architecture and verify engine is arm."""
        arm_config = get_architecture("arm")
        x64_engine.switch_architecture(arm_config)
        assert x64_engine.current_arch_name == "arm"

    def test_switch_to_arm64(self, x64_engine):
        """Switch to ARM64 and verify architecture name."""
        arm64_config = get_architecture("arm64")
        x64_engine.switch_architecture(arm64_config)
        assert x64_engine.current_arch_name == "arm64"

    def test_switch_preserves_clean_state(self, x64_engine):
        """After switching, breakpoints and history are cleared."""
        x64_engine.add_breakpoint(0x400010)
        x64_engine.assemble_and_execute("nop")

        arm_config = get_architecture("arm")
        x64_engine.switch_architecture(arm_config)

        assert len(x64_engine.breakpoints) == 0
        assert len(x64_engine.code_history) == 0


class TestRegisterReadWrite:
    """Test register read/write operations."""

    def test_set_and_read_register(self, x64_engine):
        """1c. Write 0x100 to rax, read back, verify value."""
        x64_engine.write_register("rax", 0x100)
        assert x64_engine.read_register("rax") == 0x100

    def test_set_register_case_insensitive(self, x64_engine):
        """Register names are case-insensitive."""
        x64_engine.write_register("RAX", 0x200)
        assert x64_engine.read_register("rax") == 0x200

    def test_read_unknown_register_raises(self, x64_engine):
        """Reading unknown register raises KeyError."""
        with pytest.raises(KeyError):
            x64_engine.read_register("nonexistent")


class TestMemoryReadWrite:
    """Test memory read/write operations."""

    def test_write_and_read_memory(self, x64_engine):
        """1d. Write bytes at data_base, read back, verify."""
        data_base = x64_engine.arch_config.data_base
        test_data = b"\x41\x42\x43\x44"
        x64_engine.write_memory(data_base, test_data)
        result = x64_engine.read_memory(data_base, 4)
        assert result == test_data

    def test_write_and_read_larger_block(self, x64_engine):
        """Write and read a 64-byte block."""
        data_base = x64_engine.arch_config.data_base
        test_data = bytes(range(64))
        x64_engine.write_memory(data_base, test_data)
        result = x64_engine.read_memory(data_base, 64)
        assert result == test_data


class TestBreakpointManagement:
    """Test breakpoint add/list/remove."""

    def test_add_and_list_breakpoints(self, x64_engine):
        """1e. Add breakpoints, verify they appear in the set."""
        code_base = x64_engine.arch_config.code_base
        x64_engine.add_breakpoint(code_base + 0x10)
        x64_engine.add_breakpoint(code_base + 0x20)

        bps = x64_engine.breakpoints
        assert (code_base + 0x10) in bps
        assert (code_base + 0x20) in bps
        assert len(bps) == 2

    def test_remove_breakpoint(self, x64_engine):
        """Remove a breakpoint and verify it's gone."""
        code_base = x64_engine.arch_config.code_base
        x64_engine.add_breakpoint(code_base + 0x10)
        x64_engine.add_breakpoint(code_base + 0x20)
        x64_engine.remove_breakpoint(code_base + 0x10)

        bps = x64_engine.breakpoints
        assert (code_base + 0x10) not in bps
        assert (code_base + 0x20) in bps

    def test_remove_nonexistent_breakpoint_raises(self, x64_engine):
        """Removing nonexistent breakpoint raises KeyError."""
        with pytest.raises(KeyError):
            x64_engine.remove_breakpoint(0xDEADBEEF)


class TestReset:
    """Test engine reset to clean state."""

    def test_reset_clears_state(self, x64_engine):
        """1f. After breakpoints and execution, reset restores clean state."""
        code_base = x64_engine.arch_config.code_base
        stack_base = x64_engine.arch_config.stack_base

        # Dirty the state
        x64_engine.add_breakpoint(code_base + 0x10)
        x64_engine.assemble_and_execute("mov rax, 99")
        x64_engine.write_register("rbx", 0xDEAD)

        # Reset
        x64_engine.reset()

        # Verify clean state
        assert len(x64_engine.breakpoints) == 0
        assert len(x64_engine.code_history) == 0

        # IP should be at code_base
        ip_value = x64_engine.read_register("rip")
        assert ip_value == code_base

        # SP should be at stack_base + 0x80000
        sp_value = x64_engine.read_register("rsp")
        assert sp_value == stack_base + 0x80000


class TestStateSaveLoad:
    """Test state save and load operations."""

    def test_save_and_load_state(self, x64_engine, state_mgr):
        """1g. Save state, modify engine, load state, verify restored."""
        # Set up some state
        x64_engine.write_register("rax", 0x1234)
        x64_engine.write_register("rbx", 0x5678)
        x64_engine.add_breakpoint(x64_engine.arch_config.code_base + 0x10)

        data_base = x64_engine.arch_config.data_base
        x64_engine.write_memory(data_base, b"\xaa\xbb\xcc\xdd")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            tmp_path = f.name

        try:
            # Save state
            state_mgr.save(tmp_path)

            # Modify state
            x64_engine.write_register("rax", 0)
            x64_engine.write_register("rbx", 0)
            x64_engine.remove_breakpoint(x64_engine.arch_config.code_base + 0x10)
            x64_engine.write_memory(data_base, b"\x00\x00\x00\x00")

            # Load state
            state_mgr.load(tmp_path)

            # Verify restored
            assert x64_engine.read_register("rax") == 0x1234
            assert x64_engine.read_register("rbx") == 0x5678
            assert (x64_engine.arch_config.code_base + 0x10) in x64_engine.breakpoints

            restored_mem = x64_engine.read_memory(data_base, 4)
            assert restored_mem == b"\xaa\xbb\xcc\xdd"
        finally:
            os.unlink(tmp_path)


class TestCalculator:
    """Test calculator expression evaluation."""

    def test_simple_addition(self, calculator):
        """1h. Evaluate '1 + 2' and verify result == 3."""
        result = calculator.evaluate("1 + 2", {})
        assert result == 3

    def test_hex_arithmetic(self, calculator):
        """Evaluate hex expressions."""
        result = calculator.evaluate("0x10 + 0x20", {})
        assert result == 0x30

    def test_register_substitution(self, calculator):
        """Evaluate expressions with register references."""
        regs = {"rax": 100, "rbx": 50}
        result = calculator.evaluate("$rax + $rbx", regs)
        assert result == 150

    def test_bitwise_operations(self, calculator):
        """Evaluate bitwise operations."""
        result = calculator.evaluate("0xFF & 0x0F", {})
        assert result == 0x0F


class TestDirectMode:
    """Test direct assembly mode execution."""

    def test_direct_mode_execution(self, x64_engine):
        """1i. Direct execution mode doesn't advance IP."""
        code_base = x64_engine.arch_config.code_base
        ip_before = x64_engine.read_register("rip")
        assert ip_before == code_base

        # Execute in direct mode
        x64_engine.assemble_and_execute("mov rax, 77", direct=True)

        # IP should be unchanged
        ip_after = x64_engine.read_register("rip")
        assert ip_after == code_base

        # But rax should be modified
        assert x64_engine.read_register("rax") == 77

    def test_normal_mode_advances_ip(self, x64_engine):
        """Normal mode advances IP past the instruction."""
        code_base = x64_engine.arch_config.code_base
        ip_before = x64_engine.read_register("rip")
        assert ip_before == code_base

        x64_engine.assemble_and_execute("mov rax, 42", direct=False)

        # IP should have advanced
        ip_after = x64_engine.read_register("rip")
        assert ip_after > code_base


# ---------------------------------------------------------------------------
# 2. State file interop
# ---------------------------------------------------------------------------


class TestStateFileInterop:
    """Test loading state files in the format the original version produces."""

    def test_load_original_format_state(self, x64_engine):
        """Load a state dict in original format and verify restoration."""
        arch = get_architecture("x64")
        code_base = arch.code_base
        data_base = arch.data_base
        stack_base = arch.stack_base

        # Create a state dict matching original version's output format
        state_data = {
            "version": 1,
            "architecture": "x64",
            "registers": {
                "rax": 0x42,
                "rbx": 0x100,
                "rcx": 0,
                "rdx": 0,
                "rsi": 0,
                "rdi": 0,
                "rsp": stack_base + 0x80000,
                "rbp": 0,
                "r8": 0,
                "r9": 0,
                "r10": 0,
                "r11": 0,
                "r12": 0,
                "r13": 0,
                "r14": 0,
                "r15": 0,
                "rip": code_base + 7,
                "rflags": 0,
            },
            "memory_regions": {
                "code": {
                    "base": code_base,
                    "size": 0x100000,
                    "data": "48c7c04200000090" + "00" * (0x100000 - 8),
                },
                "stack": {
                    "base": stack_base,
                    "size": 0x100000,
                    "data": "00" * 0x100000,
                },
                "data": {
                    "base": data_base,
                    "size": 0x100000,
                    "data": "deadbeef" + "00" * (0x100000 - 4),
                },
            },
            "code_history": [
                {
                    "instruction": "mov rax, 0x42",
                    "address": code_base,
                    "machine_code": "48c7c042000000",
                    "direct_execution": False,
                }
            ],
            "breakpoints": [code_base + 0x10, code_base + 0x20],
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(state_data, f)
            tmp_path = f.name

        try:
            state_mgr = StateManager(x64_engine)
            state_mgr.load(tmp_path)

            # Verify all values are correctly restored
            assert x64_engine.read_register("rax") == 0x42
            assert x64_engine.read_register("rbx") == 0x100
            assert x64_engine.read_register("rip") == code_base + 7

            # Verify breakpoints
            bps = x64_engine.breakpoints
            assert (code_base + 0x10) in bps
            assert (code_base + 0x20) in bps

            # Verify code history
            history = x64_engine.code_history
            assert len(history) == 1
            assert history[0]["instruction"] == "mov rax, 0x42"
            assert history[0]["address"] == code_base

            # Verify data memory
            data_mem = x64_engine.read_memory(data_base, 4)
            assert data_mem == bytes.fromhex("deadbeef")
        finally:
            os.unlink(tmp_path)

    def test_load_state_with_different_architecture(self, x64_engine):
        """Load state file that specifies ARM architecture triggers switch."""
        state_data = {
            "version": 1,
            "architecture": "arm",
            "registers": {"r0": 0x10, "r1": 0x20},
            "memory_regions": {},
            "code_history": [],
            "breakpoints": [],
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(state_data, f)
            tmp_path = f.name

        try:
            state_mgr = StateManager(x64_engine)
            state_mgr.load(tmp_path)

            # Architecture should have switched
            assert x64_engine.current_arch_name == "arm"

            # Registers should be restored
            assert x64_engine.read_register("r0") == 0x10
            assert x64_engine.read_register("r1") == 0x20
        finally:
            os.unlink(tmp_path)


# ---------------------------------------------------------------------------
# 3. Error format
# ---------------------------------------------------------------------------


class TestErrorFormat:
    """Verify that errors use 'error: <description>' prefix format."""

    def test_display_print_error_format(self, display):
        """DisplayRenderer.print_error uses 'error: ' prefix."""
        from io import StringIO
        from rich.console import Console

        output = StringIO()
        console = Console(file=output, no_color=True)
        renderer = DisplayRenderer(console=console)

        renderer.print_error("something went wrong")
        text = output.getvalue()
        assert "error: something went wrong" in text

    def test_assembly_error_message(self, x64_engine):
        """AssemblyError is raised for invalid instructions."""
        with pytest.raises(AssemblyError) as exc_info:
            x64_engine.assemble("not_a_valid_instruction blah blah")
        # The error message should contain useful context
        assert (
            "not_a_valid_instruction" in str(exc_info.value).lower()
            or "assembly" in str(exc_info.value).lower()
            or "failed" in str(exc_info.value).lower()
        )

    def test_memory_access_error(self, x64_engine):
        """MemoryAccessError is raised for unmapped memory access."""
        with pytest.raises(MemoryAccessError):
            x64_engine.read_memory(0xDEAD0000, 4)

    def test_state_load_invalid_json(self, x64_engine):
        """Loading invalid JSON raises FileOperationError."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("not valid json {{{{")
            tmp_path = f.name

        try:
            state_mgr = StateManager(x64_engine)
            with pytest.raises(FileOperationError) as exc_info:
                state_mgr.load(tmp_path)
            assert (
                "json" in str(exc_info.value).lower()
                or "invalid" in str(exc_info.value).lower()
            )
        finally:
            os.unlink(tmp_path)

    def test_state_load_missing_keys(self, x64_engine):
        """Loading state with missing keys raises FileOperationError."""
        state_data = {
            "version": 1,
            "architecture": "x64",
            # Missing: registers, memory_regions, code_history, breakpoints
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(state_data, f)
            tmp_path = f.name

        try:
            state_mgr = StateManager(x64_engine)
            with pytest.raises(FileOperationError) as exc_info:
                state_mgr.load(tmp_path)
            assert (
                "missing" in str(exc_info.value).lower()
                or "required" in str(exc_info.value).lower()
            )
        finally:
            os.unlink(tmp_path)

    def test_state_load_unsupported_version(self, x64_engine):
        """Loading state with unsupported version raises FileOperationError."""
        state_data = {
            "version": 999,
            "architecture": "x64",
            "registers": {},
            "memory_regions": {},
            "code_history": [],
            "breakpoints": [],
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(state_data, f)
            tmp_path = f.name

        try:
            state_mgr = StateManager(x64_engine)
            with pytest.raises(FileOperationError) as exc_info:
                state_mgr.load(tmp_path)
            assert (
                "version" in str(exc_info.value).lower()
                or "unsupported" in str(exc_info.value).lower()
            )
        finally:
            os.unlink(tmp_path)

    def test_errors_do_not_modify_engine_state(self, x64_engine):
        """Failed operations preserve engine state."""
        # Set known state
        x64_engine.write_register("rax", 0xBEEF)
        original_rax = x64_engine.read_register("rax")

        # Attempt invalid assembly - should not modify state
        with pytest.raises(AssemblyError):
            x64_engine.assemble_and_execute("invalid_instruction_xyz")

        # State should be unchanged
        assert x64_engine.read_register("rax") == original_rax
