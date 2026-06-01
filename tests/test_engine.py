"""Property-based test verifying that EngineManager.reset() restores initial state.

After dirtying the engine state (writing registers, adding breakpoints, executing
instructions), calling reset() must restore IP to code_base, SP to
stack_base + 0x80000, and clear breakpoints and code history.
"""

from hypothesis import given, settings, strategies as st

from opasm.architectures import ArchConfig, get_architecture, list_architectures
from opasm.engine import EngineManager


_STACK_OFFSET = 0x80000


@settings(max_examples=100)
@given(arch_name=st.sampled_from(list_architectures()))
def test_engine_reset_to_initial_state(arch_name: str) -> None:
    """After dirtying state and calling reset(), engine returns to initial state.

    For any supported architecture, after modifying registers, adding breakpoints,
    and executing instructions, reset() must restore:
    - IP == arch_config.code_base
    - SP == arch_config.stack_base + 0x80000
    - breakpoints set is empty
    - code_history is empty
    """
    arch_config: ArchConfig = get_architecture(arch_name)
    engine = EngineManager(arch_config)
    engine.initialize()

    # --- Dirty the state ---

    # Add breakpoints at various offsets within the code region
    engine.add_breakpoint(arch_config.code_base + 0x10)
    engine.add_breakpoint(arch_config.code_base + 0x20)
    engine.add_breakpoint(arch_config.code_base + 0x30)

    # Write a non-zero value to the stack pointer register to dirty it
    engine.write_register(
        _get_sp_register_name(arch_config),
        arch_config.stack_base + 0x1000,
    )

    # Try to assemble and execute a simple instruction to dirty code_history.
    # Not all architectures may succeed, so we use a try/except.
    _try_execute_instruction(engine, arch_config)

    # Verify state is actually dirty before reset
    assert len(engine.breakpoints) > 0, "Breakpoints should be non-empty before reset"

    # --- Reset ---
    engine.reset()

    # --- Verify initial state ---
    ip_value = engine.read_register(_get_ip_register_name(arch_config))
    sp_value = engine.read_register(_get_sp_register_name(arch_config))

    assert ip_value == arch_config.code_base, (
        f"After reset, IP should be {arch_config.code_base:#x} "
        f"but got {ip_value:#x} for arch {arch_name}"
    )
    assert sp_value == arch_config.stack_base + _STACK_OFFSET, (
        f"After reset, SP should be {arch_config.stack_base + _STACK_OFFSET:#x} "
        f"but got {sp_value:#x} for arch {arch_name}"
    )
    assert engine.breakpoints == set(), (
        f"After reset, breakpoints should be empty but got {engine.breakpoints} "
        f"for arch {arch_name}"
    )
    assert engine.code_history == [], (
        f"After reset, code_history should be empty but got {engine.code_history} "
        f"for arch {arch_name}"
    )


def _get_ip_register_name(arch_config: ArchConfig) -> str:
    """Find the register name corresponding to the instruction pointer."""
    for name, reg_id in arch_config.registers.items():
        if reg_id == arch_config.instruction_pointer_register:
            return name
    raise ValueError(f"No IP register found for {arch_config.name}")


def _get_sp_register_name(arch_config: ArchConfig) -> str:
    """Find the register name corresponding to the stack pointer."""
    for name, reg_id in arch_config.registers.items():
        if reg_id == arch_config.stack_pointer_register:
            return name
    raise ValueError(f"No SP register found for {arch_config.name}")


def _try_execute_instruction(engine: EngineManager, arch_config: ArchConfig) -> None:
    """Attempt to execute a NOP-like instruction to dirty code history."""
    # Architecture-specific simple instructions
    nop_instructions = {
        "x86": "nop",
        "x64": "nop",
        "arm": "nop",
        "arm64": "nop",
        "mips32": "nop",
        "mips64": "nop",
        "ppc32": "nop",
        "ppc64": "nop",
    }
    instruction = nop_instructions.get(arch_config.name)
    if instruction:
        try:
            engine.assemble_and_execute(instruction)
        except Exception:
            # If execution fails for any reason, that's acceptable -
            # the point is to attempt dirtying the state.
            pass
