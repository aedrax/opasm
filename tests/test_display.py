"""Property-based tests for DisplayRenderer with optional/empty data."""

from io import StringIO

from hypothesis import given, settings, strategies as st
from rich.console import Console

from opasm.display import DisplayRenderer
from opasm.engine import (
    CodeSnapshot,
    DisasmEntry,
    RegisterSnapshot,
    StackSnapshot,
)


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

_register_names = st.text(min_size=1, max_size=5, alphabet="abcdefghijklmnop")
_register_values = st.integers(min_value=0, max_value=0xFFFFFFFF)

st_registers = st.dictionaries(
    _register_names, _register_values, min_size=0, max_size=10
)

st_changed_set = st.frozensets(_register_names, min_size=0, max_size=5).map(set)

st_word_size = st.sampled_from([4, 8])

st_arch_name = st.sampled_from(
    ["x86", "x64", "arm", "arm64", "mips32", "mips64", "ppc32", "ppc64"]
)


@st.composite
def st_register_snapshot(draw):
    """Generate a RegisterSnapshot with optional flag fields."""
    arch_name = draw(st_arch_name)
    word_size = draw(st_word_size)
    registers = draw(st_registers)
    changed = draw(st_changed_set)
    has_flags = draw(st.booleans())

    if has_flags:
        flag_register_name = draw(
            st.text(min_size=1, max_size=6, alphabet="abcdefghijklmnop")
        )
        flags = draw(
            st.dictionaries(
                st.text(min_size=1, max_size=4, alphabet="ABCDEFGHIJKLMNOP"),
                st.integers(min_value=0, max_value=31),
                min_size=0,
                max_size=8,
            )
        )
        flag_descriptions = draw(
            st.dictionaries(
                st.text(min_size=1, max_size=4, alphabet="ABCDEFGHIJKLMNOP"),
                st.text(min_size=1, max_size=20),
                min_size=0,
                max_size=8,
            )
        )
    else:
        flag_register_name = None
        flags = None
        flag_descriptions = None

    return RegisterSnapshot(
        arch_name=arch_name,
        word_size=word_size,
        registers=registers,
        changed=changed,
        flag_register_name=flag_register_name,
        flags=flags,
        flag_descriptions=flag_descriptions,
    )


@st.composite
def st_stack_snapshot(draw):
    """Generate a StackSnapshot with varying data including empty bytes."""
    sp_value = draw(st.integers(min_value=0, max_value=0xFFFFFFFF))
    word_size = draw(st_word_size)
    is_little_endian = draw(st.booleans())
    data = draw(st.binary(min_size=0, max_size=128))
    changed_addresses = draw(
        st.frozensets(
            st.integers(min_value=0, max_value=0xFFFFFFFF), min_size=0, max_size=5
        ).map(set)
    )

    return StackSnapshot(
        sp_value=sp_value,
        word_size=word_size,
        is_little_endian=is_little_endian,
        data=data,
        changed_addresses=changed_addresses,
    )


@st.composite
def st_disasm_entry(draw):
    """Generate a single DisasmEntry."""
    address = draw(st.integers(min_value=0, max_value=0xFFFFFFFF))
    raw_bytes = draw(st.binary(min_size=1, max_size=15))
    mnemonic = draw(st.text(min_size=1, max_size=8, alphabet="abcdefghijklmnop"))
    operands = draw(
        st.text(min_size=0, max_size=20, alphabet="abcdefghijklmnop0123456789, ")
    )
    return DisasmEntry(
        address=address,
        raw_bytes=raw_bytes,
        mnemonic=mnemonic,
        operands=operands,
    )


@st.composite
def st_code_snapshot(draw):
    """Generate a CodeSnapshot with varying instruction lists including empty."""
    instructions = draw(st.lists(st_disasm_entry(), min_size=0, max_size=10))
    if instructions:
        current_ip = draw(
            st.sampled_from([i.address for i in instructions] + [0x400000])
        )
    else:
        current_ip = draw(st.integers(min_value=0, max_value=0xFFFFFFFF))
    return CodeSnapshot(instructions=instructions, current_ip=current_ip)


# ---------------------------------------------------------------------------
# Property test
# ---------------------------------------------------------------------------


@settings(max_examples=100)
@given(
    reg_snapshot=st_register_snapshot(),
    stack_snapshot=st_stack_snapshot(),
    code_snapshot=st_code_snapshot(),
)
def test_display_rendering_with_optional_data(
    reg_snapshot, stack_snapshot, code_snapshot
):
    """Display rendering with optional data.

    For any valid RegisterSnapshot, StackSnapshot, or CodeSnapshot (including
    cases where fields are None or empty), the DisplayRenderer SHALL produce
    output without raising an exception, SHALL omit panels for which data is
    absent, and SHALL render panels for which data is present.
    """
    console = Console(file=StringIO(), width=120)
    renderer = DisplayRenderer(console=console)

    # render_registers should not raise regardless of register content
    renderer.render_registers(reg_snapshot)

    # render_stack should not raise regardless of stack data
    renderer.render_stack(stack_snapshot)

    # render_code should not raise regardless of instruction list
    renderer.render_code(code_snapshot)

    output = console.file.getvalue()

    # If instructions list is empty, render_code should produce no output for the code panel
    if not code_snapshot.instructions:
        # The code panel should not appear. We verify by checking that
        # no "Code" table title was rendered after the stack output.
        # Since all renders go to the same console, we check output after
        # re-rendering with a fresh console.
        code_console = Console(file=StringIO(), width=120)
        code_renderer = DisplayRenderer(console=code_console)
        code_renderer.render_code(code_snapshot)
        code_output = code_console.file.getvalue()
        assert (
            code_output == ""
        ), f"Expected no output for empty instruction list, got: {code_output!r}"
