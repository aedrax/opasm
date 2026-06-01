"""Property-based tests for Architecture_Registry shared base register equivalence."""

from hypothesis import given, settings, strategies as st

from opasm.architectures import ARCHITECTURES


# ---------------------------------------------------------------------------
# Shared base register equivalence
# ---------------------------------------------------------------------------

# PPC family: ppc32 and ppc64 must share identical register keys and values
_ppc32_registers = ARCHITECTURES["ppc32"].registers
_ppc64_registers = ARCHITECTURES["ppc64"].registers
_ppc_register_names = sorted(_ppc32_registers.keys())

# MIPS family: mips32 and mips64 must share identical register keys and values
_mips32_registers = ARCHITECTURES["mips32"].registers
_mips64_registers = ARCHITECTURES["mips64"].registers
_mips_register_names = sorted(_mips32_registers.keys())


@settings(max_examples=100)
@given(reg_name=st.sampled_from(_ppc_register_names))
def test_ppc_shared_base_register_equivalence(reg_name: str) -> None:
    """For any register in the PPC family, ppc32 and ppc64 map it to the same constant."""
    assert reg_name in _ppc32_registers, f"Register '{reg_name}' missing from ppc32"
    assert reg_name in _ppc64_registers, f"Register '{reg_name}' missing from ppc64"
    assert _ppc32_registers[reg_name] == _ppc64_registers[reg_name], (
        f"PPC register '{reg_name}' differs: "
        f"ppc32={_ppc32_registers[reg_name]}, ppc64={_ppc64_registers[reg_name]}"
    )


@settings(max_examples=100)
@given(reg_name=st.sampled_from(_mips_register_names))
def test_mips_shared_base_register_equivalence(reg_name: str) -> None:
    """For any register in the MIPS family, mips32 and mips64 map it to the same constant."""
    assert reg_name in _mips32_registers, f"Register '{reg_name}' missing from mips32"
    assert reg_name in _mips64_registers, f"Register '{reg_name}' missing from mips64"
    assert _mips32_registers[reg_name] == _mips64_registers[reg_name], (
        f"MIPS register '{reg_name}' differs: "
        f"mips32={_mips32_registers[reg_name]}, mips64={_mips64_registers[reg_name]}"
    )


def test_ppc_families_have_same_keys() -> None:
    """PPC32 and PPC64 register dicts contain the exact same set of keys."""
    assert set(_ppc32_registers.keys()) == set(_ppc64_registers.keys())


def test_mips_families_have_same_keys() -> None:
    """MIPS32 and MIPS64 register dicts contain the exact same set of keys."""
    assert set(_mips32_registers.keys()) == set(_mips64_registers.keys())
