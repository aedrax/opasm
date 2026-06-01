# Calculator expression evaluation
"""Property-based tests for Calculator expression evaluation."""

import operator

from hypothesis import given, settings, strategies as st

from opasm.calculator import Calculator


# ---------------------------------------------------------------------------
# Strategy helpers
# ---------------------------------------------------------------------------

# Register name strategy: lowercase identifiers 1-5 chars
_register_names = st.from_regex(r"[a-z][a-z0-9]{0,4}", fullmatch=True)

# Register value strategy: 32-bit unsigned integers
_register_values = st.integers(min_value=0, max_value=0xFFFFFFFF)

# Register dictionaries
_register_dicts = st.dictionaries(
    _register_names, _register_values, min_size=1, max_size=5
)

# Integer literal values (kept reasonable to avoid overflow issues)
_int_values = st.integers(min_value=1, max_value=1000)

# Binary operators (no division - Python's true division produces floats
# that are incompatible with bitwise operators in sub-expressions)
_binary_ops = st.sampled_from(
    [
        ("+", operator.add),
        ("-", operator.sub),
        ("*", operator.mul),
        ("&", operator.and_),
        ("|", operator.or_),
        ("^", operator.xor),
    ]
)

# Shift operators
_shift_ops = st.sampled_from(
    [
        ("<<", operator.lshift),
        (">>", operator.rshift),
    ]
)


@st.composite
def expression_with_expected(draw):
    """Generate an arithmetic expression and its expected result.

    Builds expressions programmatically so we always know the expected value.
    """
    registers = draw(_register_dicts)
    expr, expected = draw(_build_expr(registers, depth=0))
    return expr, expected, registers


@st.composite
def _build_expr(draw, registers, depth):
    """Recursively build an expression with known expected value."""
    # Limit depth to avoid overly complex expressions
    if depth >= 2:
        return draw(_leaf_expr(registers))

    choice = draw(st.integers(min_value=0, max_value=5))

    if choice <= 1:
        # Leaf: integer literal or register reference
        return draw(_leaf_expr(registers))
    elif choice <= 3:
        # Binary arithmetic/bitwise op
        left_expr, left_val = draw(_build_expr(registers, depth + 1))
        right_expr, right_val = draw(_build_expr(registers, depth + 1))
        op_str, op_func = draw(_binary_ops)
        expr_str = f"({left_expr} {op_str} {right_expr})"
        expected = op_func(left_val, right_val)
        return expr_str, expected
    elif choice == 4:
        # Bitwise NOT of a leaf
        sub_expr, sub_val = draw(_leaf_expr(registers))
        expr_str = f"(~{sub_expr})"
        expected = ~sub_val
        return expr_str, expected
    else:
        # Shift operation with controlled amount (0-31)
        left_expr, left_val = draw(_build_expr(registers, depth + 1))
        shift_amount = draw(st.integers(min_value=0, max_value=31))
        op_str, op_func = draw(_shift_ops)
        expr_str = f"({left_expr} {op_str} {shift_amount})"
        expected = op_func(left_val, shift_amount)
        return expr_str, expected


@st.composite
def _leaf_expr(draw, registers):
    """Generate a leaf expression: integer literal (dec or hex) or register ref."""
    choice = draw(st.integers(min_value=0, max_value=2))

    if choice == 0:
        # Decimal integer literal
        val = draw(_int_values)
        return str(val), val
    elif choice == 1:
        # Hex integer literal
        val = draw(_int_values)
        return f"0x{val:x}", val
    else:
        # Register reference
        reg_name = draw(st.sampled_from(sorted(registers.keys())))
        reg_val = registers[reg_name]
        return f"${reg_name}", reg_val


@st.composite
def division_expression(draw):
    """Generate a simple division expression (top-level only).

    Division uses Python's true division (/) which produces floats,
    so we only test it at the top level where int() is applied to the result.
    """
    registers = draw(_register_dicts)
    left_expr, left_val = draw(_leaf_expr(registers))
    # Non-zero divisor
    divisor = draw(st.integers(min_value=1, max_value=100))
    expr_str = f"{left_expr} / {divisor}"
    # The Calculator uses Python eval with `/` (true division) then int()
    expected = int(left_val / divisor)
    return expr_str, expected, registers


# ---------------------------------------------------------------------------
# Calculator expression evaluation
# ---------------------------------------------------------------------------


@settings(max_examples=100)
@given(data=expression_with_expected())
def test_calculator_expression_evaluation(data) -> None:
    """For any arithmetic expression composed of integer literals, register
    references, and operators (+, -, *, &, |, ^, ~, <<, >>), the Calculator
    returns the correct numeric result computed by substituting register values
    and evaluating the expression, without requiring a running Unicorn instance.
    """
    expression, expected, registers = data
    calc = Calculator()
    result = calc.evaluate(expression, registers)
    assert result == expected, (
        f"Expression: {expression}\n"
        f"Registers: {registers}\n"
        f"Expected: {expected}\n"
        f"Got: {result}"
    )


@settings(max_examples=100)
@given(data=division_expression())
def test_calculator_division_evaluation(data) -> None:
    """For division expressions, the Calculator uses true division and
    converts the final result to int, matching Python's int(a / b) semantics.
    """
    expression, expected, registers = data
    calc = Calculator()
    result = calc.evaluate(expression, registers)
    assert result == expected, (
        f"Expression: {expression}\n"
        f"Registers: {registers}\n"
        f"Expected: {expected}\n"
        f"Got: {result}"
    )
