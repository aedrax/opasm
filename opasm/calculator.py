"""Expression evaluator with register-value substitution for Opasm.

Provides arithmetic and bitwise expression evaluation that supports
integer literals (decimal and hexadecimal), register references using
$name syntax, and standard arithmetic/bitwise operators.

Public classes:
    Calculator - Expression evaluator with register-value substitution.
"""

import ast
import operator
import re
from typing import Any

from opasm.exceptions import OpasmError


class CalculationError(OpasmError):
    """Raised when an expression cannot be evaluated.

    Parameters:
        message: Human-readable description of the evaluation failure.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)


class Calculator:
    """Expression evaluator with register-value substitution.

    Evaluates arithmetic and bitwise expressions that may contain
    integer literals (decimal and hex), register references ($name),
    and the operators: +, -, *, /, &, |, ^, ~, <<, >>.

    The calculator does not require a running Unicorn engine instance;
    register values are passed in as a plain dictionary.
    """

    # Pattern matching register references like $eax, $r0, $CP0_STATUS, $r2 (v0)
    _REGISTER_PATTERN: re.Pattern[str] = re.compile(
        r"\$([a-zA-Z_][a-zA-Z0-9_]*(?:\s*\([a-zA-Z0-9_]*\))?)"
    )

    # Pattern matching hexadecimal literals like 0x1A, 0xFF00
    _HEX_PATTERN: re.Pattern[str] = re.compile(r"0x([0-9a-fA-F]+)")

    # Supported binary operators mapped to their implementations
    _BINARY_OPS: dict[type[ast.operator], Any] = {
        ast.Add: operator.add,
        ast.Sub: operator.sub,
        ast.Mult: operator.mul,
        ast.Div: operator.truediv,
        ast.FloorDiv: operator.floordiv,
        ast.BitAnd: operator.and_,
        ast.BitOr: operator.or_,
        ast.BitXor: operator.xor,
        ast.LShift: operator.lshift,
        ast.RShift: operator.rshift,
    }

    # Supported unary operators
    _UNARY_OPS: dict[type[ast.unaryop], Any] = {
        ast.UAdd: operator.pos,
        ast.USub: operator.neg,
        ast.Invert: operator.invert,
    }

    def evaluate(self, expression: str, registers: dict[str, int]) -> int:
        """Evaluate an arithmetic/bitwise expression with register substitution.

        Substitutes $register_name references with values from the registers
        dictionary, converts hex literals to decimal, and evaluates the
        resulting expression using standard Python arithmetic.

        Args:
            expression: The expression string to evaluate. May contain:
                - Integer literals (decimal: 42, hex: 0xFF)
                - Register references ($eax, $rsp, etc.)
                - Operators: +, -, *, /, &, |, ^, ~, <<, >>
                - Parentheses for grouping
            registers: Dictionary mapping register names (lowercase) to
                their current integer values.

        Returns:
            The integer result of the evaluated expression.

        Raises:
            CalculationError: If the expression contains unknown registers,
                invalid characters, invalid syntax, or division by zero.
        """
        try:
            # Remove leading/trailing whitespace
            expr = expression.strip()

            # Replace register references with their values
            expr = self._substitute_registers(expr, registers)

            # Convert hex literals to decimal strings
            expr = self._HEX_PATTERN.sub(lambda m: str(int(m.group(1), 16)), expr)

            # Parse into AST and evaluate safely
            tree = ast.parse(expr, mode="eval")
            result = self._eval_node(tree.body)

            # Ensure result is an integer
            if isinstance(result, float):
                return int(result)
            return result

        except ZeroDivisionError as exc:
            raise CalculationError("Division by zero") from exc
        except CalculationError:
            raise
        except SyntaxError as exc:
            raise CalculationError("Invalid expression syntax") from exc
        except Exception as e:
            raise CalculationError(f"Calculation error: {e}") from e

    def _eval_node(self, node: ast.expr) -> int | float:
        """Recursively evaluate an AST node using only allowed operations.

        Args:
            node: An AST expression node.

        Returns:
            The numeric result of evaluating the node.

        Raises:
            CalculationError: If the node contains unsupported operations.
        """
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return node.value

        if isinstance(node, ast.BinOp):
            op_func = self._BINARY_OPS.get(type(node.op))
            if op_func is None:
                raise CalculationError(
                    f"Unsupported operator: {type(node.op).__name__}"
                )
            left = self._eval_node(node.left)
            right = self._eval_node(node.right)
            return op_func(left, right)

        if isinstance(node, ast.UnaryOp):
            op_func = self._UNARY_OPS.get(type(node.op))
            if op_func is None:
                raise CalculationError(
                    f"Unsupported unary operator: {type(node.op).__name__}"
                )
            operand = self._eval_node(node.operand)
            return op_func(operand)

        raise CalculationError("Expression contains unsupported operations")

    def parse_value(self, value_str: str, registers: dict[str, int]) -> int:
        """Parse a single value: decimal int, hex int, or register reference.

        Args:
            value_str: A string representing a single value. Can be:
                - A decimal integer (e.g., "42", "-7")
                - A hexadecimal integer (e.g., "0xFF", "0x1A")
                - A register reference (e.g., "$eax", "$r0")
            registers: Dictionary mapping register names (lowercase) to
                their current integer values.

        Returns:
            The integer value parsed from the string.

        Raises:
            CalculationError: If the value cannot be parsed as any of the
                supported formats or references an unknown register.
        """
        value_str = value_str.strip()

        # Check for register reference
        if value_str.startswith("$"):
            reg_name = value_str[1:].lower()
            if reg_name in registers:
                return registers[reg_name]
            else:
                raise CalculationError(f"Unknown register: {reg_name}")

        # Check for hex literal
        if value_str.lower().startswith("0x"):
            try:
                return int(value_str, 16)
            except ValueError as exc:
                raise CalculationError(
                    f"Invalid hexadecimal literal: {value_str}"
                ) from exc

        # Try decimal integer
        try:
            return int(value_str)
        except ValueError as exc:
            raise CalculationError(f"Cannot parse value: {value_str}") from exc

    def _substitute_registers(self, expression: str, registers: dict[str, int]) -> str:
        """Replace $register_name references with their integer values.

        Args:
            expression: The expression containing register references.
            registers: Dictionary mapping register names to values.

        Returns:
            The expression with all register references replaced by
            their numeric string equivalents.

        Raises:
            CalculationError: If a referenced register is not found in
                the registers dictionary.
        """

        def replace_register(match: re.Match[str]) -> str:
            reg_name = match.group(1).lower().strip()
            # Handle register names with parentheses like "r2 (v0)"
            # Normalize by removing internal spaces for lookup
            if reg_name in registers:
                return str(registers[reg_name])
            # Try with spaces normalized
            normalized = re.sub(r"\s+", " ", reg_name)
            if normalized in registers:
                return str(registers[normalized])
            raise CalculationError(f"Unknown register: {reg_name}")

        return self._REGISTER_PATTERN.sub(replace_register, expression)
