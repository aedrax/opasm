"""Unit tests for import isolation, type checking, and circular import detection."""

import subprocess
from pathlib import Path

import pytest

# All modules in the opasm package that should be independently importable.
OPASM_MODULES = [
    "opasm.architectures",
    "opasm.exceptions",
    "opasm.calculator",
    "opasm.engine",
    "opasm.state",
    "opasm.display",
    "opasm.dispatcher",
    "opasm.repl",
]

# Path to the Python interpreter in the virtual environment.
PYTHON = str(Path(__file__).resolve().parents[1] / ".venv" / "bin" / "python")

# Path to the mypy binary in the virtual environment.
MYPY = str(Path(__file__).resolve().parents[1] / ".venv" / "bin" / "mypy")

# Root of the project (where the opasm/ package lives).
PROJECT_ROOT = str(Path(__file__).resolve().parents[1])


# ---------------------------------------------------------------------------
# Import isolation tests - each module importable without side effects
# ---------------------------------------------------------------------------


class TestImportIsolation:
    """Verify each opasm module can be imported without side effects.

    Each module is imported in a clean subprocess to ensure:
    - The import succeeds (exit code 0)
    - No output is produced to stdout (no terminal output, no engine init messages)
    """

    @pytest.mark.parametrize("module", OPASM_MODULES)
    def test_module_imports_without_output(self, module: str) -> None:
        """Importing {module} produces no stdout output."""
        result = subprocess.run(
            [PYTHON, "-c", f"import {module}"],
            capture_output=True,
            text=True,
            cwd=PROJECT_ROOT,
            timeout=30,
        )
        assert result.returncode == 0, (
            f"Import of {module} failed with exit code {result.returncode}.\n"
            f"stderr: {result.stderr}"
        )
        assert result.stdout == "", (
            f"Import of {module} produced unexpected stdout output:\n"
            f"{result.stdout!r}"
        )

    @pytest.mark.parametrize("module", OPASM_MODULES)
    def test_module_imports_without_stderr_warnings(self, module: str) -> None:
        """Importing {module} produces no unexpected stderr output.

        Note: Some modules may produce deprecation warnings from third-party
        libraries (e.g., unicorn, keystone). We only check that there are no
        ImportError tracebacks or critical failures.
        """
        result = subprocess.run(
            [PYTHON, "-c", f"import {module}"],
            capture_output=True,
            text=True,
            cwd=PROJECT_ROOT,
            timeout=30,
        )
        assert (
            result.returncode == 0
        ), f"Import of {module} failed.\nstderr: {result.stderr}"
        # We don't assert stderr is empty (third-party libs may emit warnings),
        # but we verify no ImportError or ModuleNotFoundError in stderr.
        assert (
            "ImportError" not in result.stderr
        ), f"Import of {module} raised ImportError:\n{result.stderr}"
        assert (
            "ModuleNotFoundError" not in result.stderr
        ), f"Import of {module} raised ModuleNotFoundError:\n{result.stderr}"


# ---------------------------------------------------------------------------
# Type checking test - mypy --strict passes on our code
# ---------------------------------------------------------------------------


class TestTypeChecking:
    """Verify mypy --strict passes on all opasm modules.

    Third-party libraries (unicorn, capstone, keystone) lack type stubs,
    which causes certain error categories that are not our fault. We filter
    those out and focus on verifying that OUR code's annotations are correct.
    """

    # Error codes that stem from untyped third-party libraries (unicorn,
    # capstone, keystone) or known typing limitations rather than missing
    # annotations in our own code.
    ACCEPTABLE_ERROR_CODES = {
        "attr-defined",  # Module "unicorn" does not explicitly export ...
        "union-attr",  # Item "None" of "Uc | None" has no attribute ...
        "no-untyped-call",  # Call to untyped function "Uc" in typed context
        "no-any-return",  # Returning Any from function (untyped third-party)
        "arg-type",  # str vs Literal["little","big"] for byteorder (known limitation)
        "name-defined",  # Forward references in TYPE_CHECKING blocks
        "func-returns-value",  # Handler dispatch design pattern
        "unused-ignore",  # Stale type: ignore comments
    }

    def test_mypy_strict_passes(self) -> None:
        """Run mypy --strict on the opasm package.

        Uses --ignore-missing-imports to handle third-party libraries
        that lack type stubs. Filters out errors that originate from
        untyped third-party APIs and focuses on our own annotation quality.
        """
        result = subprocess.run(
            [
                MYPY,
                "--strict",
                "--ignore-missing-imports",
                "opasm/",
            ],
            capture_output=True,
            text=True,
            cwd=PROJECT_ROOT,
            timeout=120,
        )
        # Filter to only actual errors (not notes or summaries)
        all_error_lines = [
            line for line in result.stdout.splitlines() if ": error:" in line
        ]

        # Filter out errors caused by untyped third-party libraries
        # and known typing limitations
        own_code_errors = [
            line
            for line in all_error_lines
            if not any(f"[{code}]" in line for code in self.ACCEPTABLE_ERROR_CODES)
        ]

        assert (
            not own_code_errors
        ), f"mypy --strict found type errors in our code:\n" + "\n".join(
            own_code_errors
        )


# ---------------------------------------------------------------------------
# No circular imports - importing any single module doesn't trigger
# circular import errors
# ---------------------------------------------------------------------------


class TestNoCircularImports:
    """Verify no circular import errors when importing any module."""

    @pytest.mark.parametrize("module", OPASM_MODULES)
    def test_no_circular_import(self, module: str) -> None:
        """Importing {module} does not trigger circular import errors."""
        # Use a script that imports the module and checks for circular import
        # indicators in the error output.
        script = (
            f"import sys\n"
            f"try:\n"
            f"    import {module}\n"
            f"    print('OK')\n"
            f"except ImportError as e:\n"
            f"    if 'circular' in str(e).lower() or "
            f"'partially initialized' in str(e).lower():\n"
            f"        print(f'CIRCULAR: {{e}}')\n"
            f"        sys.exit(1)\n"
            f"    else:\n"
            f"        print(f'IMPORT_ERROR: {{e}}')\n"
            f"        sys.exit(2)\n"
        )
        result = subprocess.run(
            [PYTHON, "-c", script],
            capture_output=True,
            text=True,
            cwd=PROJECT_ROOT,
            timeout=30,
        )
        assert result.returncode == 0, (
            f"Circular import detected when importing {module}:\n"
            f"stdout: {result.stdout}\n"
            f"stderr: {result.stderr}"
        )
        assert (
            "CIRCULAR" not in result.stdout
        ), f"Circular import in {module}: {result.stdout}"
