"""Unit tests for the Opasm exception hierarchy.

OpasmError base class with recoverable and
unrecoverable subclass categories.
"""

import pytest

from opasm.exceptions import (
    AssemblyError,
    EngineInitError,
    FileOperationError,
    MemoryAccessError,
    OpasmError,
)


# ---------------------------------------------------------------------------
# Inheritance tests - all custom exceptions are subclasses of OpasmError
# ---------------------------------------------------------------------------


class TestInheritance:
    """Verify that all custom exceptions inherit from OpasmError."""

    def test_assembly_error_is_opasm_error(self) -> None:
        assert issubclass(AssemblyError, OpasmError)

    def test_memory_access_error_is_opasm_error(self) -> None:
        assert issubclass(MemoryAccessError, OpasmError)

    def test_file_operation_error_is_opasm_error(self) -> None:
        assert issubclass(FileOperationError, OpasmError)

    def test_engine_init_error_is_opasm_error(self) -> None:
        assert issubclass(EngineInitError, OpasmError)

    def test_opasm_error_is_exception(self) -> None:
        assert issubclass(OpasmError, Exception)

    def test_all_exceptions_catchable_as_opasm_error(self) -> None:
        """Raising any custom exception is caught by `except OpasmError`."""
        exceptions = [
            AssemblyError("test"),
            MemoryAccessError(
                "test", address=0x1000, nearest_base=0x0, nearest_size=0x1000
            ),
            FileOperationError("test"),
            EngineInitError("test", engine_name="unicorn", arch_config_name="x64"),
        ]
        for exc in exceptions:
            with pytest.raises(OpasmError):
                raise exc


# ---------------------------------------------------------------------------
# Recoverable vs unrecoverable classification
# ---------------------------------------------------------------------------

RECOVERABLE_CLASSES = (AssemblyError, MemoryAccessError, FileOperationError)
UNRECOVERABLE_CLASSES = (EngineInitError,)


class TestClassification:
    """Verify recoverable vs unrecoverable exception classification."""

    @pytest.mark.parametrize("exc_class", RECOVERABLE_CLASSES)
    def test_recoverable_exceptions_are_not_engine_init_error(
        self, exc_class: type
    ) -> None:
        """Recoverable exceptions are not instances of EngineInitError."""
        assert not issubclass(exc_class, EngineInitError)

    @pytest.mark.parametrize("exc_class", UNRECOVERABLE_CLASSES)
    def test_unrecoverable_exceptions_are_engine_init_error(
        self, exc_class: type
    ) -> None:
        """Unrecoverable exceptions are EngineInitError or subclasses."""
        assert issubclass(exc_class, EngineInitError)

    def test_recoverable_instances_distinguishable(self) -> None:
        """isinstance checks can separate recoverable from unrecoverable."""
        recoverable_exc = AssemblyError("bad instruction")
        unrecoverable_exc = EngineInitError(
            "failed", engine_name="unicorn", arch_config_name="x64"
        )

        assert isinstance(recoverable_exc, OpasmError)
        assert not isinstance(recoverable_exc, EngineInitError)

        assert isinstance(unrecoverable_exc, OpasmError)
        assert isinstance(unrecoverable_exc, EngineInitError)

    def test_all_recoverable_share_no_subclass_relation(self) -> None:
        """No recoverable exception is a subclass of another recoverable."""
        for cls_a in RECOVERABLE_CLASSES:
            for cls_b in RECOVERABLE_CLASSES:
                if cls_a is not cls_b:
                    assert not issubclass(cls_a, cls_b)


# ---------------------------------------------------------------------------
# Exception field accessibility
# ---------------------------------------------------------------------------


class TestExceptionFields:
    """Verify that exception-specific fields are accessible after construction."""

    def test_assembly_error_message(self) -> None:
        exc = AssemblyError("invalid instruction: xyz")
        assert str(exc) == "invalid instruction: xyz"
        assert exc.args[0] == "invalid instruction: xyz"

    def test_memory_access_error_fields(self) -> None:
        exc = MemoryAccessError(
            "unmapped access at 0xDEAD",
            address=0xDEAD,
            nearest_base=0x1000,
            nearest_size=0x2000,
        )
        assert exc.address == 0xDEAD
        assert exc.nearest_base == 0x1000
        assert exc.nearest_size == 0x2000
        assert str(exc) == "unmapped access at 0xDEAD"

    def test_memory_access_error_zero_address(self) -> None:
        exc = MemoryAccessError(
            "null pointer access",
            address=0x0,
            nearest_base=0x0,
            nearest_size=0x0,
        )
        assert exc.address == 0x0
        assert exc.nearest_base == 0x0
        assert exc.nearest_size == 0x0

    def test_file_operation_error_message(self) -> None:
        exc = FileOperationError("invalid JSON in state file")
        assert str(exc) == "invalid JSON in state file"
        assert exc.args[0] == "invalid JSON in state file"

    def test_engine_init_error_fields(self) -> None:
        exc = EngineInitError(
            "Unicorn failed for x64",
            engine_name="unicorn",
            arch_config_name="x64",
        )
        assert exc.engine_name == "unicorn"
        assert exc.arch_config_name == "x64"
        assert str(exc) == "Unicorn failed for x64"

    def test_engine_init_error_different_engines(self) -> None:
        for engine in ("unicorn", "capstone", "keystone"):
            exc = EngineInitError(
                f"{engine} init failed",
                engine_name=engine,
                arch_config_name="arm64",
            )
            assert exc.engine_name == engine
            assert exc.arch_config_name == "arm64"

    def test_opasm_error_base_accepts_message(self) -> None:
        exc = OpasmError("generic error")
        assert str(exc) == "generic error"
        assert exc.args[0] == "generic error"
