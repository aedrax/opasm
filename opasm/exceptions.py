"""Custom exception hierarchy for Opasm.

Defines a base exception and domain-specific subclasses categorized as
recoverable (REPL continues) or unrecoverable (REPL exits).

Public classes:
    OpasmError - Base exception for all Opasm errors
    AssemblyError - Failed instruction encoding (recoverable)
    MemoryAccessError - Unmapped memory access (recoverable)
    FileOperationError - State file I/O or validation failure (recoverable)
    EngineInitError - Engine creation failure (unrecoverable)
"""


class OpasmError(Exception):
    """Base exception for all Opasm errors.

    All custom exceptions in the Opasm tool inherit from this class,
    enabling callers to catch any Opasm-specific error with a single
    except clause.
    """


# ---------------------------------------------------------------------------
# Recoverable exceptions - REPL continues after these are raised
# ---------------------------------------------------------------------------


class AssemblyError(OpasmError):
    """Raised when an assembly instruction fails to encode.

    Parameters:
        message: Human-readable description of the assembly failure.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)


class MemoryAccessError(OpasmError):
    """Raised when a memory operation targets an unmapped region.

    Provides context about the attempted access and the nearest valid
    memory region to aid debugging.

    Parameters:
        message: Human-readable description of the memory access failure.
        address: The unmapped address that was accessed.
        nearest_base: Base address of the nearest mapped memory region.
        nearest_size: Size in bytes of the nearest mapped memory region.
    """

    def __init__(
        self,
        message: str,
        address: int,
        nearest_base: int,
        nearest_size: int,
    ) -> None:
        super().__init__(message)
        self.address: int = address
        self.nearest_base: int = nearest_base
        self.nearest_size: int = nearest_size


class FileOperationError(OpasmError):
    """Raised when a state file I/O or validation operation fails.

    Covers invalid JSON, missing required keys, unsupported schema versions,
    and filesystem errors during save/load operations.

    Parameters:
        message: Human-readable description of the file operation failure.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)


# ---------------------------------------------------------------------------
# Unrecoverable exceptions - REPL exits after these are raised
# ---------------------------------------------------------------------------


class EngineInitError(OpasmError):
    """Raised when engine initialization fails.

    Indicates that Unicorn, Capstone, or Keystone could not be initialized
    for the requested architecture. This is an unrecoverable error that
    causes the REPL to exit.

    Parameters:
        message: Human-readable description of the initialization failure.
        engine_name: Name of the engine that failed (e.g., "unicorn",
            "capstone", "keystone").
        arch_config_name: Name of the architecture configuration that was
            being initialized when the failure occurred.
    """

    def __init__(
        self,
        message: str,
        engine_name: str,
        arch_config_name: str,
    ) -> None:
        super().__init__(message)
        self.engine_name: str = engine_name
        self.arch_config_name: str = arch_config_name
