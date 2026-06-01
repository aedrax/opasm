"""State capture, comparison, serialization, and deserialization for Opasm.

Provides the StateManager class for capturing CPU/memory state snapshots,
comparing states to identify changes, and serializing/deserializing state
to/from JSON files with schema validation.

Public constants:
    STATE_SCHEMA_VERSION - Current schema version for state files.
    REQUIRED_KEYS - Set of required top-level keys in a state file.

Public classes:
    StateChanges - Dataclass holding differences between two captured states.
    StateManager - Captures, compares, serializes, and deserializes CPU/memory state.
"""

import json
from dataclasses import dataclass, field
from typing import Any, Dict, Set

from opasm.architectures import ARCHITECTURES, ArchConfig, get_architecture
from opasm.exceptions import FileOperationError

STATE_SCHEMA_VERSION: int = 1
"""Current schema version for state serialization files."""

REQUIRED_KEYS: Set[str] = {
    "version",
    "architecture",
    "registers",
    "memory_regions",
    "code_history",
    "breakpoints",
}
"""Set of required top-level keys in a valid state file."""


@dataclass
class StateChanges:
    """Differences between two captured states.

    Attributes:
        changed_registers: Set of register names whose values differ.
        changed_stack_addresses: Set of stack memory addresses whose values differ.
    """

    changed_registers: Set[str] = field(default_factory=set)
    changed_stack_addresses: Set[int] = field(default_factory=set)


class StateManager:
    """Captures, compares, serializes, and deserializes CPU/memory state.

    Provides methods to snapshot the current engine state, compare snapshots
    to detect changes, and persist/restore state via JSON files with schema
    validation.

    Parameters:
        engine: The EngineManager instance to capture state from and restore to.
    """

    def __init__(self, engine: "EngineManager") -> None:
        self._engine = engine

    def capture(self) -> Dict[str, Any]:
        """Capture the current engine state as a dictionary.

        Returns a dict containing the schema version, architecture name,
        all register values, memory region contents (hex-encoded), code
        history, and breakpoints.

        Returns:
            A dictionary representing the full engine state.
        """
        state: Dict[str, Any] = {
            "version": STATE_SCHEMA_VERSION,
            "architecture": self._engine.current_arch_name,
            "registers": {},
            "memory_regions": {},
            "code_history": self._engine.code_history,
            "breakpoints": list(self._engine.breakpoints),
        }

        # Capture register values
        for reg_name in self._engine.arch_config.registers:
            try:
                state["registers"][reg_name] = self._engine.read_register(reg_name)
            except (KeyError, Exception):
                pass

        # Capture memory region contents
        for name, (base, size) in self._engine.get_memory_regions().items():
            try:
                data = self._engine.read_memory(base, size)
                state["memory_regions"][name] = {
                    "base": base,
                    "size": size,
                    "data": data.hex(),
                }
            except Exception:
                pass

        return state

    def compare(self, previous: Dict[str, Any]) -> StateChanges:
        """Compare the current engine state against a previous capture.

        Identifies registers whose values have changed and stack memory
        addresses whose contents differ between the previous capture and
        the current state.

        Parameters:
            previous: A state dictionary from a prior call to capture().

        Returns:
            A StateChanges instance with changed registers and stack addresses.
        """
        changes = StateChanges()

        # Compare registers
        prev_registers = previous.get("registers", {})
        for reg_name in self._engine.arch_config.registers:
            try:
                current_value = self._engine.read_register(reg_name)
            except (KeyError, Exception):
                continue

            prev_value = prev_registers.get(reg_name)
            if prev_value is None or current_value != prev_value:
                changes.changed_registers.add(reg_name)

        # Compare stack memory
        prev_regions = previous.get("memory_regions", {})
        if "stack" in prev_regions:
            stack_info = prev_regions["stack"]
            stack_base = stack_info["base"]
            stack_size = stack_info["size"]
            prev_data = bytes.fromhex(stack_info["data"])

            try:
                current_data = self._engine.read_memory(stack_base, stack_size)
            except Exception:
                current_data = b""

            word_size = self._engine.arch_config.word_size
            # Compare word by word
            for offset in range(0, min(len(prev_data), len(current_data)), word_size):
                prev_word = prev_data[offset : offset + word_size]
                curr_word = current_data[offset : offset + word_size]
                if prev_word != curr_word:
                    changes.changed_stack_addresses.add(stack_base + offset)

        return changes

    def save(self, filepath: str) -> None:
        """Capture state and write it to a JSON file.

        Parameters:
            filepath: Path to the output JSON file.

        Raises:
            FileOperationError: If the file cannot be written.
        """
        state = self.capture()
        try:
            with open(filepath, "w") as f:
                json.dump(state, f, indent=2)
        except OSError as exc:
            raise FileOperationError(
                f"Cannot write state file '{filepath}': {exc}"
            ) from exc

    def load(self, filepath: str) -> None:
        """Read a JSON state file, validate it, and restore state to the engine.

        Switches architecture if needed, restores register values, memory
        contents, breakpoints, and code history.

        Parameters:
            filepath: Path to the JSON state file to load.

        Raises:
            FileOperationError: If the file contains invalid JSON, is missing
                required keys, or has an unsupported schema version.
        """
        # Read and parse JSON
        try:
            with open(filepath, "r") as f:
                data = json.load(f)
        except json.JSONDecodeError as exc:
            raise FileOperationError(f"Invalid JSON: {exc}") from exc
        except OSError as exc:
            raise FileOperationError(
                f"Cannot read state file '{filepath}': {exc}"
            ) from exc

        # Validate structure
        self.validate_state_file(data)

        # Switch architecture if needed
        arch_name = data["architecture"]
        if arch_name != self._engine.current_arch_name:
            arch_config = get_architecture(arch_name)
            self._engine.switch_architecture(arch_config)

        # Restore registers
        for reg_name, value in data["registers"].items():
            try:
                self._engine.write_register(reg_name, value)
            except (KeyError, Exception):
                pass

        # Restore memory
        for name, mem_info in data["memory_regions"].items():
            regions = self._engine.get_memory_regions()
            if name in regions:
                try:
                    mem_data = bytes.fromhex(mem_info["data"])
                    self._engine.write_memory(mem_info["base"], mem_data)
                except Exception:
                    pass

        # Restore breakpoints
        # Clear existing breakpoints first
        for bp in list(self._engine.breakpoints):
            try:
                self._engine.remove_breakpoint(bp)
            except KeyError:
                pass

        for bp in data.get("breakpoints", []):
            self._engine.add_breakpoint(bp)

        # Restore code history via public setter
        self._engine.code_history = list(data.get("code_history", []))

    def validate_state_file(self, data: Dict[str, Any]) -> None:
        """Validate a state file dictionary for required keys and version.

        Checks that all required top-level keys are present and that the
        schema version is supported.

        Parameters:
            data: The parsed state file dictionary to validate.

        Raises:
            FileOperationError: If required keys are missing or the schema
                version is unsupported.
        """
        # Check required keys
        missing = REQUIRED_KEYS - set(data.keys())
        if missing:
            raise FileOperationError(
                f"Missing required keys: {', '.join(sorted(missing))}"
            )

        # Check schema version
        version = data["version"]
        if version != STATE_SCHEMA_VERSION:
            raise FileOperationError(
                f"Unsupported schema version: {version} (supported: {STATE_SCHEMA_VERSION})"
            )
