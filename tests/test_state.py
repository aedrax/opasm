"""Property-based tests for state load validation."""

import json
import os
import tempfile
from unittest.mock import MagicMock

import pytest
from hypothesis import given, settings, strategies as st

from opasm.exceptions import FileOperationError
from opasm.state import REQUIRED_KEYS, STATE_SCHEMA_VERSION, StateManager


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_mock_engine() -> MagicMock:
    """Create a mock engine with minimal interface for StateManager."""
    engine = MagicMock()
    engine.current_arch_name = "x64"
    engine.arch_config.registers = {"rax": 0, "rbx": 1}
    engine.arch_config.word_size = 8
    engine.breakpoints = set()
    engine.code_history = []
    engine.read_register.return_value = 0
    engine.get_memory_regions.return_value = {}
    return engine


def _valid_state_dict() -> dict:
    """Return a minimal valid state dictionary with all required keys."""
    return {
        "version": STATE_SCHEMA_VERSION,
        "architecture": "x64",
        "registers": {"rax": 0, "rbx": 0},
        "memory_regions": {},
        "code_history": [],
        "breakpoints": [],
    }


# ---------------------------------------------------------------------------
# Strategy: Generate proper subsets of REQUIRED_KEYS (missing 1-5 keys)
# ---------------------------------------------------------------------------


@st.composite
def missing_keys_state(draw: st.DrawFn) -> tuple:
    """Generate a state dict with a proper subset of required keys removed.

    Returns a tuple of (state_dict, set_of_missing_keys).
    """
    # Pick how many keys to remove (1 to len(REQUIRED_KEYS) - 1 to keep at least one)
    all_keys = sorted(REQUIRED_KEYS)
    num_to_remove = draw(st.integers(min_value=1, max_value=len(all_keys)))
    keys_to_remove = set(
        draw(
            st.lists(
                st.sampled_from(all_keys),
                min_size=num_to_remove,
                max_size=num_to_remove,
                unique=True,
            )
        )
    )

    state = _valid_state_dict()
    for key in keys_to_remove:
        del state[key]

    return state, keys_to_remove


# ---------------------------------------------------------------------------
# Strategy: Generate unsupported version values (anything != 1)
# ---------------------------------------------------------------------------

bad_version_strategy = st.one_of(
    st.integers(max_value=0),
    st.integers(min_value=2),
)


# ---------------------------------------------------------------------------
# Strategy: Generate invalid JSON text
# ---------------------------------------------------------------------------

invalid_json_strategy = st.text(
    min_size=1,
    alphabet=st.characters(blacklist_categories=("Cs",)),
).filter(lambda s: _is_not_valid_json(s))


def _is_not_valid_json(s: str) -> bool:
    """Return True if s is not valid JSON."""
    try:
        json.loads(s)
        return False
    except (json.JSONDecodeError, ValueError):
        return True


# ---------------------------------------------------------------------------
# Property tests
# ---------------------------------------------------------------------------


class TestStateLoadValidation:
    """State load validation."""

    @given(data=missing_keys_state())
    @settings(max_examples=100)
    def test_validate_state_file_missing_keys_raises_file_operation_error(
        self, data: tuple
    ) -> None:
        """validate_state_file raises FileOperationError for missing required keys."""
        state_dict, missing = data
        engine = _make_mock_engine()
        mgr = StateManager(engine)

        with pytest.raises(FileOperationError) as exc_info:
            mgr.validate_state_file(state_dict)

        error_msg = str(exc_info.value)
        # Error message should mention "Missing required keys"
        assert (
            "missing required keys" in error_msg.lower()
            or "missing" in error_msg.lower()
        )
        # Each missing key should appear in the error message
        for key in missing:
            assert key in error_msg

    @given(bad_version=bad_version_strategy)
    @settings(max_examples=100)
    def test_validate_state_file_bad_version_raises_file_operation_error(
        self, bad_version: int
    ) -> None:
        """validate_state_file raises FileOperationError for unsupported version."""
        state_dict = _valid_state_dict()
        state_dict["version"] = bad_version

        engine = _make_mock_engine()
        mgr = StateManager(engine)

        with pytest.raises(FileOperationError) as exc_info:
            mgr.validate_state_file(state_dict)

        error_msg = str(exc_info.value)
        # Error message should identify unsupported version
        assert "version" in error_msg.lower() or "unsupported" in error_msg.lower()
        # Error message should include the bad version value
        assert str(bad_version) in error_msg

    @given(invalid_text=invalid_json_strategy)
    @settings(max_examples=100)
    def test_load_invalid_json_raises_file_operation_error(
        self, invalid_text: str
    ) -> None:
        """load() raises FileOperationError for files containing invalid JSON."""
        engine = _make_mock_engine()
        mgr = StateManager(engine)

        # Write invalid JSON to a temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(invalid_text)
            tmp_path = f.name

        try:
            with pytest.raises(FileOperationError) as exc_info:
                mgr.load(tmp_path)

            error_msg = str(exc_info.value)
            # Error message should identify invalid JSON
            assert "json" in error_msg.lower() or "invalid" in error_msg.lower()
        finally:
            os.unlink(tmp_path)

    @given(data=missing_keys_state())
    @settings(max_examples=100)
    def test_load_missing_keys_does_not_modify_engine_state(self, data: tuple) -> None:
        """load() with missing keys does not modify engine state."""
        state_dict, _ = data
        engine = _make_mock_engine()
        mgr = StateManager(engine)

        # Write the incomplete state to a temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(state_dict, f)
            tmp_path = f.name

        try:
            with pytest.raises(FileOperationError):
                mgr.load(tmp_path)

            # Engine state should not have been modified
            engine.switch_architecture.assert_not_called()
            engine.write_register.assert_not_called()
            engine.write_memory.assert_not_called()
        finally:
            os.unlink(tmp_path)
