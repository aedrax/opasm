"""Property-based tests for CommandDispatcher error resilience."""

from unittest.mock import MagicMock

from hypothesis import given, settings, strategies as st

from opasm.dispatcher import CommandDispatcher
from opasm.exceptions import (
    AssemblyError,
    EngineInitError,
    FileOperationError,
    MemoryAccessError,
    OpasmError,
)


# ---------------------------------------------------------------------------
# Strategy helpers
# ---------------------------------------------------------------------------

# Strategy for generating recoverable OpasmError subclass instances
_recoverable_errors = st.one_of(
    st.text(min_size=1, max_size=50).map(lambda msg: AssemblyError(msg)),
    st.builds(
        MemoryAccessError,
        message=st.text(min_size=1, max_size=50),
        address=st.integers(min_value=0, max_value=0xFFFFFFFF),
        nearest_base=st.integers(min_value=0, max_value=0xFFFFFFFF),
        nearest_size=st.integers(min_value=1, max_value=0x100000),
    ),
    st.text(min_size=1, max_size=50).map(lambda msg: FileOperationError(msg)),
)

# Strategy for generating command names (simple lowercase identifiers)
_command_names = st.from_regex(r"[a-z]{3,8}", fullmatch=True)

# Strategy for generating EngineInitError instances (unrecoverable)
_unrecoverable_errors = st.builds(
    EngineInitError,
    message=st.text(min_size=1, max_size=50),
    engine_name=st.sampled_from(["unicorn", "capstone", "keystone"]),
    arch_config_name=st.sampled_from(["x86", "x64", "arm", "arm64", "mips32"]),
)


def _make_context() -> MagicMock:
    """Create a mock CommandContext with the required attributes."""
    ctx = MagicMock()
    ctx.engine = MagicMock()
    ctx.display = MagicMock()
    ctx.state_mgr = MagicMock()
    ctx.calculator = MagicMock()
    return ctx


# ---------------------------------------------------------------------------
# Recoverable error resilience
# ---------------------------------------------------------------------------


@settings(max_examples=100)
@given(error=_recoverable_errors, cmd_name=_command_names)
def test_recoverable_error_repl_continues(error: OpasmError, cmd_name: str) -> None:
    """For any registered command handler that raises a recoverable OpasmError
    subclass (AssemblyError, MemoryAccessError, FileOperationError), the
    CommandDispatcher SHALL catch the exception at the dispatch level, call
    print_error with the error message, and return True so the REPL loop
    continues.
    """
    ctx = _make_context()
    assembly_handler = MagicMock()

    dispatcher = CommandDispatcher(context=ctx, assembly_handler=assembly_handler)

    # Register a handler that raises the generated recoverable error
    def raising_handler(context, args):
        raise error

    dispatcher.register(
        name=cmd_name, handler=raising_handler, aliases=[], usage="test"
    )

    # Dispatch input that matches the command
    result = dispatcher.dispatch(cmd_name)

    # REPL should continue (returns True)
    assert result is True, (
        f"Expected dispatch to return True for recoverable {type(error).__name__}, "
        f"got {result}"
    )

    # print_error should have been called with the error message
    ctx.display.print_error.assert_called_once_with(str(error))

    # No exception should have propagated (we reached this assertion)
    # Assembly handler should NOT have been called (command was matched)
    assembly_handler.assert_not_called()


@settings(max_examples=100)
@given(error=_unrecoverable_errors, cmd_name=_command_names)
def test_unrecoverable_error_is_reraised(error: EngineInitError, cmd_name: str) -> None:
    """For any registered command handler that raises an EngineInitError
    (unrecoverable), the CommandDispatcher SHALL re-raise the exception
    so it propagates to the REPL level for process termination.
    """
    ctx = _make_context()
    assembly_handler = MagicMock()

    dispatcher = CommandDispatcher(context=ctx, assembly_handler=assembly_handler)

    # Register a handler that raises the unrecoverable error
    def raising_handler(context, args):
        raise error

    dispatcher.register(
        name=cmd_name, handler=raising_handler, aliases=[], usage="test"
    )

    # Dispatch should re-raise EngineInitError
    raised = False
    try:
        dispatcher.dispatch(cmd_name)
    except EngineInitError as exc:
        raised = True
        assert exc is error, "Expected the original EngineInitError to be re-raised"

    assert (
        raised
    ), f"Expected EngineInitError to propagate, but dispatch returned normally"

    # print_error should NOT have been called (unrecoverable errors propagate)
    ctx.display.print_error.assert_not_called()


@settings(max_examples=100)
@given(error=_recoverable_errors, cmd_name=_command_names)
def test_recoverable_error_state_unchanged(error: OpasmError, cmd_name: str) -> None:
    """For any recoverable OpasmError raised during command execution, the
    engine state (registers, memory, breakpoints) SHALL remain unmodified
    after the error is caught by the dispatcher.
    """
    ctx = _make_context()
    assembly_handler = MagicMock()

    dispatcher = CommandDispatcher(context=ctx, assembly_handler=assembly_handler)

    # Register a handler that raises the generated recoverable error
    def raising_handler(context, args):
        raise error

    dispatcher.register(
        name=cmd_name, handler=raising_handler, aliases=[], usage="test"
    )

    # Record state before dispatch - no state-modifying methods called
    ctx.engine.reset_mock()
    ctx.state_mgr.reset_mock()

    result = dispatcher.dispatch(cmd_name)

    # REPL continues
    assert result is True

    # Engine state was not modified by the dispatcher itself
    # (write_register, write_memory, reset, switch_architecture not called)
    ctx.engine.write_register.assert_not_called()
    ctx.engine.write_memory.assert_not_called()
    ctx.engine.reset.assert_not_called()
    ctx.engine.switch_architecture.assert_not_called()


# ---------------------------------------------------------------------------
# Command dispatch routing
# ---------------------------------------------------------------------------

# Additional strategies for dispatch routing tests

# Alias names: short lowercase identifiers
_alias_names = st.from_regex(r"[a-z][a-z0-9]{0,4}", fullmatch=True)

# Argument tokens: alphanumeric strings
_arg_tokens = st.from_regex(r"[a-zA-Z0-9_]{1,10}", fullmatch=True)


@st.composite
def command_registrations(draw):
    """Generate a list of command registrations with unique names and aliases.

    Each registration is a tuple of (name, aliases_list).
    All names and aliases are guaranteed to be distinct across the entire set.
    """
    from hypothesis import assume as _assume

    num_commands = draw(st.integers(min_value=1, max_value=5))
    used_keys: set = set()
    registrations: list = []

    for _ in range(num_commands):
        name = draw(_command_names)
        _assume(name.lower() not in used_keys)
        used_keys.add(name.lower())

        num_aliases = draw(st.integers(min_value=0, max_value=2))
        aliases: list = []
        for _ in range(num_aliases):
            alias = draw(_alias_names)
            _assume(alias.lower() not in used_keys)
            used_keys.add(alias.lower())
            aliases.append(alias)

        registrations.append((name, aliases))

    return registrations


@st.composite
def matching_input(draw, registrations):
    """Generate input that matches one of the registered commands or aliases.

    Returns (input_string, matched_command_index, expected_remaining_tokens).
    """
    cmd_idx = draw(st.integers(min_value=0, max_value=len(registrations) - 1))
    name, aliases = registrations[cmd_idx]

    # Choose whether to match by name or alias
    all_keys = [name] + aliases
    chosen_key = draw(st.sampled_from(all_keys))

    # Vary the case of the chosen key to test case-insensitivity
    case_varied = draw(
        st.sampled_from(
            [
                chosen_key.lower(),
                chosen_key.upper(),
                chosen_key.capitalize(),
            ]
        )
    )

    # Generate 0-3 argument tokens
    num_args = draw(st.integers(min_value=0, max_value=3))
    args = [draw(_arg_tokens) for _ in range(num_args)]

    # Build the input string
    parts = [case_varied] + args
    input_str = " ".join(parts)

    return input_str, cmd_idx, args


@st.composite
def non_matching_input(draw, registrations):
    """Generate input whose first token does NOT match any registered command or alias."""
    from hypothesis import assume as _assume

    # Collect all registered keys (lowercase)
    all_keys: set = set()
    for name, aliases in registrations:
        all_keys.add(name.lower())
        for alias in aliases:
            all_keys.add(alias.lower())

    # Generate a first token that doesn't match any registered key
    first_token = draw(_command_names)
    _assume(first_token.lower() not in all_keys)

    # Generate optional trailing content
    num_args = draw(st.integers(min_value=0, max_value=3))
    args = [draw(_arg_tokens) for _ in range(num_args)]

    parts = [first_token] + args
    input_str = " ".join(parts)

    return input_str


@settings(max_examples=100)
@given(data=st.data())
def test_dispatch_routes_to_correct_handler(data) -> None:
    """For any set of registered commands and any user input whose first token
    matches a registered name or alias (case-insensitive), the corresponding
    handler is invoked with the remaining tokens.
    """
    registrations = data.draw(command_registrations())
    input_str, cmd_idx, expected_args = data.draw(matching_input(registrations))

    # Set up dispatcher with mock context and handlers
    ctx = _make_context()
    assembly_handler = MagicMock()
    dispatcher = CommandDispatcher(context=ctx, assembly_handler=assembly_handler)

    handlers: list = []
    for name, aliases in registrations:
        handler = MagicMock(return_value=None)
        handlers.append(handler)
        dispatcher.register(
            name=name,
            handler=handler,
            aliases=aliases,
            usage=f"Usage for {name}",
        )

    # Dispatch the input
    dispatcher.dispatch(input_str)

    # The correct handler should have been called with remaining tokens
    target_handler = handlers[cmd_idx]
    target_handler.assert_called_once_with(ctx, expected_args)

    # Assembly handler should NOT have been called
    assembly_handler.assert_not_called()

    # No other handler should have been called
    for i, handler in enumerate(handlers):
        if i != cmd_idx:
            handler.assert_not_called()


@settings(max_examples=100)
@given(data=st.data())
def test_dispatch_falls_back_to_assembly_handler(data) -> None:
    """For any user input whose first token does NOT match any registered
    command name or alias, the full unmodified input string is passed to
    the assembly execution handler.
    """
    registrations = data.draw(command_registrations())
    input_str = data.draw(non_matching_input(registrations))

    # Set up dispatcher with mock context and handlers
    ctx = _make_context()
    assembly_handler = MagicMock()
    dispatcher = CommandDispatcher(context=ctx, assembly_handler=assembly_handler)

    handlers: list = []
    for name, aliases in registrations:
        handler = MagicMock(return_value=None)
        handlers.append(handler)
        dispatcher.register(
            name=name,
            handler=handler,
            aliases=aliases,
            usage=f"Usage for {name}",
        )

    # Dispatch the input
    dispatcher.dispatch(input_str)

    # Assembly handler should have been called with the full unmodified input
    assembly_handler.assert_called_once_with(input_str)

    # No command handler should have been called
    for handler in handlers:
        handler.assert_not_called()
