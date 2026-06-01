"""Command dispatch and routing for Opasm.

Routes user input to registered command handlers. Provides command
registration, case-insensitive name/alias matching, and structured
error handling that distinguishes recoverable from unrecoverable errors.

Public classes:
    CommandContext - Protocol defining the context passed to handlers.
    CommandEntry - Dataclass describing a registered command.
    CommandDispatcher - Routes user input to registered command handlers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Protocol, runtime_checkable

from opasm.exceptions import EngineInitError, OpasmError


@runtime_checkable
class CommandContext(Protocol):
    """Protocol for the object passed to command handlers.

    Implementations must expose engine, display, state_mgr, and calculator
    attributes that command handlers use to interact with the system.
    """

    @property
    def engine(self) -> Any:
        """The EngineManager instance."""
        ...

    @property
    def display(self) -> Any:
        """The DisplayRenderer instance."""
        ...

    @property
    def state_mgr(self) -> Any:
        """The StateManager instance."""
        ...

    @property
    def calculator(self) -> Any:
        """The Calculator instance."""
        ...


@dataclass
class CommandEntry:
    """Registration entry for a single command.

    Attributes:
        name: Primary command name (e.g., "registers").
        handler: Callable accepting (CommandContext, list[str]) and returning None.
        aliases: Alternative names for the command (e.g., ["reg"]).
        usage: Description string (max 200 chars) for help output.
    """

    name: str
    handler: Callable[[CommandContext, list[str]], None]
    aliases: list[str] = field(default_factory=list)
    usage: str = ""


class CommandDispatcher:
    """Routes user input to registered command handlers.

    Matches the first whitespace-delimited token of user input
    (case-insensitive) against registered command names and aliases.
    If a match is found, the corresponding handler is invoked. If no
    match is found, the full input string is delegated to the assembly
    handler.

    Parameters:
        context: A CommandContext providing engine, display, state_mgr,
                 and calculator to command handlers.
        assembly_handler: Callable accepting the full input string,
                          invoked when input does not match any command.
    """

    def __init__(
        self,
        context: CommandContext,
        assembly_handler: Callable[[str], None],
    ) -> None:
        """Initialize the command dispatcher.

        Args:
            context: The CommandContext passed to all command handlers.
            assembly_handler: Fallback callable for unrecognized input.
        """
        self._context: CommandContext = context
        self._assembly_handler: Callable[[str], None] = assembly_handler
        self._commands: dict[str, CommandEntry] = {}
        self._alias_map: dict[str, str] = {}

    def register(
        self,
        name: str,
        handler: Callable[[CommandContext, list[str]], None],
        aliases: list[str] | None = None,
        usage: str = "",
    ) -> None:
        """Register a command with its handler, aliases, and usage text.

        Args:
            name: Primary command name (stored lowercase).
            handler: Callable accepting (CommandContext, list[str]).
            aliases: Optional list of alternative names for the command.
            usage: Description string (max 200 chars) for help output.

        Raises:
            ValueError: If name or any alias conflicts with an existing
                        registration.
        """
        if aliases is None:
            aliases = []

        # Truncate usage to 200 chars
        usage = usage[:200]

        lower_name = name.lower()

        if lower_name in self._commands or lower_name in self._alias_map:
            raise ValueError(
                f"Command name '{name}' conflicts with an existing registration"
            )

        for alias in aliases:
            lower_alias = alias.lower()
            if lower_alias in self._commands or lower_alias in self._alias_map:
                raise ValueError(
                    f"Alias '{alias}' conflicts with an existing registration"
                )

        entry = CommandEntry(
            name=lower_name,
            handler=handler,
            aliases=[a.lower() for a in aliases],
            usage=usage,
        )

        self._commands[lower_name] = entry

        for alias in entry.aliases:
            self._alias_map[alias] = lower_name

    def dispatch(self, user_input: str) -> bool:
        """Dispatch user input to the appropriate handler.

        Splits input on whitespace, matches the first token
        case-insensitively against registered names and aliases.
        If matched, calls the handler wrapped in error handling.
        If not matched, delegates to the assembly handler.

        Args:
            user_input: Raw input string from the user.

        Returns:
            True to continue the REPL loop, False to exit.

        Raises:
            EngineInitError: Re-raised when an unrecoverable engine
                             initialization error occurs.
        """
        stripped = user_input.strip()
        if not stripped:
            return True

        tokens = stripped.split()
        first_token = tokens[0].lower()
        remaining_tokens = tokens[1:]

        # Look up by name first, then by alias
        entry: CommandEntry | None = None
        if first_token in self._commands:
            entry = self._commands[first_token]
        elif first_token in self._alias_map:
            primary_name = self._alias_map[first_token]
            entry = self._commands[primary_name]

        if entry is not None:
            try:
                result = entry.handler(self._context, remaining_tokens)
                # If handler explicitly returns False, signal REPL exit
                if result is False:
                    return False
            except EngineInitError:
                # Unrecoverable - re-raise to REPL level
                raise
            except OpasmError as exc:
                # Recoverable - display error and continue
                self._context.display.print_error(str(exc))
            return True

        # No command match - delegate to assembly handler
        try:
            self._assembly_handler(user_input)
        except EngineInitError:
            raise
        except OpasmError as exc:
            self._context.display.print_error(str(exc))

        return True

    def get_help_entries(self) -> list[CommandEntry]:
        """Return all registered command entries sorted by name.

        Returns:
            List of CommandEntry objects in alphabetical order by name.
        """
        return sorted(self._commands.values(), key=lambda e: e.name)

    def get_command_names(self) -> list[str]:
        """Return all registered command names and aliases.

        Returns:
            List of all names and aliases (lowercase) that the
            dispatcher recognizes.
        """
        names: list[str] = []
        for entry in self._commands.values():
            names.append(entry.name)
            names.extend(entry.aliases)
        return sorted(names)
