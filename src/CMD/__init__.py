"""CMD command line interpreter primitives for VVRP."""

from .dispatch import DispatchOutcome, dispatch_line
from .models import (
    CliContext,
    CommandResult,
    CommandSpec,
    CompletionCandidate,
    HelpCandidate,
    ModeFrame,
    ParseResult,
    ParseStatus,
    TokenStyle,
)
from .parser import CommandParser
from .registry import CommandRegistry

__all__ = [
    "CliContext",
    "CommandParser",
    "CommandRegistry",
    "CommandResult",
    "CommandSpec",
    "CompletionCandidate",
    "DispatchOutcome",
    "HelpCandidate",
    "ModeFrame",
    "ParseResult",
    "ParseStatus",
    "TokenStyle",
    "dispatch_line",
]
