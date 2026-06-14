from __future__ import annotations

from dataclasses import dataclass

from .help import format_help
from .models import CliContext, CommandResult, ParseStatus
from .parser import CommandParser
from .registry import CommandRegistry


@dataclass(frozen=True)
class DispatchOutcome:
    executed: bool
    display_command: str
    status: ParseStatus
    message: str = ""


def dispatch_line(ctx: CliContext, registry: CommandRegistry, line: str) -> DispatchOutcome:
    parser = CommandParser(registry)

    if "?" in line:
        message = format_help(parser.help_candidates(line, mode=ctx.mode))
        ctx.write(message)
        return DispatchOutcome(False, line, ParseStatus.EMPTY, message)

    parsed = parser.parse(line, mode=ctx.mode)

    if parsed.status == ParseStatus.EMPTY:
        return DispatchOutcome(False, "", parsed.status)

    if parsed.status == ParseStatus.AMBIGUOUS:
        message = "% Ambiguous command"
        ctx.write(message)
        return DispatchOutcome(False, parsed.complete_command, parsed.status, message)

    if parsed.status == ParseStatus.INVALID:
        message = "% Invalid input"
        ctx.write(message)
        return DispatchOutcome(False, parsed.complete_command, parsed.status, message)

    if not parsed.executable:
        message = "% Incomplete command"
        ctx.write(message)
        return DispatchOutcome(False, parsed.complete_command, parsed.status, message)

    try:
        raw_result = parsed.handler(ctx, dict(parsed.args))
    except Exception as exc:  # pragma: no cover - safety net for real CLI sessions.
        raw_result = CommandResult(ok=False, message=f"% Handler error: {exc}")

    result = _normalize_result(raw_result)
    if result.exit_requested:
        ctx.exit_requested = True
    if result.message:
        ctx.write(result.message)

    return DispatchOutcome(True, parsed.complete_command, parsed.status, result.message)


def _normalize_result(result: CommandResult | str | None) -> CommandResult:
    if isinstance(result, CommandResult):
        return result
    if isinstance(result, str):
        return CommandResult(message=result)
    return CommandResult()
