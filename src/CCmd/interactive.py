from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Callable

from .dispatch import dispatch_line
from .help import format_help
from .models import CliContext, ParseStatus, TokenStatus, TokenStyle
from .parser import CommandParser
from .registry import CommandRegistry
from .running_config import load_saved_configuration, set_saved_configuration_path


def _preserve_help_input(text: str) -> str:
    return text.split("?", 1)[0]


def _format_help_screen_update(prompt_text: str, input_text: str, help_text: str) -> str:
    if not help_text:
        return f"{prompt_text}{input_text}"
    return f"{prompt_text}{input_text}\n{help_text}"


def _format_colored_help_screen_update(
    prompt_text: str,
    input_text: str,
    help_text: str,
    token_statuses: tuple[TokenStatus, ...],
) -> str:
    colored_input = _render_input_with_token_styles(input_text, token_statuses)
    if not help_text:
        return f"{prompt_text}{colored_input}"
    return f"{prompt_text}{colored_input}\n{help_text}"


def _render_input_with_token_styles(
    input_text: str,
    token_statuses: tuple[TokenStatus, ...],
) -> str:
    fragments: list[str] = []
    position = 0
    ansi_by_style = {
        TokenStyle.VALID: "\x1b[32m",
        TokenStyle.AMBIGUOUS: "\x1b[33m",
        TokenStyle.INVALID: "\x1b[31m",
    }
    reset = "\x1b[0m"
    for token_status in token_statuses:
        if position < token_status.start:
            fragments.append(input_text[position:token_status.start])
        token_text = input_text[token_status.start:token_status.end]
        ansi_color = ansi_by_style.get(token_status.style)
        if ansi_color:
            fragments.append(f"{ansi_color}{token_text}{reset}")
        else:
            fragments.append(token_text)
        position = token_status.end
    if position < len(input_text):
        fragments.append(input_text[position:])
    return "".join(fragments)


def _run_plain_cli(
    registry: CommandRegistry,
    prompt: str | None = None,
    hostname: str = "Router",
    saved_configuration_file: str | os.PathLike[str] | None = None,
) -> int:
    ctx = CliContext(hostname=hostname)
    registry.initialize_context(ctx)
    _print_saved_configuration_errors(
        ctx,
        load_saved_configuration(ctx, registry, saved_configuration_file),
    )
    pending_input = ""
    while not ctx.exit_requested:
        try:
            line = input(f"{prompt or ctx.prompt}{pending_input}")
        except EOFError:
            break

        line = f"{pending_input}{line}"
        dispatch_line(ctx, registry, line)
        pending_input = _preserve_help_input(line) if "?" in line else ""

    return 0


class _PromptToolkitAnsiOutput:
    def __init__(self, print_formatted_text: Callable, ansi_factory: Callable) -> None:
        self._print_formatted_text = print_formatted_text
        self._ansi_factory = ansi_factory

    def write(self, text: str) -> int:
        if text:
            self._print_formatted_text(self._ansi_factory(text), end="")
        return len(text)

    def flush(self) -> None:
        return None


def run_interactive_cli(
    registry: CommandRegistry,
    prompt: str | None = None,
    hostname: str = "Router",
    history_file: str | os.PathLike[str] | None = None,
    saved_configuration_file: str | os.PathLike[str] | None = None,
) -> int:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        return _run_plain_cli(
            registry,
            prompt=prompt,
            hostname=hostname,
            saved_configuration_file=saved_configuration_file,
        )

    try:
        from prompt_toolkit import PromptSession
        from prompt_toolkit.application import run_in_terminal
        from prompt_toolkit.completion import Completer, Completion
        from prompt_toolkit.document import Document
        from prompt_toolkit.formatted_text import ANSI
        from prompt_toolkit.history import FileHistory
        from prompt_toolkit.key_binding import KeyBindings
        from prompt_toolkit.lexers import Lexer
        from prompt_toolkit.shortcuts import print_formatted_text
        from prompt_toolkit.styles import Style
    except ImportError:
        print("prompt_toolkit is required for interactive mode.")
        print("Install it with: python -m pip install prompt_toolkit")
        return 2

    parser = CommandParser(registry)
    ctx = CliContext(
        hostname=hostname,
        output=_PromptToolkitAnsiOutput(print_formatted_text, ANSI),
    )
    registry.initialize_context(ctx)
    set_saved_configuration_path(ctx, saved_configuration_file)
    _print_saved_configuration_errors(
        ctx,
        load_saved_configuration(ctx, registry, saved_configuration_file),
    )

    class RouterCommandLexer(Lexer):
        def lex_document(self, document):
            def get_line(lineno: int):
                line = document.lines[lineno]
                parsed = parser.parse(line, mode=ctx.mode, ctx=ctx)
                fragments = []
                position = 0
                style_map = {
                    TokenStyle.VALID: "class:command.valid",
                    TokenStyle.AMBIGUOUS: "class:command.ambiguous",
                    TokenStyle.INVALID: "class:command.invalid",
                }
                for token_status in parsed.token_statuses:
                    if position < token_status.start:
                        fragments.append(("", line[position:token_status.start]))
                    fragments.append(
                        (
                            style_map[token_status.style],
                            line[token_status.start:token_status.end],
                        )
                    )
                    position = token_status.end
                if position < len(line):
                    fragments.append(("", line[position:]))
                return fragments

            return get_line

    class RouterCommandCompleter(Completer):
        def get_completions(self, document, complete_event):
            for candidate in parser.completions(
                document.text_before_cursor,
                mode=ctx.mode,
                ctx=ctx,
            ):
                if candidate.text:
                    yield Completion(
                        candidate.text,
                        start_position=candidate.start_position,
                        display=candidate.display,
                        display_meta=candidate.meta,
                    )

    def show_status(message: str, ansi_color: str) -> None:
        run_in_terminal(
            lambda: print_formatted_text(ANSI(f"{ansi_color}{message}\x1b[0m"))
        )

    def show_help(
        input_text: str,
        message: str,
        token_statuses: tuple[TokenStatus, ...],
    ) -> None:
        run_in_terminal(
            lambda: print_formatted_text(
                ANSI(
                    _format_colored_help_screen_update(
                        prompt or ctx.prompt,
                        input_text,
                        message,
                        token_statuses,
                    )
                )
            )
        )

    key_bindings = KeyBindings()

    @key_bindings.add(" ")
    def _(event) -> None:
        buffer = event.current_buffer
        completed = parser.complete_before_space(
            buffer.document.text_before_cursor,
            mode=ctx.mode,
            ctx=ctx,
        )
        if completed is not None:
            buffer.document = Document(completed, cursor_position=len(completed))
            return
        buffer.insert_text(" ")

    @key_bindings.add("enter")
    def _(event) -> None:
        buffer = event.current_buffer

        if "?" in buffer.text:
            input_text = buffer.text
            parsed_for_color = parser.parse(input_text, mode=ctx.mode, ctx=ctx)
            help_text = format_help(
                parser.help_candidates(input_text, mode=ctx.mode, ctx=ctx)
            )
            preserved_text = _preserve_help_input(input_text)
            show_help(input_text, help_text, parsed_for_color.token_statuses)
            buffer.document = Document(
                preserved_text,
                cursor_position=len(preserved_text),
            )
            return

        parsed = parser.parse(buffer.text, mode=ctx.mode, ctx=ctx)

        if parsed.status == ParseStatus.EMPTY:
            buffer.validate_and_handle()
            return

        if parsed.status == ParseStatus.AMBIGUOUS:
            show_status("% Ambiguous command", "\x1b[33m")
            return

        if parsed.status == ParseStatus.INVALID:
            show_status("% Invalid input", "\x1b[31m")
            return

        if not parsed.executable:
            show_status("% Incomplete command", "\x1b[31m")
            return

        if parsed.complete_command and parsed.complete_command != buffer.text.strip():
            buffer.document = Document(
                parsed.complete_command,
                cursor_position=len(parsed.complete_command),
            )
        buffer.validate_and_handle()

    style = Style.from_dict(
        {
            "command.valid": "ansigreen",
            "command.ambiguous": "ansiyellow",
            "command.invalid": "ansired",
            "completion-menu.completion.current": "bg:#444444 #ffffff",
        }
    )

    history_path = Path(history_file or Path.home() / ".vvrp_ccmd_history")
    session = PromptSession(
        lexer=RouterCommandLexer(),
        completer=RouterCommandCompleter(),
        complete_while_typing=False,
        history=FileHistory(str(history_path)),
        key_bindings=key_bindings,
        style=style,
    )

    while not ctx.exit_requested:
        try:
            line = session.prompt(prompt or ctx.prompt)
        except KeyboardInterrupt:
            continue
        except EOFError:
            break

        dispatch_line(ctx, registry, line)

    return 0


def _print_saved_configuration_errors(ctx: CliContext, errors: list[str]) -> None:
    for error in errors:
        ctx.write(error)
