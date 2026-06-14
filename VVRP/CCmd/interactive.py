from __future__ import annotations

import os
import sys
from pathlib import Path

from .dispatch import dispatch_line
from .models import CliContext, ParseStatus, TokenStyle
from .parser import CommandParser
from .registry import CommandRegistry


def _run_plain_cli(
    registry: CommandRegistry,
    prompt: str | None = None,
    hostname: str = "Router",
) -> int:
    ctx = CliContext(hostname=hostname)
    registry.initialize_context(ctx)
    while not ctx.exit_requested:
        try:
            line = input(prompt or ctx.prompt)
        except EOFError:
            break

        dispatch_line(ctx, registry, line)

    return 0


def run_interactive_cli(
    registry: CommandRegistry,
    prompt: str | None = None,
    hostname: str = "Router",
    history_file: str | os.PathLike[str] | None = None,
) -> int:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        return _run_plain_cli(registry, prompt=prompt, hostname=hostname)

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
    ctx = CliContext(hostname=hostname)
    registry.initialize_context(ctx)

    class RouterCommandLexer(Lexer):
        def lex_document(self, document):
            def get_line(lineno: int):
                line = document.lines[lineno]
                parsed = parser.parse(line, mode=ctx.mode)
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
            for candidate in parser.completions(document.text_before_cursor, mode=ctx.mode):
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

    key_bindings = KeyBindings()

    @key_bindings.add(" ")
    def _(event) -> None:
        buffer = event.current_buffer
        completed = parser.complete_before_space(buffer.document.text_before_cursor, mode=ctx.mode)
        if completed is not None:
            buffer.document = Document(completed, cursor_position=len(completed))
            return
        buffer.insert_text(" ")

    @key_bindings.add("enter")
    def _(event) -> None:
        buffer = event.current_buffer

        if "?" in buffer.text:
            buffer.validate_and_handle()
            return

        parsed = parser.parse(buffer.text, mode=ctx.mode)

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
