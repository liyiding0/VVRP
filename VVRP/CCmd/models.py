from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Literal, Pattern, TextIO


class ParseStatus(str, Enum):
    EMPTY = "empty"
    VALID_UNIQUE = "valid_unique"
    AMBIGUOUS = "ambiguous"
    INVALID = "invalid"


class TokenStyle(str, Enum):
    VALID = "valid"
    AMBIGUOUS = "ambiguous"
    INVALID = "invalid"


@dataclass
class CommandResult:
    ok: bool = True
    message: str = ""
    exit_requested: bool = False


@dataclass
class ModeFrame:
    name: str
    label: str = ""


@dataclass
class CliContext:
    hostname: str = "Router"
    mode_stack: list[ModeFrame] = field(default_factory=lambda: [ModeFrame("user")])
    state: dict[str, Any] = field(default_factory=dict)
    exit_requested: bool = False
    output: TextIO = field(default_factory=lambda: sys.stdout)

    @property
    def mode(self) -> str:
        return self.mode_stack[-1].name

    @property
    def mode_label(self) -> str:
        return self.mode_stack[-1].label

    @property
    def prompt(self) -> str:
        if self.mode == "user":
            return f"<{self.hostname}> "
        if self.mode == "privileged":
            return f"{self.hostname}# "
        if self.mode == "config":
            return f"{self.hostname}(config)# "
        if self.mode == "interface":
            return f"{self.hostname}(config-if-{self.mode_label})# "
        if self.mode == "hidden":
            return f"({self.hostname}-hidden)# "
        return f"{self.hostname}({self.mode})# "

    def write(self, text: str = "") -> None:
        print(text, file=self.output)

    def push_mode(self, name: str, label: str = "") -> None:
        self.mode_stack.append(ModeFrame(name=name, label=label))

    def quit_mode(self) -> None:
        if len(self.mode_stack) > 1:
            self.mode_stack.pop()
        else:
            self.exit_requested = True


CommandHandler = Callable[[CliContext, dict[str, str]], CommandResult | str | None]


@dataclass(frozen=True)
class TokenSpec:
    kind: Literal["literal", "parameter"]
    literal: str | None = None
    name: str | None = None
    pattern_text: str | None = None
    pattern: Pattern[str] | None = None
    remainder: bool = False

    @classmethod
    def literal_token(cls, value: str) -> TokenSpec:
        return cls(kind="literal", literal=value)

    @classmethod
    def parameter_token(
        cls,
        name: str,
        pattern_text: str,
        remainder: bool = False,
    ) -> TokenSpec:
        try:
            pattern = re.compile(pattern_text)
        except re.error as exc:
            raise ValueError(f"Invalid regex for parameter {name!r}: {exc}") from exc
        return cls(
            kind="parameter",
            name=name,
            pattern_text=pattern_text,
            pattern=pattern,
            remainder=remainder,
        )

    @property
    def display(self) -> str:
        if self.kind == "literal":
            return self.literal or ""
        return f"<{self.name}>"

    @property
    def key(self) -> str:
        if self.kind == "literal":
            return self.literal or ""
        return f"<{self.name}>"


@dataclass(frozen=True)
class CommandSpec:
    pattern: str
    tokens: tuple[TokenSpec, ...]
    handler: CommandHandler
    help_text: str = ""
    modes: tuple[str, ...] = ("*",)
    hidden: bool = False

    @property
    def canonical(self) -> str:
        return " ".join(token.display for token in self.tokens)


@dataclass(frozen=True)
class TokenStatus:
    start: int
    end: int
    style: TokenStyle


@dataclass(frozen=True)
class CompletionCandidate:
    text: str
    start_position: int
    display: str
    meta: str = ""


@dataclass(frozen=True)
class HelpCandidate:
    display: str
    help_text: str = ""


@dataclass(frozen=True)
class ParseResult:
    text: str
    status: ParseStatus
    complete_command: str = ""
    command: CommandSpec | None = None
    handler: CommandHandler | None = None
    args: dict[str, str] = field(default_factory=dict)
    token_statuses: tuple[TokenStatus, ...] = ()
    error_position: int | None = None
    candidates: tuple[str, ...] = ()

    @property
    def valid_unique(self) -> bool:
        return self.status == ParseStatus.VALID_UNIQUE

    @property
    def ambiguous(self) -> bool:
        return self.status == ParseStatus.AMBIGUOUS

    @property
    def invalid(self) -> bool:
        return self.status == ParseStatus.INVALID

    @property
    def executable(self) -> bool:
        return self.valid_unique and self.handler is not None
