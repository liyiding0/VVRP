from __future__ import annotations

import re
from dataclasses import dataclass, field
from collections.abc import Sequence
from typing import Callable, Iterable

from .models import CliContext, CommandHandler, CommandSpec, TokenSpec


_PARAMETER_TOKEN_RE = re.compile(r"^<([A-Za-z_][A-Za-z0-9_]*):(.+)>$")
_REMAINDER_TOKEN_RE = re.compile(r"^<([A-Za-z_][A-Za-z0-9_]*)\.\.\.:(.+)>$")


@dataclass
class TrieEdge:
    token: TokenSpec
    node: TrieNode


@dataclass
class TrieNode:
    literal_edges: dict[str, TrieEdge] = field(default_factory=dict)
    parameter_edges: list[TrieEdge] = field(default_factory=list)
    command: CommandSpec | None = None


class CommandRegistry:
    def __init__(self) -> None:
        self.root = TrieNode()
        self._commands_by_key: dict[tuple[str, ...], CommandSpec] = {}
        self._roots_by_mode: dict[str, TrieNode] = {}
        self._context_initializers: list[Callable[[CliContext], None]] = []
        self._parameter_value_providers: dict[
            tuple[tuple[str, ...], str],
            Callable[[CliContext], Iterable[str]],
        ] = {}

    @property
    def commands(self) -> tuple[CommandSpec, ...]:
        return tuple(sorted(self._commands_by_key.values(), key=lambda item: item.canonical))

    def command(
        self,
        pattern: str,
        help_text: str = "",
        modes: str | Iterable[str] = "*",
        hidden: bool = False,
    ) -> Callable[[CommandHandler], CommandHandler]:
        def decorator(handler: CommandHandler) -> CommandHandler:
            self.register(pattern, handler, help_text=help_text, modes=modes, hidden=hidden)
            return handler

        return decorator

    def register(
        self,
        pattern: str,
        handler: CommandHandler,
        help_text: str = "",
        modes: str | Iterable[str] = "*",
        hidden: bool = False,
    ) -> CommandSpec:
        tokens = tuple(self._parse_pattern(pattern))
        if not tokens:
            raise ValueError("Command pattern must contain at least one token")

        key = tuple(token.key for token in tokens)
        if key in self._commands_by_key:
            raise ValueError(f"Duplicate command pattern: {pattern!r}")

        spec = CommandSpec(
            pattern=pattern,
            tokens=tokens,
            handler=handler,
            help_text=help_text,
            modes=self._normalize_modes(modes),
            hidden=hidden,
        )
        self._insert_into_root(self.root, spec)
        self._commands_by_key[key] = spec
        self._roots_by_mode.clear()
        return spec

    def root_for_mode(self, mode: str) -> TrieNode:
        root = self._roots_by_mode.get(mode)
        if root is not None:
            return root

        root = TrieNode()
        for command in self._commands_by_key.values():
            if "*" in command.modes or mode in command.modes:
                self._insert_into_root(root, command)

        self._roots_by_mode[mode] = root
        return root

    def commands_for_mode(self, mode: str) -> tuple[CommandSpec, ...]:
        commands = [
            command
            for command in self._commands_by_key.values()
            if ("*" in command.modes or mode in command.modes) and not command.hidden
        ]
        return tuple(sorted(commands, key=lambda item: item.canonical))

    def context_initializer(
        self,
        initializer: Callable[[CliContext], None],
    ) -> Callable[[CliContext], None]:
        self._context_initializers.append(initializer)
        return initializer

    def initialize_context(self, ctx: CliContext) -> None:
        for initializer in self._context_initializers:
            initializer(ctx)

    def parameter_values(
        self,
        prefix: Sequence[str],
        name: str,
        provider: Callable[[CliContext], Iterable[str]],
    ) -> None:
        self._parameter_value_providers[(tuple(prefix), name)] = provider

    def values_for_parameter(
        self,
        prefix: Sequence[str],
        name: str,
        ctx: CliContext | None,
    ) -> tuple[str, ...] | None:
        provider = self._parameter_value_providers.get((tuple(prefix), name))
        if provider is None or ctx is None:
            return None
        return tuple(dict.fromkeys(provider(ctx)))

    def _parse_pattern(self, pattern: str) -> Iterable[TokenSpec]:
        for raw_token in pattern.split():
            remainder_match = _REMAINDER_TOKEN_RE.fullmatch(raw_token)
            if remainder_match:
                name, regex_text = remainder_match.groups()
                yield TokenSpec.parameter_token(name, regex_text, remainder=True)
                continue

            match = _PARAMETER_TOKEN_RE.fullmatch(raw_token)
            if match:
                name, regex_text = match.groups()
                yield TokenSpec.parameter_token(name, regex_text)
            else:
                if raw_token.startswith("<") or raw_token.endswith(">"):
                    raise ValueError(f"Invalid parameter token syntax: {raw_token!r}")
                yield TokenSpec.literal_token(raw_token)

    def _get_or_create_edge(self, node: TrieNode, token: TokenSpec) -> TrieEdge:
        if token.kind == "literal":
            assert token.literal is not None
            edge = node.literal_edges.get(token.literal)
            if edge is None:
                edge = TrieEdge(token=token, node=TrieNode())
                node.literal_edges[token.literal] = edge
            return edge

        for edge in node.parameter_edges:
            if (
                edge.token.name == token.name
                and edge.token.pattern_text == token.pattern_text
            ):
                return edge

        edge = TrieEdge(token=token, node=TrieNode())
        node.parameter_edges.append(edge)
        return edge

    def _insert_into_root(self, root: TrieNode, spec: CommandSpec) -> None:
        node = root
        for token in spec.tokens:
            edge = self._get_or_create_edge(node, token)
            node = edge.node

        if node.command is not None:
            raise ValueError(f"Duplicate command path: {spec.pattern!r}")

        node.command = spec

    def _normalize_modes(self, modes: str | Iterable[str]) -> tuple[str, ...]:
        if isinstance(modes, str):
            normalized = (modes,)
        else:
            normalized = tuple(modes)

        if not normalized:
            raise ValueError("At least one mode must be supplied")
        if any(not mode or not isinstance(mode, str) for mode in normalized):
            raise ValueError("Modes must be non-empty strings")
        if "*" in normalized and len(normalized) > 1:
            raise ValueError("Wildcard mode '*' cannot be combined with specific modes")

        return tuple(dict.fromkeys(normalized))
