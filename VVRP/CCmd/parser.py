from __future__ import annotations

from dataclasses import dataclass

from .models import (
    CliContext,
    CompletionCandidate,
    HelpCandidate,
    ParseResult,
    ParseStatus,
    TokenStatus,
    TokenStyle,
)
from .registry import CommandRegistry, TrieEdge, TrieNode


@dataclass(frozen=True)
class _TokenSlice:
    text: str
    start: int
    end: int


@dataclass(frozen=True)
class _EdgeMatch:
    edge: TrieEdge
    style: TokenStyle = TokenStyle.VALID
    candidates: tuple[str, ...] = ()


def _scan_tokens(text: str) -> tuple[list[_TokenSlice], bool]:
    tokens: list[_TokenSlice] = []
    index = 0
    while index < len(text):
        if text[index].isspace():
            index += 1
            continue

        start = index
        if text[index] == '"':
            token, index = _scan_quoted_token(text, index)
            tokens.append(_TokenSlice(token, start, index))
            continue

        while index < len(text) and not text[index].isspace():
            index += 1
        tokens.append(_TokenSlice(text[start:index], start, index))

    trailing_space = bool(text) and text[-1].isspace()
    return tokens, trailing_space


def _scan_quoted_token(text: str, start: int) -> tuple[str, int]:
    index = start + 1
    token_chars: list[str] = []
    while index < len(text):
        char = text[index]
        if char == "\\" and index + 1 < len(text):
            token_chars.append(text[index + 1])
            index += 2
            continue
        if char == '"':
            return "".join(token_chars), index + 1
        token_chars.append(char)
        index += 1

    return "".join(token_chars), index


class CommandParser:
    def __init__(self, registry: CommandRegistry) -> None:
        self.registry = registry

    def parse(
        self,
        text: str,
        mode: str = "user",
        ctx: CliContext | None = None,
    ) -> ParseResult:
        root = self.registry.root_for_mode(mode)
        token_slices, _ = _scan_tokens(text)
        if not token_slices:
            return ParseResult(
                text=text,
                status=ParseStatus.EMPTY,
                candidates=tuple(self._candidate_names(root)),
            )

        node = root
        args: dict[str, str] = {}
        resolved_tokens: list[str] = []
        token_statuses: list[TokenStatus] = []

        for index, token_slice in enumerate(token_slices):
            if token_slice.text == "?":
                help_candidates = self.help_candidates(
                    text[: token_slice.start],
                    mode=mode,
                    ctx=ctx,
                )
                if help_candidates:
                    token_statuses.append(
                        TokenStatus(token_slice.start, token_slice.end, TokenStyle.VALID)
                    )
                    token_statuses.extend(
                        TokenStatus(rest.start, rest.end, TokenStyle.INVALID)
                        for rest in token_slices[index + 1 :]
                    )
                    return ParseResult(
                        text=text,
                        status=ParseStatus.VALID_UNIQUE,
                        complete_command=" ".join([*resolved_tokens, "?"]),
                        args=args,
                        token_statuses=tuple(token_statuses),
                        candidates=tuple(candidate.display for candidate in help_candidates),
                    )

                token_statuses.append(
                    TokenStatus(token_slice.start, token_slice.end, TokenStyle.INVALID)
                )
                return ParseResult(
                    text=text,
                    status=ParseStatus.INVALID,
                    complete_command=" ".join(resolved_tokens),
                    args=args,
                    token_statuses=tuple(token_statuses),
                    error_position=token_slice.start,
                )

            matches = self._match_edges(node, token_slice.text, resolved_tokens, ctx)
            if not matches:
                token_statuses.append(
                    TokenStatus(token_slice.start, token_slice.end, TokenStyle.INVALID)
                )
                token_statuses.extend(
                    TokenStatus(rest.start, rest.end, TokenStyle.INVALID)
                    for rest in token_slices[index + 1 :]
                )
                return ParseResult(
                    text=text,
                    status=ParseStatus.INVALID,
                    complete_command=" ".join(resolved_tokens),
                    args=args,
                    token_statuses=tuple(token_statuses),
                    error_position=token_slice.start,
                    candidates=tuple(self._candidate_names(node)),
                )

            if len(matches) > 1 or matches[0].style == TokenStyle.AMBIGUOUS:
                token_statuses.append(
                    TokenStatus(token_slice.start, token_slice.end, TokenStyle.AMBIGUOUS)
                )
                token_statuses.extend(
                    TokenStatus(rest.start, rest.end, TokenStyle.INVALID)
                    for rest in token_slices[index + 1 :]
                )
                return ParseResult(
                    text=text,
                    status=ParseStatus.AMBIGUOUS,
                    complete_command=" ".join(resolved_tokens),
                    args=args,
                    token_statuses=tuple(token_statuses),
                    error_position=token_slice.start,
                    candidates=matches[0].candidates
                    or tuple(match.edge.token.display for match in matches),
                )

            edge = matches[0].edge
            if edge.token.remainder:
                remainder_text = text[token_slice.start:].strip()
                assert edge.token.name is not None
                args[edge.token.name] = remainder_text
                resolved_tokens.append(_format_resolved_token(remainder_text))
                token_statuses.append(
                    TokenStatus(token_slice.start, len(text), TokenStyle.VALID)
                )
                node = edge.node
                break

            token_statuses.append(
                TokenStatus(token_slice.start, token_slice.end, TokenStyle.VALID)
            )
            if edge.token.kind == "literal":
                resolved_tokens.append(edge.token.literal or "")
            else:
                assert edge.token.name is not None
                args[edge.token.name] = token_slice.text
                resolved_tokens.append(_format_resolved_token(token_slice.text))
            node = edge.node

        command = node.command
        return ParseResult(
            text=text,
            status=ParseStatus.VALID_UNIQUE,
            complete_command=" ".join(resolved_tokens),
            command=command,
            handler=command.handler if command is not None else None,
            args=args,
            token_statuses=tuple(token_statuses),
            candidates=tuple(self._candidate_names(node)),
        )

    def completions(
        self,
        text_before_cursor: str,
        mode: str = "user",
        ctx: CliContext | None = None,
    ) -> tuple[CompletionCandidate, ...]:
        token_slices, trailing_space = _scan_tokens(text_before_cursor)
        node = self.registry.root_for_mode(mode)

        if trailing_space:
            prefix = ""
            previous_tokens = token_slices
        elif token_slices:
            prefix = token_slices[-1].text
            previous_tokens = token_slices[:-1]
        else:
            prefix = ""
            previous_tokens = []

        for token_slice in previous_tokens:
            matches = self._match_edges(node, token_slice.text, [], ctx)
            if len(matches) != 1 or matches[0].style != TokenStyle.VALID:
                return ()
            node = matches[0].edge.node

        candidates: list[CompletionCandidate] = []
        start_position = -len(prefix) if prefix else 0
        literal_names = sorted(node.literal_edges)

        for name in literal_names:
            edge = node.literal_edges[name]
            if self._edge_is_hidden(edge):
                continue
            if not prefix or name.startswith(prefix):
                meta = edge.node.command.help_text if edge.node.command else ""
                candidates.append(
                    CompletionCandidate(
                        text=name,
                        start_position=start_position,
                        display=name,
                        meta=meta,
                    )
                )

        for edge in node.parameter_edges:
            if self._edge_is_hidden(edge):
                continue
            dynamic_values = self._parameter_values(edge, [item.text for item in previous_tokens], ctx)
            if dynamic_values is not None:
                for value in sorted(dynamic_values):
                    if not prefix or value.startswith(prefix):
                        candidates.append(
                            CompletionCandidate(
                                text=_format_resolved_token(value),
                                start_position=start_position,
                                display=value,
                                meta=edge.token.display,
                            )
                        )
                continue
            if not prefix:
                candidates.append(
                    CompletionCandidate(
                        text="",
                        start_position=0,
                        display=edge.token.display,
                        meta=edge.token.pattern_text or "",
                    )
                )

        return tuple(candidates)

    def complete_before_space(
        self,
        text_before_cursor: str,
        mode: str = "user",
        ctx: CliContext | None = None,
    ) -> str | None:
        if not text_before_cursor or text_before_cursor[-1].isspace():
            return None

        parsed = self.parse(text_before_cursor, mode=mode, ctx=ctx)
        if not parsed.valid_unique or not parsed.complete_command:
            return None

        if parsed.complete_command == text_before_cursor.strip():
            return None

        return f"{parsed.complete_command} "

    def help_candidates(
        self,
        text_before_question: str,
        mode: str = "user",
        ctx: CliContext | None = None,
    ) -> tuple[HelpCandidate, ...]:
        text_before_question = text_before_question.split("?", 1)[0]
        token_slices, trailing_space = _scan_tokens(text_before_question)
        node = self.registry.root_for_mode(mode)

        if trailing_space:
            prefix = ""
            previous_tokens = token_slices
        elif token_slices:
            prefix = token_slices[-1].text
            previous_tokens = token_slices[:-1]
        else:
            prefix = ""
            previous_tokens = []

        for token_slice in previous_tokens:
            matches = self._match_edges(node, token_slice.text, [], ctx)
            if len(matches) != 1 or matches[0].style != TokenStyle.VALID:
                return ()
            node = matches[0].edge.node

        candidates: list[HelpCandidate] = []
        for name, edge in sorted(node.literal_edges.items()):
            if self._edge_is_hidden(edge):
                continue
            if not prefix or name.startswith(prefix):
                candidates.append(
                    HelpCandidate(
                        display=name,
                        help_text=self._edge_help_text(edge),
                    )
                )

        for edge in node.parameter_edges:
            if self._edge_is_hidden(edge):
                continue
            dynamic_values = self._parameter_values(edge, [item.text for item in previous_tokens], ctx)
            if dynamic_values is not None:
                for value in sorted(dynamic_values):
                    if not prefix or value.startswith(prefix):
                        candidates.append(
                            HelpCandidate(
                                display=value,
                                help_text=self._edge_help_text(edge),
                            )
                        )
                continue
            if not prefix or self._parameter_accepts_prefix(edge, prefix):
                candidates.append(
                    HelpCandidate(
                        display=edge.token.display,
                        help_text=self._edge_help_text(edge),
                    )
                )

        if prefix == "" and node.command is not None and not node.command.hidden:
            candidates.append(HelpCandidate(display="<cr>", help_text=node.command.help_text))

        return tuple(candidates)

    def _match_edges(
        self,
        node: TrieNode,
        value: str,
        resolved_tokens: list[str],
        ctx: CliContext | None,
    ) -> list[_EdgeMatch]:
        exact = node.literal_edges.get(value)
        if exact is not None:
            return [_EdgeMatch(exact)]

        literal_matches = [
            edge for name, edge in sorted(node.literal_edges.items()) if name.startswith(value)
        ]
        if literal_matches:
            return [_EdgeMatch(edge) for edge in literal_matches]

        parameter_matches: list[_EdgeMatch] = []
        for edge in node.parameter_edges:
            if edge.token.pattern is None or edge.token.pattern.fullmatch(value) is None:
                continue

            dynamic_values = self._parameter_values(edge, resolved_tokens, ctx)
            if dynamic_values is None:
                parameter_matches.append(_EdgeMatch(edge))
                continue

            if value in dynamic_values:
                parameter_matches.append(_EdgeMatch(edge, TokenStyle.VALID, (value,)))
                continue

            prefix_matches = tuple(
                value_candidate
                for value_candidate in sorted(dynamic_values)
                if value_candidate.startswith(value)
            )
            if prefix_matches:
                parameter_matches.append(
                    _EdgeMatch(edge, TokenStyle.AMBIGUOUS, prefix_matches)
                )
        return parameter_matches

    def _candidate_names(self, node: TrieNode) -> list[str]:
        names = sorted(node.literal_edges)
        names.extend(edge.token.display for edge in node.parameter_edges)
        return names

    def _parameter_accepts_prefix(self, edge: TrieEdge, prefix: str) -> bool:
        if edge.token.pattern is None:
            return False
        return (
            edge.token.display.startswith(prefix)
            or edge.token.pattern.fullmatch(prefix) is not None
        )

    def _parameter_values(
        self,
        edge: TrieEdge,
        resolved_tokens: list[str],
        ctx: CliContext | None,
    ) -> tuple[str, ...] | None:
        if edge.token.name is None:
            return None
        return self.registry.values_for_parameter(resolved_tokens, edge.token.name, ctx)

    def _edge_help_text(self, edge: TrieEdge) -> str:
        if edge.node.command is not None and edge.node.command.help_text:
            return edge.node.command.help_text

        commands = self._visible_descendant_commands(edge.node)
        if len(commands) == 1:
            return commands[0].help_text

        return ""

    def _descendant_commands(self, node: TrieNode):
        commands = []
        if node.command is not None:
            commands.append(node.command)
        for edge in node.literal_edges.values():
            commands.extend(self._descendant_commands(edge.node))
        for edge in node.parameter_edges:
            commands.extend(self._descendant_commands(edge.node))
        return commands

    def _edge_is_hidden(self, edge: TrieEdge) -> bool:
        commands = self._descendant_commands(edge.node)
        return bool(commands) and all(command.hidden for command in commands)

    def _visible_descendant_commands(self, node: TrieNode):
        return [command for command in self._descendant_commands(node) if not command.hidden]


def _format_resolved_token(token: str) -> str:
    if token and not any(char.isspace() for char in token):
        return token
    escaped = token.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'
