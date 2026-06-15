from __future__ import annotations

import io
from pathlib import Path
from typing import Any

from .models import CliContext, ModeFrame


DEFAULT_RUNNING_CONFIG_FILE = "running-config"
RUNNING_CONFIG_STATE_KEY = "ccmd.running_config"
RUNNING_CONFIG_PATH_STATE_KEY = "ccmd.running_config.path"
RUNNING_CONFIG_LOADING_STATE_KEY = "ccmd.running_config.loading"


def set_running_config_path(
    ctx: CliContext,
    path: str | Path | None = None,
) -> Path:
    config_path = Path(path or DEFAULT_RUNNING_CONFIG_FILE)
    ctx.state[RUNNING_CONFIG_PATH_STATE_KEY] = config_path
    _config_store(ctx)
    return config_path


def load_running_config(
    ctx: CliContext,
    registry,
    path: str | Path | None = None,
) -> list[str]:
    config_path = set_running_config_path(ctx, path)
    if not config_path.exists():
        return []

    original_stack = [ModeFrame(frame.name, frame.label) for frame in ctx.mode_stack]
    errors: list[str] = []
    ctx.state[RUNNING_CONFIG_LOADING_STATE_KEY] = True
    try:
        _enter_config_mode(ctx)
        skip_indented_block = False
        for number, raw_line in enumerate(config_path.read_text(encoding="utf-8").splitlines(), start=1):
            line = raw_line.strip()
            if not line or line.startswith(("!", "#")):
                continue
            is_indented = raw_line[:1].isspace()
            if skip_indented_block and is_indented:
                continue
            if not is_indented:
                skip_indented_block = False
            outcome = _dispatch_line_silently(ctx, registry, line)
            if outcome.message.startswith("%"):
                errors.append(f"{config_path}:{number}: {outcome.message}: {line}")
                if not is_indented and _is_interface_command(line):
                    skip_indented_block = True
    finally:
        ctx.state[RUNNING_CONFIG_LOADING_STATE_KEY] = False
        ctx.mode_stack = original_stack
    return errors


def set_global_config_command(ctx: CliContext, key: str, line: str) -> str:
    store = _config_store(ctx)
    store["global"][key] = line
    return _autosave(ctx)


def remove_global_config_command(ctx: CliContext, key: str) -> str:
    store = _config_store(ctx)
    store["global"].pop(key, None)
    return _autosave(ctx)


def set_interface_config_command(
    ctx: CliContext,
    interface_name: str,
    key: str,
    line: str,
) -> str:
    commands = _interface_commands(ctx, interface_name)
    commands[key] = line
    return _autosave(ctx)


def remove_interface_config_command(
    ctx: CliContext,
    interface_name: str,
    key: str,
) -> str:
    commands = _interface_commands(ctx, interface_name)
    commands.pop(key, None)
    _drop_empty_interface(ctx, interface_name)
    return _autosave(ctx)


def remove_interface_config_prefix(
    ctx: CliContext,
    interface_name: str,
    prefix: str,
) -> str:
    commands = _interface_commands(ctx, interface_name)
    for key in tuple(commands):
        if key.startswith(prefix):
            commands.pop(key, None)
    _drop_empty_interface(ctx, interface_name)
    return _autosave(ctx)


def interface_config_commands(
    ctx: CliContext,
    interface_name: str,
) -> dict[str, str]:
    commands = _config_store(ctx)["interfaces"].get(interface_name)
    if not isinstance(commands, dict):
        return {}
    return dict(commands)


def render_running_config(ctx: CliContext) -> str:
    store = _config_store(ctx)
    lines: list[str] = []

    for key in _ordered_global_keys(store["global"]):
        lines.append(store["global"][key])

    for interface_name in _ordered_interface_names(store["interfaces"]):
        commands = store["interfaces"][interface_name]
        if not commands:
            continue
        lines.append(f"interface {_format_cli_token(interface_name)}")
        for key in _ordered_interface_command_keys(commands):
            lines.append(f" {commands[key]}")
        lines.append(" quit")

    if not lines:
        return ""
    return "\n".join(lines) + "\n"


def write_running_config(ctx: CliContext) -> None:
    config_path = _running_config_path(ctx)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(render_running_config(ctx), encoding="utf-8")


def _dispatch_line_silently(ctx: CliContext, registry, line: str):
    from .dispatch import dispatch_line

    original_output = ctx.output
    ctx.output = io.StringIO()
    try:
        return dispatch_line(ctx, registry, line)
    finally:
        ctx.output = original_output


def _is_interface_command(line: str) -> bool:
    return line == "interface" or line.startswith("interface ")


def _config_store(ctx: CliContext) -> dict[str, Any]:
    store = ctx.state.get(RUNNING_CONFIG_STATE_KEY)
    if isinstance(store, dict):
        store.setdefault("global", {})
        store.setdefault("interfaces", {})
        return store

    store = {"global": {}, "interfaces": {}}
    ctx.state[RUNNING_CONFIG_STATE_KEY] = store
    return store


def _interface_commands(ctx: CliContext, interface_name: str) -> dict[str, str]:
    store = _config_store(ctx)
    interfaces = store["interfaces"]
    commands = interfaces.get(interface_name)
    if not isinstance(commands, dict):
        commands = {}
        interfaces[interface_name] = commands
    return commands


def _drop_empty_interface(ctx: CliContext, interface_name: str) -> None:
    store = _config_store(ctx)
    commands = store["interfaces"].get(interface_name)
    if isinstance(commands, dict) and not commands:
        store["interfaces"].pop(interface_name, None)


def _autosave(ctx: CliContext) -> str:
    if ctx.state.get(RUNNING_CONFIG_LOADING_STATE_KEY):
        return ""
    try:
        write_running_config(ctx)
    except OSError as exc:
        return f"% running-config write failed: {exc}"
    return ""


def _running_config_path(ctx: CliContext) -> Path:
    value = ctx.state.get(RUNNING_CONFIG_PATH_STATE_KEY)
    if isinstance(value, Path):
        return value
    return set_running_config_path(ctx)


def _enter_config_mode(ctx: CliContext) -> None:
    ctx.mode_stack = [ModeFrame("user"), ModeFrame("privileged"), ModeFrame("config")]


def _ordered_global_keys(commands: dict[str, str]) -> tuple[str, ...]:
    if "hostname" not in commands:
        return tuple(sorted(commands))
    return ("hostname", *tuple(sorted(key for key in commands if key != "hostname")))


def _ordered_interface_names(interfaces: dict[str, dict[str, str]]) -> tuple[str, ...]:
    return tuple(sorted(interfaces, key=str.casefold))


def _ordered_interface_command_keys(commands: dict[str, str]) -> tuple[str, ...]:
    def sort_key(key: str) -> tuple[int, str]:
        if key == "shutdown":
            return (0, key)
        if key == "ip-address-dhcp":
            return (1, key)
        if key == "ip-address:primary":
            return (2, key)
        if key.startswith("ip-address:"):
            return (3, key)
        return (4, key)

    return tuple(sorted(commands, key=sort_key))


def _format_cli_token(token: str) -> str:
    if token and not any(char.isspace() for char in token):
        return token
    escaped = token.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'
