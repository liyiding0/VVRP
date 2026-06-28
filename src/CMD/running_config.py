from __future__ import annotations

import io
import os
from pathlib import Path
from typing import Any

from .models import CliContext, ModeFrame


DEFAULT_SAVED_CONFIGURATION_FILE = "saved-configuration"
DEFAULT_RUNNING_CONFIG_FILE = DEFAULT_SAVED_CONFIGURATION_FILE
RUNNING_CONFIG_STATE_KEY = "cmd.running_configuration"
SAVED_CONFIGURATION_PATH_STATE_KEY = "cmd.saved_configuration.path"
RUNNING_CONFIG_PATH_STATE_KEY = SAVED_CONFIGURATION_PATH_STATE_KEY
RUNNING_CONFIG_LOADING_STATE_KEY = "cmd.saved_configuration.loading"


def default_saved_configuration_path() -> Path:
    return default_runtime_directory() / DEFAULT_SAVED_CONFIGURATION_FILE


def default_runtime_directory() -> Path:
    configured = os.environ.get("VVRP_RUNTIME_DIR")
    if configured:
        return Path(configured)
    return Path(__file__).parent.parent.parent


def set_saved_configuration_path(
    ctx: CliContext,
    path: str | Path | None = None,
) -> Path:
    config_path = _resolve_configuration_path(path)
    ctx.state[SAVED_CONFIGURATION_PATH_STATE_KEY] = config_path
    _config_store(ctx)
    return config_path


def set_running_config_path(
    ctx: CliContext,
    path: str | Path | None = None,
) -> Path:
    return set_saved_configuration_path(ctx, path)


def load_saved_configuration(
    ctx: CliContext,
    registry,
    path: str | Path | None = None,
) -> list[str]:
    config_path = set_saved_configuration_path(ctx, path)
    if not config_path.exists():
        return []

    original_stack = [ModeFrame(frame.name, frame.label) for frame in ctx.mode_stack]
    errors: list[str] = []
    ctx.state[RUNNING_CONFIG_LOADING_STATE_KEY] = True
    try:
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
            line = _prepare_running_config_mode(ctx, line, is_indented)
            outcome = _dispatch_line_silently(ctx, registry, line)
            if outcome.message.startswith("%"):
                errors.append(f"{config_path}:{number}: {outcome.message}: {line}")
                if not is_indented and _is_interface_command(line):
                    skip_indented_block = True
    finally:
        ctx.state[RUNNING_CONFIG_LOADING_STATE_KEY] = False
        ctx.mode_stack = original_stack
    return errors


def load_running_config(
    ctx: CliContext,
    registry,
    path: str | Path | None = None,
) -> list[str]:
    return load_saved_configuration(ctx, registry, path)


def set_global_config_command(
    ctx: CliContext,
    key: str,
    line: str,
    autosave: bool = False,
) -> str:
    store = _config_store(ctx)
    store["global"][key] = line
    if not autosave:
        return ""
    return _autosave(ctx)


def remove_global_config_command(
    ctx: CliContext,
    key: str,
    autosave: bool = False,
) -> str:
    store = _config_store(ctx)
    store["global"].pop(key, None)
    if not autosave:
        return ""
    return _autosave(ctx)


def set_interface_config_command(
    ctx: CliContext,
    interface_name: str,
    key: str,
    line: str,
    autosave: bool = False,
) -> str:
    commands = _interface_commands(ctx, interface_name)
    commands[key] = line
    if not autosave:
        return ""
    return _autosave(ctx)


def remove_interface_config_command(
    ctx: CliContext,
    interface_name: str,
    key: str,
    autosave: bool = False,
) -> str:
    commands = _interface_commands(ctx, interface_name)
    commands.pop(key, None)
    _drop_empty_interface(ctx, interface_name)
    if not autosave:
        return ""
    return _autosave(ctx)


def remove_interface_config_prefix(
    ctx: CliContext,
    interface_name: str,
    prefix: str,
    autosave: bool = False,
) -> str:
    commands = _interface_commands(ctx, interface_name)
    for key in tuple(commands):
        if key.startswith(prefix):
            commands.pop(key, None)
    _drop_empty_interface(ctx, interface_name)
    if not autosave:
        return ""
    return _autosave(ctx)


def interface_config_commands(
    ctx: CliContext,
    interface_name: str,
) -> dict[str, str]:
    commands = _config_store(ctx)["interfaces"].get(interface_name)
    if not isinstance(commands, dict):
        return {}
    return dict(commands)


def set_host_interface_config_command(
    ctx: CliContext,
    interface_name: str,
    key: str,
    line: str,
    autosave: bool = False,
) -> str:
    commands = _host_interface_commands(ctx, interface_name)
    commands[key] = line
    if not autosave:
        return ""
    return _autosave(ctx)


def remove_host_interface_config_command(
    ctx: CliContext,
    interface_name: str,
    key: str,
    autosave: bool = False,
) -> str:
    commands = _host_interface_commands(ctx, interface_name)
    commands.pop(key, None)
    _drop_empty_host_interface(ctx, interface_name)
    if not autosave:
        return ""
    return _autosave(ctx)


def remove_host_interface_config_prefix(
    ctx: CliContext,
    interface_name: str,
    prefix: str,
    autosave: bool = False,
) -> str:
    commands = _host_interface_commands(ctx, interface_name)
    for key in tuple(commands):
        if key.startswith(prefix):
            commands.pop(key, None)
    _drop_empty_host_interface(ctx, interface_name)
    if not autosave:
        return ""
    return _autosave(ctx)


def host_interface_config_commands(
    ctx: CliContext,
    interface_name: str,
) -> dict[str, str]:
    commands = _config_store(ctx)["host_interfaces"].get(interface_name)
    if not isinstance(commands, dict):
        return {}
    return dict(commands)


def render_host_interface_config(ctx: CliContext, interface_name: str) -> str:
    commands = host_interface_config_commands(ctx, interface_name)
    if not commands:
        return ""

    lines = [f"host interface {_format_cli_token(interface_name)}"]
    for key in _ordered_host_interface_command_keys(commands):
        lines.append(f" {commands[key]}")
    lines.append(" quit")
    return "\n".join(lines) + "\n"


def render_interface_config(ctx: CliContext, interface_name: str) -> str:
    commands = interface_config_commands(ctx, interface_name)
    if not commands:
        return ""

    lines = [f"interface {_format_cli_token(interface_name)}"]
    for key in _ordered_interface_command_keys(commands):
        lines.append(f" {commands[key]}")
    lines.append(" quit")
    return "\n".join(lines) + "\n"


def render_running_configuration(ctx: CliContext) -> str:
    store = _config_store(ctx)
    lines: list[str] = []

    for key in _ordered_global_keys(store["global"]):
        lines.append(store["global"][key])

    for interface_name in _ordered_interface_names(store["host_interfaces"]):
        rendered = render_host_interface_config(ctx, interface_name).rstrip()
        if rendered:
            lines.extend(rendered.splitlines())

    for interface_name in _ordered_interface_names(store["interfaces"]):
        rendered = render_interface_config(ctx, interface_name).rstrip()
        if rendered:
            lines.extend(rendered.splitlines())

    if not lines:
        return ""
    return "\n".join(lines) + "\n"


def render_running_config(ctx: CliContext) -> str:
    return render_running_configuration(ctx)


def read_saved_configuration(ctx: CliContext) -> str:
    config_path = _saved_configuration_path(ctx)
    if not config_path.exists():
        return ""
    return config_path.read_text(encoding="utf-8")


def write_saved_configuration(ctx: CliContext) -> None:
    config_path = _saved_configuration_path(ctx)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(render_running_configuration(ctx), encoding="utf-8")


def write_running_config(ctx: CliContext) -> None:
    write_saved_configuration(ctx)


def _dispatch_line_silently(ctx: CliContext, registry, line: str):
    from .dispatch import dispatch_line

    original_output = ctx.output
    ctx.output = io.StringIO()
    try:
        return dispatch_line(ctx, registry, line)
    finally:
        ctx.output = original_output


def _is_interface_command(line: str) -> bool:
    return (
        _is_host_interface_command(line)
        or _is_legacy_interface_command(line)
    )


def _is_host_interface_command(line: str) -> bool:
    return line == "host interface" or line.startswith("host interface ")


def _is_legacy_interface_command(line: str) -> bool:
    return line == "interface" or line.startswith("interface ")


def _config_store(ctx: CliContext) -> dict[str, Any]:
    store = ctx.state.get(RUNNING_CONFIG_STATE_KEY)
    if isinstance(store, dict):
        store.setdefault("global", {})
        store.setdefault("host_interfaces", {})
        store.setdefault("interfaces", {})
        return store

    store = {"global": {}, "host_interfaces": {}, "interfaces": {}}
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


def _host_interface_commands(ctx: CliContext, interface_name: str) -> dict[str, str]:
    store = _config_store(ctx)
    interfaces = store["host_interfaces"]
    commands = interfaces.get(interface_name)
    if not isinstance(commands, dict):
        commands = {}
        interfaces[interface_name] = commands
    return commands


def _drop_empty_host_interface(ctx: CliContext, interface_name: str) -> None:
    store = _config_store(ctx)
    commands = store["host_interfaces"].get(interface_name)
    if isinstance(commands, dict) and not commands:
        store["host_interfaces"].pop(interface_name, None)


def _autosave(ctx: CliContext) -> str:
    if ctx.state.get(RUNNING_CONFIG_LOADING_STATE_KEY):
        return ""
    try:
        write_saved_configuration(ctx)
    except OSError as exc:
        return f"% saved-configuration write failed: {exc}"
    return ""


def _saved_configuration_path(ctx: CliContext) -> Path:
    value = ctx.state.get(SAVED_CONFIGURATION_PATH_STATE_KEY)
    if isinstance(value, Path):
        return value
    return set_saved_configuration_path(ctx)


def _running_config_path(ctx: CliContext) -> Path:
    return _saved_configuration_path(ctx)


def _resolve_configuration_path(path: str | Path | None) -> Path:
    if path is None:
        return default_saved_configuration_path()
    config_path = Path(path)
    if config_path.is_absolute():
        return config_path
    return default_runtime_directory() / config_path


def _enter_config_mode(ctx: CliContext) -> None:
    ctx.mode_stack = [ModeFrame("user"), ModeFrame("privileged"), ModeFrame("config")]


def _enter_hidden_mode(ctx: CliContext) -> None:
    ctx.mode_stack = [ModeFrame("user"), ModeFrame("hidden")]


def _prepare_running_config_mode(ctx: CliContext, line: str, is_indented: bool) -> str:
    if is_indented:
        return line
    if _is_host_interface_command(line):
        _enter_hidden_mode(ctx)
        return line
    if _is_legacy_interface_command(line):
        _enter_config_mode(ctx)
        return line
    _enter_config_mode(ctx)
    return line


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
        if key == "mtu":
            return (1, key)
        if key == "mac-address":
            return (2, key)
        if key == "ip-address-dhcp":
            return (3, key)
        if key == "ip-address:primary":
            return (4, key)
        if key.startswith("ip-address:"):
            return (5, key)
        return (6, key)

    return tuple(sorted(commands, key=sort_key))


def _ordered_host_interface_command_keys(commands: dict[str, str]) -> tuple[str, ...]:
    def sort_key(key: str) -> tuple[int, str]:
        if key == "import":
            return (0, key)
        if key == "shutdown":
            return (1, key)
        if key == "ip-address-dhcp":
            return (2, key)
        if key == "ip-address:primary":
            return (3, key)
        if key.startswith("ip-address:"):
            return (4, key)
        return (5, key)

    return tuple(sorted(commands, key=sort_key))


def _format_cli_token(token: str) -> str:
    if token and not any(char.isspace() for char in token):
        return token
    escaped = token.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'
