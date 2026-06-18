from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from VVRP.CCmd.models import CommandResult
from VVRP.CCmd.registry import CommandRegistry
from VVRP.CCmd.running_config import (
    RUNNING_CONFIG_LOADING_STATE_KEY,
    remove_host_interface_config_command,
    set_host_interface_config_command,
)
from VVRP.DPlane.Windows.npcap import (
    NpcapDevice,
    NpcapError,
    NpcapLibrary,
    find_npcap_device_for_interface,
)
from VVRP.IFNET.admin import InterfaceAdminProvider
from VVRP.IFNET.discovery import InterfaceDiscoveryError, InterfaceProvider
from VVRP.IFNET.imports import (
    commit_imports,
    imported_ifnet_index_map,
    imported_interface_names,
    pending_import_names,
    stage_import_interface,
    stage_unimport_interface,
)
from VVRP.IFNET.inventory import get_ifnet_manager
from VVRP.IFNET.models import NetworkInterface


DEFAULT_DPLANE_COMMAND_MODES = ("hidden",)
HOST_INTERFACE_NAME_PATTERN = r".+"
BRIGHT_WHITE = "\x1b[38;2;242;242;242m"
ANSI_RESET = "\x1b[0m"


@dataclass(frozen=True)
class DplaneInterfaceRow:
    interface: NetworkInterface
    os_index: str
    vvrp: str
    ifnet_index: str
    npcap_device: str
    status: str


def register_dplane_commands(
    registry: CommandRegistry,
    ifnet_provider: InterfaceProvider | None = None,
    ifnet_admin_provider: InterfaceAdminProvider | None = None,
    npcap_library: NpcapLibrary | None = None,
    modes: Sequence[str] = DEFAULT_DPLANE_COMMAND_MODES,
) -> None:
    @registry.command(
        "show dplane interfaces",
        help_text="Show data-plane interface bindings",
        modes=tuple(modes),
    )
    def show_dplane_interfaces(ctx, args):
        try:
            interfaces = get_ifnet_manager(
                ctx.state,
                provider=ifnet_provider,
                admin_provider=ifnet_admin_provider,
            ).list_interfaces()
            devices = (npcap_library or NpcapLibrary()).list_devices()
        except InterfaceDiscoveryError as exc:
            return CommandResult(ok=False, message=f"% {exc}")
        except NpcapError as exc:
            return CommandResult(ok=False, message=f"% Npcap interface discovery failed: {exc}")

        return CommandResult(message=_format_dplane_interfaces_detail(ctx.state, interfaces, devices))

    @registry.command(
        "show dplane interfaces brief",
        help_text="Show brief data-plane interface bindings",
        modes=tuple(modes),
    )
    def show_dplane_interfaces_brief(ctx, args):
        try:
            interfaces = get_ifnet_manager(
                ctx.state,
                provider=ifnet_provider,
                admin_provider=ifnet_admin_provider,
            ).list_interfaces()
            devices = (npcap_library or NpcapLibrary()).list_devices()
        except InterfaceDiscoveryError as exc:
            return CommandResult(ok=False, message=f"% {exc}")
        except NpcapError as exc:
            return CommandResult(ok=False, message=f"% Npcap interface discovery failed: {exc}")

        return CommandResult(message=_format_dplane_interfaces_brief(ctx.state, interfaces, devices))

    @registry.command(
        f"host interface <name:{HOST_INTERFACE_NAME_PATTERN}>",
        help_text="Enter host interface view",
        modes=("hidden", "host-interface"),
    )
    def host_interface(ctx, args):
        interface = _get_host_interface(ctx, ifnet_provider, ifnet_admin_provider, args["name"])
        if isinstance(interface, CommandResult):
            return interface
        if ctx.mode == "host-interface":
            ctx.mode_stack[-1].label = interface.name
        else:
            ctx.push_mode("host-interface", interface.name)
        return CommandResult()

    def host_interface_name_values(ctx):
        try:
            return tuple(
                interface.name
                for interface in _list_host_interfaces(ctx, ifnet_provider, ifnet_admin_provider)
            )
        except InterfaceDiscoveryError:
            return ()

    registry.parameter_values(("host", "interface"), "name", host_interface_name_values)

    @registry.command(
        "import",
        help_text="Import current host interface into VVRP IFNET",
        modes=("host-interface",),
    )
    def import_interface(ctx, args):
        interface = _get_host_interface(ctx, ifnet_provider, ifnet_admin_provider, ctx.mode_label)
        if isinstance(interface, CommandResult):
            return interface
        devices = _list_npcap_devices(npcap_library)
        if isinstance(devices, CommandResult):
            return devices
        if find_npcap_device_for_interface(interface, devices) is None:
            return CommandResult(
                ok=False,
                message=f"% Host interface is not matched to an Npcap device: {interface.name}",
            )
        stage_import_interface(ctx.state, interface.name)
        if ctx.state.get(RUNNING_CONFIG_LOADING_STATE_KEY):
            commit_imports(ctx.state)
            config_error = _sync_import_config_from_active(ctx, (interface.name,))
            return CommandResult(ok=not config_error, message=config_error)
        return CommandResult(message="% Configuration changed; use commit to apply")

    @registry.command(
        "no import",
        help_text="Remove current host interface from VVRP IFNET imports",
        modes=("host-interface",),
    )
    def no_import_interface(ctx, args):
        interface = _get_host_interface(ctx, ifnet_provider, ifnet_admin_provider, ctx.mode_label)
        if isinstance(interface, CommandResult):
            return interface
        stage_unimport_interface(ctx.state, interface.name)
        if ctx.state.get(RUNNING_CONFIG_LOADING_STATE_KEY):
            commit_imports(ctx.state)
            config_error = _sync_import_config_from_active(ctx, (interface.name,))
            return CommandResult(ok=not config_error, message=config_error)
        return CommandResult(message="% Configuration changed; use commit to apply")

    @registry.command(
        "commit",
        help_text="Commit host interface import configuration",
        modes=("host-interface",),
    )
    def commit_host_interface(ctx, args):
        active_before = imported_interface_names(ctx.state)
        pending_before = pending_import_names(ctx.state)
        commit_imports(ctx.state)
        config_error = _sync_import_config_from_active(
            ctx,
            active_before | pending_before | imported_interface_names(ctx.state),
        )
        if config_error:
            return CommandResult(ok=False, message=config_error)
        return CommandResult(message="Commit complete")

def _list_host_interfaces(
    ctx,
    ifnet_provider: InterfaceProvider | None,
    ifnet_admin_provider: InterfaceAdminProvider | None,
) -> tuple[NetworkInterface, ...]:
    return get_ifnet_manager(
        ctx.state,
        provider=ifnet_provider,
        admin_provider=ifnet_admin_provider,
    ).list_interfaces()


def _sync_import_config_from_active(ctx, interface_names) -> str:
    active_imports = imported_interface_names(ctx.state)
    for name in sorted(interface_names, key=str.casefold):
        if name in active_imports:
            config_error = set_host_interface_config_command(
                ctx,
                name,
                "import",
                "import",
                autosave=False,
            )
        else:
            config_error = remove_host_interface_config_command(
                ctx,
                name,
                "import",
                autosave=False,
            )
        if config_error:
            return config_error
    return ""


def _get_host_interface(
    ctx,
    ifnet_provider: InterfaceProvider | None,
    ifnet_admin_provider: InterfaceAdminProvider | None,
    name: str,
) -> NetworkInterface | CommandResult:
    try:
        interface = get_ifnet_manager(
            ctx.state,
            provider=ifnet_provider,
            admin_provider=ifnet_admin_provider,
        ).get_interface(name)
    except InterfaceDiscoveryError as exc:
        return CommandResult(ok=False, message=f"% {exc}")

    if interface is None:
        return CommandResult(ok=False, message=f"% Host interface not found: {name}")
    return interface


def _list_npcap_devices(npcap_library: NpcapLibrary | None) -> tuple[NpcapDevice, ...] | CommandResult:
    try:
        return (npcap_library or NpcapLibrary()).list_devices()
    except NpcapError as exc:
        return CommandResult(ok=False, message=f"% Npcap interface discovery failed: {exc}")


def _format_dplane_interfaces_detail(
    state: dict,
    interfaces: tuple[NetworkInterface, ...],
    devices: tuple[NpcapDevice, ...],
) -> str:
    if not interfaces:
        return "No IFNET interfaces found"

    rows = _dplane_interface_rows(state, interfaces, devices)
    blocks: list[str] = []
    for row in rows:
        block = [
            f"Host interface : {row.interface.name}",
            f"OS Index       : {row.os_index}",
            f"VVRP           : {_highlight_dplane_word(row.vvrp)}",
            f"IFNET Index    : {row.ifnet_index}",
            f"Npcap Device   : {row.npcap_device}",
            f"Status         : {_highlight_dplane_word(row.status)}",
        ]
        blocks.append("\n".join(block))
    return "\n\n".join(blocks)


def _format_dplane_interfaces_brief(
    state: dict,
    interfaces: tuple[NetworkInterface, ...],
    devices: tuple[NpcapDevice, ...],
) -> str:
    rows = _dplane_interface_rows(state, interfaces, devices)
    lines = [
        f"{'Host Interface':<32} {'OS Index':<8} {'IFNET Index':<12} Status",
    ]
    for row in rows:
        lines.append(
            f"{row.interface.name:<32} "
            f"{row.os_index:<8} "
            f"{row.ifnet_index:<12} "
            f"{_highlight_dplane_word(row.status)}"
        )
    if not interfaces:
        lines.append("No IFNET interfaces found")
    return "\n".join(lines)


def _dplane_interface_rows(
    state: dict,
    interfaces: tuple[NetworkInterface, ...],
    devices: tuple[NpcapDevice, ...],
) -> tuple[DplaneInterfaceRow, ...]:
    active_imports = imported_interface_names(state)
    pending_imports = pending_import_names(state)
    imported_indices = imported_ifnet_index_map(state, interfaces)
    rows: list[DplaneInterfaceRow] = []
    for interface in interfaces:
        device = find_npcap_device_for_interface(interface, devices)
        if device is None:
            device_name = "-"
            status = "unmatched"
        elif interface.name in active_imports:
            device_name = device.name
            status = "imported"
        elif interface.name in pending_imports:
            device_name = device.name
            status = "pending"
        else:
            device_name = device.name
            status = "matched"
        rows.append(
            DplaneInterfaceRow(
                interface=interface,
                os_index=_display_os_index(interface.index),
                vvrp=_display_vvrp_import_state(interface.name, active_imports),
                ifnet_index=_display_ifnet_index(imported_indices.get(interface.name)),
                npcap_device=device_name,
                status=status,
            )
        )
    return tuple(rows)


def _display_ifnet_index(ifnet_index: int | None) -> str:
    if ifnet_index is None:
        return "-"
    return f"0x{ifnet_index:x}"


def _display_vvrp_import_state(name: str, active_imports: frozenset[str]) -> str:
    if name in active_imports:
        return "Imported"
    return "-"


def _display_os_index(index: int | None) -> str:
    if index is None:
        return "-"
    return str(index)


def _format_dplane_cell(value: str, width: int) -> str:
    return _highlight_dplane_word(value) + (" " * max(0, width - len(value)))


def _highlight_dplane_word(value: str) -> str:
    if value in ("Imported", "matched"):
        return f"{BRIGHT_WHITE}{value}{ANSI_RESET}"
    return value


def _format_cli_token(token: str) -> str:
    if token and not any(char.isspace() for char in token):
        return token
    escaped = token.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'
