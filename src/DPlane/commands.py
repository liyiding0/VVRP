from __future__ import annotations

from collections.abc import Sequence
from collections.abc import Callable
from dataclasses import dataclass

from src.CCmd.models import CommandResult
from src.CCmd.registry import CommandRegistry
from src.CCmd.running_config import (
    RUNNING_CONFIG_LOADING_STATE_KEY,
    remove_host_interface_config_command,
    render_host_interface_config,
    set_host_interface_config_command,
)
from src.DPlane.backend import DPlane_create_backend
from src.DPlane.models import DPlane_Backend, DPlane_PacketDevice
from src.ETHERNET.device import (
    ETHERNET_commit_device_changes,
    ETHERNET_has_pending_device_changes,
    ETHERNET_installed_device_names,
    ETHERNET_pending_device_names,
    ETHERNET_stage_device_install,
    ETHERNET_stage_device_uninstall,
)
from src.IFNET.admin import InterfaceAdminProvider
from src.IFNET.discovery import InterfaceDiscoveryError, InterfaceProvider
from src.IFNET.interfaces import IFNET_ethernet_ifnet_index_map
from src.IFNET.inventory import get_ifnet_manager
from src.IFNET.models import NetworkInterface


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
    packet_device: str
    status: str


def register_dplane_commands(
    registry: CommandRegistry,
    ifnet_provider: InterfaceProvider | None = None,
    ifnet_admin_provider: InterfaceAdminProvider | None = None,
    dplane_backend: DPlane_Backend | None = None,
    modes: Sequence[str] = DEFAULT_DPLANE_COMMAND_MODES,
    after_import_commit: Callable | None = None,
) -> None:
    DPlane_backend = dplane_backend or DPlane_create_backend(
        DPlane_ifnet_provider=ifnet_provider,
        DPlane_admin_provider=ifnet_admin_provider,
    )

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
            devices = DPlane_backend.DPlane_list_packet_devices()
        except InterfaceDiscoveryError as exc:
            return CommandResult(ok=False, message=f"% {exc}")
        except RuntimeError as exc:
            return CommandResult(ok=False, message=f"% DPlane interface discovery failed: {exc}")

        return CommandResult(message=_format_dplane_interfaces_detail(ctx.state, interfaces, devices, DPlane_backend))

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
            devices = DPlane_backend.DPlane_list_packet_devices()
        except InterfaceDiscoveryError as exc:
            return CommandResult(ok=False, message=f"% {exc}")
        except RuntimeError as exc:
            return CommandResult(ok=False, message=f"% DPlane interface discovery failed: {exc}")

        return CommandResult(message=_format_dplane_interfaces_brief(ctx.state, interfaces, devices, DPlane_backend))

    @registry.command(
        "show host interface",
        help_text="Show host system interfaces",
        modes=tuple(modes),
    )
    def show_host_interfaces(ctx, args):
        result = _list_host_interfaces_result(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(result, CommandResult):
            return result
        return CommandResult(message=_format_host_interfaces_detail(result, ctx.state))

    @registry.command(
        "show host interface brief",
        help_text="Show brief host system interface summary",
        modes=tuple(modes),
    )
    def show_host_interfaces_brief(ctx, args):
        result = _list_host_interfaces_result(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(result, CommandResult):
            return result
        return CommandResult(message=_format_host_interface_brief(result, ctx.state))

    @registry.command(
        f"show host interface <name:{HOST_INTERFACE_NAME_PATTERN}>",
        help_text="Show host system interface detail",
        modes=tuple(modes),
    )
    def show_host_interface_detail(ctx, args):
        interface = _get_host_interface(ctx, ifnet_provider, ifnet_admin_provider, args["name"])
        if isinstance(interface, CommandResult):
            return interface
        return CommandResult(message=_format_host_interface_detail(interface, ctx.state))

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
    registry.parameter_values(("show", "host", "interface"), "name", host_interface_name_values)

    @registry.command(
        "show this",
        help_text="Show current host interface configuration",
        modes=("host-interface",),
    )
    def show_this_host_interface(ctx, args):
        rendered = render_host_interface_config(ctx, ctx.mode_label)
        if not rendered:
            rendered = f"host interface {_format_cli_token(ctx.mode_label)}\n quit\n"
        return CommandResult(message=rendered.rstrip())

    @registry.command(
        "import",
        help_text="Install current host Ethernet device into VVRP",
        modes=("host-interface",),
    )
    def import_interface(ctx, args):
        interface = _get_host_interface(ctx, ifnet_provider, ifnet_admin_provider, ctx.mode_label)
        if isinstance(interface, CommandResult):
            return interface
        devices = _list_packet_devices(DPlane_backend)
        if isinstance(devices, CommandResult):
            return devices
        if DPlane_backend.DPlane_find_packet_device(interface, devices) is None:
            return CommandResult(
                ok=False,
                message=f"% Host interface is not matched to a DPlane packet device: {interface.name}",
            )
        ETHERNET_stage_device_install(ctx.state, interface.name)
        if ctx.state.get(RUNNING_CONFIG_LOADING_STATE_KEY):
            ETHERNET_commit_device_changes(ctx.state)
            _call_after_import_commit(ctx, after_import_commit)
            config_error = _sync_import_config_from_active(ctx, (interface.name,))
            return CommandResult(ok=not config_error, message=config_error)
        return CommandResult(message="% Configuration changed; use commit to apply")

    @registry.command(
        "no import",
        help_text="Remove current host Ethernet device from VVRP",
        modes=("host-interface",),
    )
    def no_import_interface(ctx, args):
        interface = _get_host_interface(ctx, ifnet_provider, ifnet_admin_provider, ctx.mode_label)
        if isinstance(interface, CommandResult):
            return interface
        ETHERNET_stage_device_uninstall(ctx.state, interface.name)
        if ctx.state.get(RUNNING_CONFIG_LOADING_STATE_KEY):
            ETHERNET_commit_device_changes(ctx.state)
            _call_after_import_commit(ctx, after_import_commit)
            config_error = _sync_import_config_from_active(ctx, (interface.name,))
            return CommandResult(ok=not config_error, message=config_error)
        return CommandResult(message="% Configuration changed; use commit to apply")

    @registry.command(
        "commit",
        help_text="Commit host interface import configuration",
        modes=("host-interface",),
    )
    def commit_host_interface(ctx, args):
        active_before = ETHERNET_installed_device_names(ctx.state)
        pending_before = ETHERNET_pending_device_names(ctx.state)
        if not _has_pending_import_changes(ctx.state, active_before, pending_before):
            return CommandResult(message="% No host interface import changes to commit")
        ETHERNET_commit_device_changes(ctx.state)
        _call_after_import_commit(ctx, after_import_commit)
        config_error = _sync_import_config_from_active(
            ctx,
            active_before | pending_before | ETHERNET_installed_device_names(ctx.state),
        )
        if config_error:
            return CommandResult(ok=False, message=config_error)
        return CommandResult(message="Commit complete")


def _call_after_import_commit(ctx, callback: Callable | None) -> None:
    if callback is None:
        return
    callback(ctx)


def _has_pending_import_changes(
    state: dict,
    active_imports: frozenset[str],
    pending_imports: frozenset[str],
) -> bool:
    return ETHERNET_has_pending_device_changes(state, active_imports, pending_imports)


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


def _list_host_interfaces_result(
    ctx,
    ifnet_provider: InterfaceProvider | None,
    ifnet_admin_provider: InterfaceAdminProvider | None,
) -> tuple[NetworkInterface, ...] | CommandResult:
    try:
        return _list_host_interfaces(ctx, ifnet_provider, ifnet_admin_provider)
    except InterfaceDiscoveryError as exc:
        return CommandResult(ok=False, message=f"% {exc}")


def _sync_import_config_from_active(ctx, interface_names) -> str:
    active_imports = ETHERNET_installed_device_names(ctx.state)
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


def _list_packet_devices(
    DPlane_backend: DPlane_Backend,
) -> tuple[DPlane_PacketDevice, ...] | CommandResult:
    try:
        return DPlane_backend.DPlane_list_packet_devices()
    except RuntimeError as exc:
        return CommandResult(ok=False, message=f"% DPlane interface discovery failed: {exc}")


def _format_dplane_interfaces_detail(
    state: dict,
    interfaces: tuple[NetworkInterface, ...],
    devices: tuple[DPlane_PacketDevice, ...],
    DPlane_backend: DPlane_Backend,
) -> str:
    if not interfaces:
        return "No IFNET interfaces found"

    rows = _dplane_interface_rows(state, interfaces, devices, DPlane_backend)
    blocks: list[str] = []
    for row in rows:
        block = [
            f"Host interface : {row.interface.name}",
            f"OS Index       : {row.os_index}",
            f"VVRP           : {_highlight_dplane_word(row.vvrp)}",
            f"IFNET Index    : {row.ifnet_index}",
            f"Packet Device  : {row.packet_device}",
            f"Status         : {_highlight_dplane_word(row.status)}",
        ]
        blocks.append("\n".join(block))
    return "\n\n".join(blocks)


def _format_host_interface_brief(
    interfaces: tuple[NetworkInterface, ...],
    state: dict,
) -> str:
    if not interfaces:
        return "No interfaces found"

    lines = [
        "PHY: Physical",
        "*down: administratively down",
        "(l): loopback",
        "(s): spoofing",
        "InUti/OutUti: input utility/output utility",
        f"{'Interface':<28} {'PHY':<8} {'Protocol':<8} {'InUti':>5} {'OutUti':>6} {'inErrors':>8} {'outErrors':>9}",
    ]
    for interface in interfaces:
        lines.append(
            f"{interface.name:<28} "
            f"{_display_host_phy(interface, state):<8} "
            f"{_display_host_protocol(interface, state):<8} "
            f"{'0%':>5} "
            f"{'0%':>6} "
            f"{0:>8} "
            f"{0:>9}"
        )
    return "\n".join(lines)


def _format_host_interfaces_detail(
    interfaces: tuple[NetworkInterface, ...],
    state: dict,
) -> str:
    if not interfaces:
        return "No interfaces found"
    return "\n\n".join(_format_host_interface_detail(interface, state) for interface in interfaces)


def _format_host_interface_detail(interface: NetworkInterface, state: dict) -> str:
    lines = [
        f"{interface.name} is {_display_host_detail_state(interface, state)}, line protocol is {_display_host_protocol(interface, state)}",
        f"  IFNET Index is {_display_ifnet_index(interface.ifnet_index)}",
        f"  OS interface index is {_display_host_index(interface.index)}, type is {interface.kind}",
        f"  Hardware address is {_display_value(interface.mac_address)}",
        f"  MTU {_display_value(interface.mtu)} bytes, bandwidth {_display_speed(interface.speed_mbps)}",
        f"  Internet address is {_join_addresses(interface.addresses_by_family('ipv4'))}",
        f"  IPv6 address is {_join_addresses(interface.addresses_by_family('ipv6'))}",
    ]
    return "\n".join(lines)


def _format_dplane_interfaces_brief(
    state: dict,
    interfaces: tuple[NetworkInterface, ...],
    devices: tuple[DPlane_PacketDevice, ...],
    DPlane_backend: DPlane_Backend,
) -> str:
    rows = _dplane_interface_rows(state, interfaces, devices, DPlane_backend)
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
    devices: tuple[DPlane_PacketDevice, ...],
    DPlane_backend: DPlane_Backend,
) -> tuple[DplaneInterfaceRow, ...]:
    active_imports = ETHERNET_installed_device_names(state)
    pending_imports = ETHERNET_pending_device_names(state)
    imported_indices = IFNET_ethernet_ifnet_index_map(state, interfaces)
    rows: list[DplaneInterfaceRow] = []
    for interface in interfaces:
        device = DPlane_backend.DPlane_find_packet_device(interface, devices)
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
                packet_device=device_name,
                status=status,
            )
        )
    return tuple(rows)


def _display_ifnet_index(ifnet_index: int | None) -> str:
    if ifnet_index is None:
        return "-"
    return f"0x{ifnet_index:x}"


def _join_addresses(addresses) -> str:
    if not addresses:
        return "-"
    return ", ".join(address.display for address in addresses)


def _display_host_index(index: int | None) -> str:
    if index is None:
        return "-"
    return str(index)


def _display_host_state(interface: NetworkInterface) -> str:
    return "up" if interface.is_up else "down"


def _display_host_detail_state(interface: NetworkInterface, state: dict) -> str:
    from src.IFNET.state import is_admin_down

    if is_admin_down(state, interface.name):
        return "administratively down"
    return _display_host_state(interface)


def _display_host_phy(interface: NetworkInterface, state: dict) -> str:
    from src.IFNET.state import is_admin_down

    if is_admin_down(state, interface.name):
        return "*down"
    if interface.kind == "loopback":
        return f"{_display_host_state(interface)}(l)"
    return _display_host_state(interface)


def _display_host_protocol(interface: NetworkInterface, state: dict) -> str:
    from src.IFNET.state import is_admin_down

    if is_admin_down(state, interface.name):
        return "down"
    if interface.kind == "loopback" and interface.is_up:
        return "up(s)"
    return _display_host_state(interface)


def _display_speed(speed_mbps: int | None) -> str:
    if speed_mbps is None:
        return "-"
    return f"{speed_mbps} Mbps"


def _display_value(value: object) -> str:
    if value is None or value == "":
        return "-"
    return str(value)


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
