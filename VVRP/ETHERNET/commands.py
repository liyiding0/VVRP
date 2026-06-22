from __future__ import annotations

from collections.abc import Callable, Sequence

from VVRP.CCmd.models import CliContext, CommandResult
from VVRP.CCmd.registry import CommandRegistry
from VVRP.CCmd.running_config import remove_interface_config_command, set_interface_config_command
from VVRP.IFNET.admin import InterfaceAdminProvider
from VVRP.IFNET.discovery import InterfaceDiscoveryError, InterfaceProvider
from VVRP.IFNET.imports import imported_interfaces
from VVRP.IFNET.inventory import get_ifnet_manager
from VVRP.IFNET.models import NetworkInterface
from VVRP.IFNET.state import remove_interface_mac_address, set_interface_mac_address

from .debug import is_ethernet_frame_brief_debug_enabled, set_ethernet_frame_brief_debug


ETHERNET_DEBUG_MODES = ("privileged", "config", "hidden")
MAC_ADDRESS_PATTERN = r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}|(?:[0-9A-Fa-f]{4}[.:-]){2}[0-9A-Fa-f]{4}|[0-9A-Fa-f]{12}"


def register_ethernet_commands(
    registry: CommandRegistry,
    modes: Sequence[str] = ETHERNET_DEBUG_MODES,
    ifnet_provider: InterfaceProvider | None = None,
    ifnet_admin_provider: InterfaceAdminProvider | None = None,
    frame_debug_start: Callable[[CliContext], str] | None = None,
    frame_debug_stop: Callable[[], str] | None = None,
    frame_debug_status: Callable[[], str] | None = None,
) -> None:
    @registry.command(
        f"mac-address <mac_address:{MAC_ADDRESS_PATTERN}>",
        help_text="Configure current VVRP Ethernet MAC address",
        modes=("interface",),
    )
    def mac_address(ctx, args):
        vvrp_interface = _current_vvrp_interface(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(vvrp_interface, CommandResult):
            return vvrp_interface
        imported_interface = _current_imported_interface(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(imported_interface, CommandResult):
            return imported_interface
        if vvrp_interface.kind != "ethernet":
            return CommandResult(
                ok=False,
                message=f"% Unsupported interface type for mac-address: {vvrp_interface.kind}",
            )
        normalized = _normalize_configured_mac_address(args["mac_address"])
        if normalized is None:
            return CommandResult(ok=False, message=f"% Invalid MAC address: {args['mac_address']}")
        validation_error = _validate_configured_mac_address(normalized, imported_interface)
        if validation_error:
            return CommandResult(ok=False, message=validation_error)
        set_interface_mac_address(ctx.state, vvrp_interface.name, normalized)
        config_error = set_interface_config_command(
            ctx,
            vvrp_interface.name,
            "mac-address",
            f"mac-address {normalized}",
        )
        return CommandResult(ok=not config_error, message=config_error)

    @registry.command(
        "no mac-address",
        help_text="Restore original imported Ethernet MAC address",
        modes=("interface",),
    )
    def no_mac_address(ctx, args):
        interface = _current_vvrp_interface(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(interface, CommandResult):
            return interface
        remove_interface_mac_address(ctx.state, interface.name)
        config_error = remove_interface_config_command(ctx, interface.name, "mac-address")
        return CommandResult(ok=not config_error, message=config_error)

    @registry.command(
        "debugging ethernet frame brief",
        help_text="Enable brief Ethernet frame debugging",
        modes=tuple(modes),
    )
    def debugging_ethernet_frame_brief(ctx, args):
        set_ethernet_frame_brief_debug(ctx, True)
        detail = _call_frame_debug_start(ctx, frame_debug_start)
        if detail:
            return CommandResult(message=f"Ethernet frame brief debugging is on ({detail})")
        return CommandResult(message="Ethernet frame brief debugging is on")

    @registry.command(
        "no debugging ethernet frame brief",
        help_text="Disable brief Ethernet frame debugging",
        modes=tuple(modes),
    )
    def no_debugging_ethernet_frame_brief(ctx, args):
        set_ethernet_frame_brief_debug(ctx, False)
        detail = _call_frame_debug_stop(frame_debug_stop)
        if detail:
            return CommandResult(message=f"Ethernet frame brief debugging is off ({detail})")
        return CommandResult(message="Ethernet frame brief debugging is off")

    @registry.command(
        "show debugging ethernet",
        help_text="Show Ethernet debugging switches",
        modes=tuple(modes),
    )
    def show_debugging_ethernet(ctx, args):
        state = "on" if is_ethernet_frame_brief_debug_enabled(ctx) else "off"
        detail = frame_debug_status() if frame_debug_status is not None else ""
        if detail:
            return CommandResult(message=f"Ethernet frame brief debugging is {state} ({detail})")
        return CommandResult(message=f"Ethernet frame brief debugging is {state}")


def _call_frame_debug_start(ctx: CliContext, callback: Callable[[CliContext], str] | None) -> str:
    if callback is None:
        return ""
    try:
        return callback(ctx)
    except RuntimeError as exc:
        return f"listener start failed: {exc}"


def _call_frame_debug_stop(callback: Callable[[], str] | None) -> str:
    if callback is None:
        return ""
    return callback()


def _current_vvrp_interface(
    ctx: CliContext,
    ifnet_provider: InterfaceProvider | None,
    ifnet_admin_provider: InterfaceAdminProvider | None,
) -> NetworkInterface | CommandResult:
    interfaces = _list_imported_interfaces(ctx, ifnet_provider, ifnet_admin_provider)
    if isinstance(interfaces, CommandResult):
        return interfaces
    for interface in interfaces:
        if interface.name == ctx.mode_label:
            return interface
    return CommandResult(ok=False, message=f"% Interface not found: {ctx.mode_label}")


def _current_imported_interface(
    ctx: CliContext,
    ifnet_provider: InterfaceProvider | None,
    ifnet_admin_provider: InterfaceAdminProvider | None,
) -> NetworkInterface | CommandResult:
    try:
        interface = get_ifnet_manager(
            ctx.state,
            provider=ifnet_provider,
            admin_provider=ifnet_admin_provider,
        ).get_interface(ctx.mode_label)
    except InterfaceDiscoveryError as exc:
        return CommandResult(ok=False, message=f"% {exc}")
    if interface is None:
        return CommandResult(ok=False, message=f"% Interface not found: {ctx.mode_label}")
    return interface


def _list_imported_interfaces(
    ctx: CliContext,
    ifnet_provider: InterfaceProvider | None,
    ifnet_admin_provider: InterfaceAdminProvider | None,
) -> tuple[NetworkInterface, ...] | CommandResult:
    try:
        host_interfaces = get_ifnet_manager(
            ctx.state,
            provider=ifnet_provider,
            admin_provider=ifnet_admin_provider,
        ).list_interfaces()
    except InterfaceDiscoveryError as exc:
        return CommandResult(ok=False, message=f"% {exc}")
    return imported_interfaces(ctx.state, host_interfaces)


def _normalize_configured_mac_address(value: str) -> str | None:
    raw = "".join(char for char in value.strip() if char not in ":-.")
    if len(raw) != 12:
        return None
    try:
        octets = [int(raw[index : index + 2], 16) for index in range(0, 12, 2)]
    except ValueError:
        return None
    return ":".join(f"{octet:02X}" for octet in octets)


def _validate_configured_mac_address(mac_address: str, imported_interface: NetworkInterface) -> str:
    octets = [int(part, 16) for part in mac_address.split(":")]
    if all(octet == 0 for octet in octets):
        return "% Invalid MAC address: all-zero address is not allowed"
    if all(octet == 0xFF for octet in octets):
        return "% Invalid MAC address: broadcast address is not allowed"
    if octets[0] & 1:
        return "% Invalid MAC address: multicast address is not allowed"
    original = _normalize_configured_mac_address(imported_interface.mac_address)
    if original == mac_address:
        return "% Invalid MAC address: configured MAC must differ from imported host MAC"
    return ""
