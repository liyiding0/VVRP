from __future__ import annotations

import time
from collections.abc import Sequence

from VVRP.CCmd.models import CommandResult
from VVRP.CCmd.registry import CommandRegistry
from VVRP.CCmd.running_config import (
    remove_interface_config_command,
    set_interface_config_command,
)

from .admin import InterfaceAdminProvider
from .discovery import InterfaceDiscoveryError, InterfaceProvider
from .imports import imported_interfaces
from .inventory import IfnetManager, get_ifnet_manager
from .models import InterfaceAddress, NetworkInterface
from .policy import interface_can_shutdown
from .state import is_admin_down, no_shutdown_interface, shutdown_interface


DEFAULT_IFNET_COMMAND_MODES = ("hidden", "interface")
VVRP_INTERFACE_SHOW_MODES = ("user", "privileged", "config", "hidden", "interface", "host-interface")
VVRP_INTERFACE_CONFIG_MODES = ("config", "interface")
INTERFACE_NAME_PATTERN = r".+"
OS_ADMIN_VERIFY_ATTEMPTS = 10
OS_ADMIN_VERIFY_DELAY_SECONDS = 0.5


def register_ifnet_commands(
    registry: CommandRegistry,
    provider: InterfaceProvider | None = None,
    admin_provider: InterfaceAdminProvider | None = None,
    modes: Sequence[str] = DEFAULT_IFNET_COMMAND_MODES,
    register_interface_config_command: bool = True,
) -> None:
    @registry.command(
        "show interfaces",
        help_text="Show VVRP interfaces",
        modes=VVRP_INTERFACE_SHOW_MODES,
    )
    def show_vvrp_interfaces(ctx, args):
        result = _list_vvrp_interfaces(ctx, provider, admin_provider)
        if isinstance(result, CommandResult):
            return result
        return CommandResult(message=_format_vvrp_interfaces_detail(result, ctx.state))

    @registry.command(
        "show interfaces brief",
        help_text="Show brief VVRP interface summary",
        modes=VVRP_INTERFACE_SHOW_MODES,
    )
    def show_vvrp_interfaces_brief(ctx, args):
        result = _list_vvrp_interfaces(ctx, provider, admin_provider)
        if isinstance(result, CommandResult):
            return result
        return CommandResult(message=_format_interface_brief(result, ctx.state))

    @registry.command(
        f"show interfaces brief <name:{INTERFACE_NAME_PATTERN}>",
        help_text="Show brief VVRP summary for an interface",
        modes=VVRP_INTERFACE_SHOW_MODES,
    )
    def show_vvrp_interfaces_brief_name(ctx, args):
        interface = _get_vvrp_interface(ctx, provider, admin_provider, args["name"])
        if isinstance(interface, CommandResult):
            return interface
        return CommandResult(message=_format_interface_brief((interface,), ctx.state))

    @registry.command(
        f"show interfaces <name:{INTERFACE_NAME_PATTERN}>",
        help_text="Show VVRP interface detail",
        modes=VVRP_INTERFACE_SHOW_MODES,
    )
    def show_vvrp_interface_detail(ctx, args):
        interface = _get_vvrp_interface(ctx, provider, admin_provider, args["name"])
        if isinstance(interface, CommandResult):
            return interface
        return CommandResult(message=_format_vvrp_interface_detail(interface, ctx.state))

    @registry.command(
        f"interface <name:{INTERFACE_NAME_PATTERN}>",
        help_text="Enter VVRP interface configuration mode",
        modes=VVRP_INTERFACE_CONFIG_MODES,
    )
    def vvrp_interface_config(ctx, args):
        interface = _get_vvrp_interface(ctx, provider, admin_provider, args["name"])
        if isinstance(interface, CommandResult):
            return interface
        if ctx.mode == "interface":
            ctx.mode_stack[-1].label = interface.name
        else:
            ctx.push_mode("interface", interface.name)
        return CommandResult()

    def vvrp_interface_name_values(ctx):
        result = _list_vvrp_interfaces(ctx, provider, admin_provider)
        if isinstance(result, CommandResult):
            return ()
        return tuple(interface.name for interface in result)

    registry.parameter_values(("interface",), "name", vvrp_interface_name_values)
    registry.parameter_values(("show", "interfaces"), "name", vvrp_interface_name_values)
    registry.parameter_values(("show", "interfaces", "brief"), "name", vvrp_interface_name_values)

    @registry.command(
        "show host interfaces",
        help_text="Show host system interfaces",
        modes=tuple(modes),
    )
    def show_host_interfaces(ctx, args):
        result = _list_interfaces(ctx, provider, admin_provider)
        if isinstance(result, CommandResult):
            return result
        return CommandResult(message=_format_interfaces_detail(result, ctx.state))

    @registry.command(
        "show host interfaces brief",
        help_text="Show brief host system interface summary",
        modes=tuple(modes),
    )
    def show_host_interfaces_brief(ctx, args):
        result = _list_interfaces(ctx, provider, admin_provider)
        if isinstance(result, CommandResult):
            return result
        return CommandResult(message=_format_interface_brief(result, ctx.state))

    @registry.command(
        f"show host interfaces <name:{INTERFACE_NAME_PATTERN}>",
        help_text="Show host system interface detail",
        modes=tuple(modes),
    )
    def show_host_interface_detail(ctx, args):
        name = args["name"]
        interface = _get_interface(ctx, provider, admin_provider, name)
        if isinstance(interface, CommandResult):
            return interface
        return CommandResult(message=_format_interface_detail(interface, ctx.state))

    if register_interface_config_command:
        @registry.command(
            f"host interface <name:{INTERFACE_NAME_PATTERN}>",
            help_text="Enter host interface view",
            modes=("hidden", "host-interface"),
        )
        def interface_config(ctx, args):
            interface = _get_interface(ctx, provider, admin_provider, args["name"])
            if isinstance(interface, CommandResult):
                return interface
            if ctx.mode == "host-interface":
                ctx.mode_stack[-1].label = interface.name
            else:
                ctx.push_mode("host-interface", interface.name)
            return CommandResult()

        def interface_name_values(ctx):
            try:
                return tuple(interface.name for interface in _manager(ctx, provider, admin_provider).list_interfaces())
            except InterfaceDiscoveryError:
                return ()

        registry.parameter_values(("host", "interface"), "name", interface_name_values)

    @registry.command(
        "shutdown",
        help_text="Administratively shut down current interface",
        modes=("interface",),
    )
    def shutdown(ctx, args):
        manager = _manager(ctx, provider, admin_provider)
        interface = _current_interface(ctx, provider, admin_provider)
        if isinstance(interface, CommandResult):
            return interface
        if not interface_can_shutdown(interface):
            return CommandResult(
                ok=False,
                message=f"% {interface.kind.capitalize()} interface cannot be shut down: {interface.name}",
            )
        result = manager.admin_provider.shutdown(interface)
        if not result.ok:
            return CommandResult(ok=False, message=result.message)
        verified = _verify_os_admin_state(manager, interface.name, expected_up=False)
        if isinstance(verified, CommandResult):
            return verified
        shutdown_interface(ctx.state, interface.name)
        config_error = set_interface_config_command(
            ctx,
            interface.name,
            "shutdown",
            "shutdown",
        )
        return CommandResult(ok=not config_error, message=config_error or result.message)

    @registry.command(
        "no shutdown",
        help_text="Administratively enable current interface",
        modes=("interface",),
    )
    def no_shutdown(ctx, args):
        manager = _manager(ctx, provider, admin_provider)
        interface = _current_interface(ctx, provider, admin_provider)
        if isinstance(interface, CommandResult):
            return interface
        if not interface_can_shutdown(interface):
            no_shutdown_interface(ctx.state, interface.name)
            return CommandResult()
        result = manager.admin_provider.no_shutdown(interface)
        if not result.ok:
            return CommandResult(ok=False, message=result.message)
        verified = _verify_os_admin_state(manager, interface.name, expected_up=True)
        if isinstance(verified, CommandResult):
            return verified
        no_shutdown_interface(ctx.state, interface.name)
        config_error = remove_interface_config_command(ctx, interface.name, "shutdown")
        return CommandResult(ok=not config_error, message=config_error or result.message)

    @registry.context_initializer
    def initialize_ifnet(ctx):
        try:
            _manager(ctx, provider, admin_provider).ensure_loaded()
        except InterfaceDiscoveryError:
            pass


def _manager(
    ctx,
    provider: InterfaceProvider | None,
    admin_provider: InterfaceAdminProvider | None,
) -> IfnetManager:
    return get_ifnet_manager(ctx.state, provider=provider, admin_provider=admin_provider)


def _list_interfaces(
    ctx,
    provider: InterfaceProvider | None,
    admin_provider: InterfaceAdminProvider | None,
) -> tuple[NetworkInterface, ...] | CommandResult:
    try:
        return _manager(ctx, provider, admin_provider).list_interfaces()
    except InterfaceDiscoveryError as exc:
        return CommandResult(ok=False, message=f"% {exc}")


def _list_vvrp_interfaces(
    ctx,
    provider: InterfaceProvider | None,
    admin_provider: InterfaceAdminProvider | None,
) -> tuple[NetworkInterface, ...] | CommandResult:
    result = _list_interfaces(ctx, provider, admin_provider)
    if isinstance(result, CommandResult):
        return result
    return imported_interfaces(ctx.state, result)


def _get_interface(
    ctx,
    provider: InterfaceProvider | None,
    admin_provider: InterfaceAdminProvider | None,
    name: str,
) -> NetworkInterface | CommandResult:
    try:
        interface = _manager(ctx, provider, admin_provider).get_interface(name)
    except InterfaceDiscoveryError as exc:
        return CommandResult(ok=False, message=f"% {exc}")

    if interface is None:
        return CommandResult(ok=False, message=f"% Interface not found: {name}")
    return interface


def _get_vvrp_interface(
    ctx,
    provider: InterfaceProvider | None,
    admin_provider: InterfaceAdminProvider | None,
    name: str,
) -> NetworkInterface | CommandResult:
    interfaces = _list_vvrp_interfaces(ctx, provider, admin_provider)
    if isinstance(interfaces, CommandResult):
        return interfaces
    for interface in interfaces:
        if interface.name == name:
            return interface
    return CommandResult(ok=False, message=f"% Interface not found: {name}")


def _current_interface(
    ctx,
    provider: InterfaceProvider | None,
    admin_provider: InterfaceAdminProvider | None,
) -> NetworkInterface | CommandResult:
    return _get_interface(ctx, provider, admin_provider, ctx.mode_label)


def _verify_os_admin_state(
    manager: IfnetManager,
    name: str,
    expected_up: bool,
) -> CommandResult | None:
    discovered: tuple[NetworkInterface, ...] = ()
    for attempt in range(OS_ADMIN_VERIFY_ATTEMPTS):
        try:
            discovered = manager.refresh()
        except InterfaceDiscoveryError as exc:
            return CommandResult(ok=False, message=f"% {exc}")

        current = _find_interface(discovered, name)
        if expected_up:
            if current is not None and current.is_up:
                return None
        elif current is None or not current.is_up:
            return None

        if attempt < OS_ADMIN_VERIFY_ATTEMPTS - 1:
            time.sleep(OS_ADMIN_VERIFY_DELAY_SECONDS)

    current = _find_interface(discovered, name)
    actual_state = "missing" if current is None else _display_state(current)
    expected_state = "up" if expected_up else "down"
    return CommandResult(
        ok=False,
        message=(
            "% OS interface admin change did not take effect: "
            f"{name} is still {actual_state}, expected {expected_state}"
        ),
    )


def _find_interface(
    interfaces: tuple[NetworkInterface, ...],
    name: str,
) -> NetworkInterface | None:
    for interface in interfaces:
        if interface.name == name:
            return interface
    return None


def _format_interface_brief(
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
            f"{_display_phy(interface, state):<8} "
            f"{_display_protocol(interface, state):<8} "
            f"{'0%':>5} "
            f"{'0%':>6} "
            f"{0:>8} "
            f"{0:>9}"
        )
    return "\n".join(lines)


def _format_interfaces_detail(
    interfaces: tuple[NetworkInterface, ...],
    state: dict,
) -> str:
    if not interfaces:
        return "No interfaces found"
    return "\n\n".join(_format_interface_detail(interface, state) for interface in interfaces)


def _format_vvrp_interfaces_detail(
    interfaces: tuple[NetworkInterface, ...],
    state: dict,
) -> str:
    if not interfaces:
        return "No interfaces found"
    return "\n\n".join(_format_vvrp_interface_detail(interface, state) for interface in interfaces)


def _format_interface_detail(interface: NetworkInterface, state: dict) -> str:
    lines = [
        f"{interface.name} is {_display_detail_state(interface, state)}, line protocol is {_display_protocol(interface, state)}",
        f"  IFNET Index is {_display_ifnet_index(interface.ifnet_index)}",
        f"  OS interface index is {_display_index(interface.index)}, type is {interface.kind}",
        f"  Hardware address is {_display_value(interface.mac_address)}",
        f"  MTU {_display_value(interface.mtu)} bytes, bandwidth {_display_speed(interface.speed_mbps)}",
        f"  Internet address is {_join_addresses(interface.addresses_by_family('ipv4'))}",
        f"  IPv6 address is {_join_addresses(interface.addresses_by_family('ipv6'))}",
    ]
    return "\n".join(lines)


def _format_vvrp_interface_detail(interface: NetworkInterface, state: dict) -> str:
    lines = [
        f"{interface.name} current state : {_display_detail_state_upper(interface, state)}",
        f"Line protocol current state : {_display_protocol_upper(interface, state)}",
        "Description:",
        f"Route Port,The Maximum Transmit Unit is {_display_mtu(interface.mtu)}",
        f"IFNET Index : {_display_ifnet_index(interface.ifnet_index)}",
        f"Interface type : {interface.kind}",
        f"Hardware address is {_display_value(interface.mac_address)}",
        f"Port BW: {_display_speed(interface.speed_mbps)}",
    ]

    ipv4_addresses = interface.addresses_by_family("ipv4")
    if ipv4_addresses:
        for index, address in enumerate(ipv4_addresses):
            role = "Primary" if index == 0 else "Sub"
            lines.append(f"Internet Address is {address.display} {role}")
    else:
        lines.append("Internet Address is unassigned")

    ipv6_addresses = interface.addresses_by_family("ipv6")
    if ipv6_addresses:
        lines.append(f"IPv6 Address is {_join_addresses(ipv6_addresses)}")

    lines.extend(
        [
            "Last physical up time   : -",
            "Last physical down time : -",
            "Current system time     : -",
            "Input: 0 packets, 0 bytes",
            "Output: 0 packets, 0 bytes",
            "Input error: 0, Output error: 0",
        ]
    )
    return "\n".join(lines)


def _join_addresses(addresses: tuple[InterfaceAddress, ...]) -> str:
    if not addresses:
        return "-"
    return ", ".join(address.display for address in addresses)


def _display_index(index: int | None) -> str:
    if index is None:
        return "-"
    return str(index)


def _display_ifnet_index(ifnet_index: int) -> str:
    return f"0x{ifnet_index:x}"


def _display_state(interface: NetworkInterface) -> str:
    return "up" if interface.is_up else "down"


def _display_detail_state(interface: NetworkInterface, state: dict) -> str:
    if is_admin_down(state, interface.name):
        return "administratively down"
    return _display_state(interface)


def _display_detail_state_upper(interface: NetworkInterface, state: dict) -> str:
    if is_admin_down(state, interface.name):
        return "Administratively DOWN"
    return _display_state(interface).upper()


def _display_phy(interface: NetworkInterface, state: dict) -> str:
    if is_admin_down(state, interface.name):
        return "*down"
    if interface.kind == "loopback":
        return f"{_display_state(interface)}(l)"
    return _display_state(interface)


def _display_protocol(interface: NetworkInterface, state: dict) -> str:
    if is_admin_down(state, interface.name):
        return "down"
    if interface.kind == "loopback" and interface.is_up:
        return "up(s)"
    return _display_state(interface)


def _display_protocol_upper(interface: NetworkInterface, state: dict) -> str:
    if is_admin_down(state, interface.name):
        return "DOWN"
    if interface.kind == "loopback" and interface.is_up:
        return "UP(spoofing)"
    return _display_state(interface).upper()


def _display_mtu(mtu: int | None) -> str:
    if mtu is None:
        return "-"
    return str(mtu)


def _display_speed(speed_mbps: int | None) -> str:
    if speed_mbps is None:
        return "-"
    return f"{speed_mbps} Mbps"


def _display_value(value: object) -> str:
    if value is None or value == "":
        return "-"
    return str(value)
