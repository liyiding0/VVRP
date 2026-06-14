from __future__ import annotations

import time
from collections.abc import Sequence

from VVRP.CCmd.models import CommandResult
from VVRP.CCmd.registry import CommandRegistry

from .admin import InterfaceAdminProvider
from .discovery import InterfaceDiscoveryError, InterfaceProvider
from .inventory import IfnetManager, get_ifnet_manager
from .models import InterfaceAddress, NetworkInterface
from .policy import interface_can_shutdown
from .state import is_admin_down, no_shutdown_interface, shutdown_interface


DEFAULT_IFNET_COMMAND_MODES = ("user", "privileged")
INTERFACE_NAME_PATTERN = r".+"
OS_ADMIN_VERIFY_ATTEMPTS = 10
OS_ADMIN_VERIFY_DELAY_SECONDS = 0.5


def register_ifnet_commands(
    registry: CommandRegistry,
    provider: InterfaceProvider | None = None,
    admin_provider: InterfaceAdminProvider | None = None,
    modes: Sequence[str] = DEFAULT_IFNET_COMMAND_MODES,
) -> None:
    @registry.command(
        "show interfaces",
        help_text="Show system interfaces",
        modes=tuple(modes),
    )
    def show_interfaces(ctx, args):
        result = _list_interfaces(ctx, provider, admin_provider)
        if isinstance(result, CommandResult):
            return result
        return CommandResult(message=_format_interfaces_detail(result, ctx.state))

    @registry.command(
        "show interfaces brief",
        help_text="Show brief system interface summary",
        modes=tuple(modes),
    )
    def show_interfaces_brief(ctx, args):
        result = _list_interfaces(ctx, provider, admin_provider)
        if isinstance(result, CommandResult):
            return result
        return CommandResult(message=_format_interface_brief(result, ctx.state))

    @registry.command(
        f"show interfaces <name:{INTERFACE_NAME_PATTERN}>",
        help_text="Show system interface detail",
        modes=tuple(modes),
    )
    def show_interface_detail(ctx, args):
        name = args["name"]
        interface = _get_interface(ctx, provider, admin_provider, name)
        if isinstance(interface, CommandResult):
            return interface
        return CommandResult(message=_format_interface_detail(interface, ctx.state))

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
        return CommandResult(message=result.message)

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
        return CommandResult(message=result.message)

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


def _display_speed(speed_mbps: int | None) -> str:
    if speed_mbps is None:
        return "-"
    return f"{speed_mbps} Mbps"


def _display_value(value: object) -> str:
    if value is None or value == "":
        return "-"
    return str(value)
