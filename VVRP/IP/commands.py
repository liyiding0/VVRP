from __future__ import annotations

import ipaddress
from collections.abc import Sequence

from VVRP.CCmd.models import CommandResult
from VVRP.CCmd.registry import CommandRegistry
from VVRP.CCmd.running_config import (
    remove_interface_config_command,
    remove_interface_config_prefix,
    set_interface_config_command,
)
from VVRP.IFNET.admin import InterfaceAdminProvider
from VVRP.IFNET.discovery import InterfaceDiscoveryError, InterfaceProvider
from VVRP.IFNET.inventory import get_ifnet_manager
from VVRP.IFNET.models import InterfaceAddress, NetworkInterface
from VVRP.IFNET.state import is_admin_down

from .dhcp import DhcpClientProvider, OsDhcpClientProvider
from .ping import PING_ARGUMENT_PATTERN, run_ping
from .static import (
    OsStaticIpv4Provider,
    StaticIpv4Provider,
    StaticIpv4ValidationError,
    parse_static_ipv4_address,
)


DEFAULT_IP_COMMAND_MODES = ("user", "privileged", "config", "interface", "hidden")
IPV4_ADDRESS_PATTERN = r"(?:\d{1,3}\.){3}\d{1,3}"
IPV4_MASK_PATTERN = r"(?:(?:\d{1,3}\.){3}\d{1,3}|\d{1,2})"
INTERFACE_NAME_PATTERN = r".+"


def register_ip_commands(
    registry: CommandRegistry,
    modes: Sequence[str] = DEFAULT_IP_COMMAND_MODES,
    ifnet_provider: InterfaceProvider | None = None,
    ifnet_admin_provider: InterfaceAdminProvider | None = None,
    dhcp_provider: DhcpClientProvider | None = None,
    static_ipv4_provider: StaticIpv4Provider | None = None,
) -> None:
    active_dhcp_provider = dhcp_provider or OsDhcpClientProvider()
    active_static_ipv4_provider = static_ipv4_provider or OsStaticIpv4Provider()

    @registry.command(
        f"ping <arguments...:{PING_ARGUMENT_PATTERN}>",
        help_text="Ping an IPv4 address or hostname",
        modes=tuple(modes),
    )
    def ping(ctx, args):
        result = run_ping(args["arguments"], output=ctx.output)
        return CommandResult(ok=result.ok, message=result.message)

    @registry.command(
        "show ip interface",
        help_text="Show IPv4 interface information",
        modes=tuple(modes),
    )
    def show_ip_interface(ctx, args):
        result = _list_interfaces(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(result, CommandResult):
            return result
        return CommandResult(message=_format_ip_interface_detail(result, ctx.state))

    @registry.command(
        "show ip interface brief",
        help_text="Show brief IPv4 interface summary",
        modes=tuple(modes),
    )
    def show_ip_interface_brief(ctx, args):
        result = _list_interfaces(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(result, CommandResult):
            return result
        return CommandResult(message=_format_ip_interface_brief(result, ctx.state))

    @registry.command(
        "show ip interface brief ethernet",
        help_text="Show brief IPv4 summary for Ethernet interfaces",
        modes=tuple(modes),
    )
    def show_ip_interface_brief_ethernet(ctx, args):
        result = _list_interfaces(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(result, CommandResult):
            return result
        result = _filter_interface_kind(result, "ethernet")
        return CommandResult(message=_format_ip_interface_brief(result, ctx.state))

    @registry.command(
        "show ip interface brief loopback",
        help_text="Show brief IPv4 summary for loopback interfaces",
        modes=tuple(modes),
    )
    def show_ip_interface_brief_loopback(ctx, args):
        result = _list_interfaces(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(result, CommandResult):
            return result
        result = _filter_interface_kind(result, "loopback")
        return CommandResult(message=_format_ip_interface_brief(result, ctx.state))

    @registry.command(
        "show ip interface brief ip-configured",
        help_text="Show brief IPv4 summary for interfaces with IPv4 configured",
        modes=tuple(modes),
    )
    def show_ip_interface_brief_ip_configured(ctx, args):
        result = _list_interfaces(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(result, CommandResult):
            return result
        result = _filter_ip_configured(result)
        return CommandResult(message=_format_ip_interface_brief(result, ctx.state))

    @registry.command(
        "show ip interface brief ip-configured except ethernet",
        help_text="Show IPv4-configured interfaces except Ethernet",
        modes=tuple(modes),
    )
    def show_ip_interface_brief_ip_configured_except_ethernet(ctx, args):
        result = _list_interfaces(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(result, CommandResult):
            return result
        result = _exclude_interface_kind(_filter_ip_configured(result), "ethernet")
        return CommandResult(message=_format_ip_interface_brief(result, ctx.state))

    @registry.command(
        "show ip interface brief ip-configured except loopback",
        help_text="Show IPv4-configured interfaces except loopback",
        modes=tuple(modes),
    )
    def show_ip_interface_brief_ip_configured_except_loopback(ctx, args):
        result = _list_interfaces(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(result, CommandResult):
            return result
        result = _exclude_interface_kind(_filter_ip_configured(result), "loopback")
        return CommandResult(message=_format_ip_interface_brief(result, ctx.state))

    @registry.command(
        f"show ip interface brief <name:{INTERFACE_NAME_PATTERN}>",
        help_text="Show brief IPv4 summary for an interface",
        modes=tuple(modes),
    )
    def show_ip_interface_brief_name(ctx, args):
        interface = _get_interface(ctx, ifnet_provider, ifnet_admin_provider, args["name"])
        if isinstance(interface, CommandResult):
            return interface
        return CommandResult(message=_format_ip_interface_brief((interface,), ctx.state))

    @registry.command(
        "show ip interface description",
        help_text="Show IPv4 interface descriptions",
        modes=tuple(modes),
    )
    def show_ip_interface_description(ctx, args):
        result = _list_interfaces(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(result, CommandResult):
            return result
        return CommandResult(message=_format_ip_interface_description(result, ctx.state))

    @registry.command(
        "show ip interface description ethernet",
        help_text="Show IPv4 descriptions for Ethernet interfaces",
        modes=tuple(modes),
    )
    def show_ip_interface_description_ethernet(ctx, args):
        result = _list_interfaces(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(result, CommandResult):
            return result
        result = _filter_interface_kind(result, "ethernet")
        return CommandResult(message=_format_ip_interface_description(result, ctx.state))

    @registry.command(
        "show ip interface description loopback",
        help_text="Show IPv4 descriptions for loopback interfaces",
        modes=tuple(modes),
    )
    def show_ip_interface_description_loopback(ctx, args):
        result = _list_interfaces(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(result, CommandResult):
            return result
        result = _filter_interface_kind(result, "loopback")
        return CommandResult(message=_format_ip_interface_description(result, ctx.state))

    @registry.command(
        "show ip interface description ip-configured",
        help_text="Show IPv4 descriptions for interfaces with IPv4 configured",
        modes=tuple(modes),
    )
    def show_ip_interface_description_ip_configured(ctx, args):
        result = _list_interfaces(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(result, CommandResult):
            return result
        result = _filter_ip_configured(result)
        return CommandResult(message=_format_ip_interface_description(result, ctx.state))

    @registry.command(
        "show ip interface description ip-configured except ethernet",
        help_text="Show IPv4-configured descriptions except Ethernet",
        modes=tuple(modes),
    )
    def show_ip_interface_description_ip_configured_except_ethernet(ctx, args):
        result = _list_interfaces(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(result, CommandResult):
            return result
        result = _exclude_interface_kind(_filter_ip_configured(result), "ethernet")
        return CommandResult(message=_format_ip_interface_description(result, ctx.state))

    @registry.command(
        "show ip interface description ip-configured except loopback",
        help_text="Show IPv4-configured descriptions except loopback",
        modes=tuple(modes),
    )
    def show_ip_interface_description_ip_configured_except_loopback(ctx, args):
        result = _list_interfaces(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(result, CommandResult):
            return result
        result = _exclude_interface_kind(_filter_ip_configured(result), "loopback")
        return CommandResult(message=_format_ip_interface_description(result, ctx.state))

    @registry.command(
        f"show ip interface description <name:{INTERFACE_NAME_PATTERN}>",
        help_text="Show IPv4 description for an interface",
        modes=tuple(modes),
    )
    def show_ip_interface_description_name(ctx, args):
        interface = _get_interface(ctx, ifnet_provider, ifnet_admin_provider, args["name"])
        if isinstance(interface, CommandResult):
            return interface
        return CommandResult(message=_format_ip_interface_description((interface,), ctx.state))

    @registry.command(
        f"show ip interface <name:{INTERFACE_NAME_PATTERN}>",
        help_text="Show IPv4 information for an interface",
        modes=tuple(modes),
    )
    def show_ip_interface_name(ctx, args):
        interface = _get_interface(ctx, ifnet_provider, ifnet_admin_provider, args["name"])
        if isinstance(interface, CommandResult):
            return interface
        return CommandResult(message=_format_one_ip_interface_detail(interface, ctx.state))

    @registry.command(
        "ip address dhcp-alloc",
        help_text="Obtain an IPv4 address with DHCP",
        modes=("interface",),
    )
    def ip_address_dhcp_alloc(ctx, args):
        interface = _current_interface(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(interface, CommandResult):
            return interface
        unsupported = _unsupported_dhcp_interface(interface)
        if unsupported is not None:
            return unsupported

        result = active_dhcp_provider.enable_dhcp(interface)
        if not result.ok:
            return CommandResult(ok=False, message=result.message)
        refresh_error = _refresh_ifnet(ctx, ifnet_provider, ifnet_admin_provider)
        if refresh_error is not None:
            return refresh_error
        remove_error = remove_interface_config_prefix(ctx, interface.name, "ip-address:")
        if remove_error:
            return CommandResult(ok=False, message=remove_error)
        config_error = set_interface_config_command(
            ctx,
            interface.name,
            "ip-address-dhcp",
            "ip address dhcp-alloc",
        )
        return CommandResult(ok=not config_error, message=config_error or result.message)

    @registry.command(
        "no ip address dhcp-alloc",
        help_text="Disable DHCP address allocation",
        modes=("interface",),
    )
    def no_ip_address_dhcp_alloc(ctx, args):
        interface = _current_interface(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(interface, CommandResult):
            return interface
        unsupported = _unsupported_dhcp_interface(interface)
        if unsupported is not None:
            return unsupported

        result = active_dhcp_provider.disable_dhcp(interface)
        if not result.ok:
            return CommandResult(ok=False, message=result.message)
        refresh_error = _refresh_ifnet(ctx, ifnet_provider, ifnet_admin_provider)
        if refresh_error is not None:
            return refresh_error
        config_error = remove_interface_config_command(
            ctx,
            interface.name,
            "ip-address-dhcp",
        )
        return CommandResult(ok=not config_error, message=config_error or result.message)

    @registry.command(
        f"ip address <ip_address:{IPV4_ADDRESS_PATTERN}> <mask:{IPV4_MASK_PATTERN}>",
        help_text="Configure a primary static IPv4 address",
        modes=("interface",),
    )
    def ip_address_static(ctx, args):
        return _set_static_ipv4(
            ctx,
            ifnet_provider,
            ifnet_admin_provider,
            active_static_ipv4_provider,
            args["ip_address"],
            args["mask"],
            secondary=False,
        )

    @registry.command(
        f"ip address <ip_address:{IPV4_ADDRESS_PATTERN}> <mask:{IPV4_MASK_PATTERN}> sub",
        help_text="Configure a secondary static IPv4 address",
        modes=("interface",),
    )
    def ip_address_static_sub(ctx, args):
        return _set_static_ipv4(
            ctx,
            ifnet_provider,
            ifnet_admin_provider,
            active_static_ipv4_provider,
            args["ip_address"],
            args["mask"],
            secondary=True,
        )

    @registry.command(
        "no ip address",
        help_text="Remove all static IPv4 addresses",
        modes=("interface",),
    )
    def no_ip_address_all(ctx, args):
        return _remove_static_ipv4(
            ctx,
            ifnet_provider,
            ifnet_admin_provider,
            active_static_ipv4_provider,
        )

    @registry.command(
        f"no ip address <ip_address:{IPV4_ADDRESS_PATTERN}> <mask:{IPV4_MASK_PATTERN}>",
        help_text="Remove a static IPv4 address",
        modes=("interface",),
    )
    def no_ip_address_static(ctx, args):
        return _remove_static_ipv4(
            ctx,
            ifnet_provider,
            ifnet_admin_provider,
            active_static_ipv4_provider,
            args["ip_address"],
            args["mask"],
            secondary=False,
        )

    @registry.command(
        f"no ip address <ip_address:{IPV4_ADDRESS_PATTERN}> <mask:{IPV4_MASK_PATTERN}> sub",
        help_text="Remove a secondary static IPv4 address",
        modes=("interface",),
    )
    def no_ip_address_static_sub(ctx, args):
        return _remove_static_ipv4(
            ctx,
            ifnet_provider,
            ifnet_admin_provider,
            active_static_ipv4_provider,
            args["ip_address"],
            args["mask"],
            secondary=True,
        )


def _current_interface(
    ctx,
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


def _list_interfaces(
    ctx,
    ifnet_provider: InterfaceProvider | None,
    ifnet_admin_provider: InterfaceAdminProvider | None,
) -> tuple[NetworkInterface, ...] | CommandResult:
    try:
        return get_ifnet_manager(
            ctx.state,
            provider=ifnet_provider,
            admin_provider=ifnet_admin_provider,
        ).list_interfaces()
    except InterfaceDiscoveryError as exc:
        return CommandResult(ok=False, message=f"% {exc}")


def _get_interface(
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
        return CommandResult(ok=False, message=f"% Interface not found: {name}")
    return interface


def _unsupported_dhcp_interface(interface: NetworkInterface) -> CommandResult | None:
    if interface.kind == "ethernet":
        return None
    return CommandResult(
        ok=False,
        message=(
            f"% {interface.kind.capitalize()} interface does not support DHCP client: "
            f"{interface.name}"
        ),
    )


def _unsupported_static_ipv4_interface(interface: NetworkInterface) -> CommandResult | None:
    if interface.kind == "ethernet":
        return None
    return CommandResult(
        ok=False,
        message=(
            f"% {interface.kind.capitalize()} interface does not support static IPv4: "
            f"{interface.name}"
        ),
    )


def _set_static_ipv4(
    ctx,
    ifnet_provider: InterfaceProvider | None,
    ifnet_admin_provider: InterfaceAdminProvider | None,
    static_ipv4_provider: StaticIpv4Provider,
    ip_address: str,
    mask: str,
    secondary: bool,
) -> CommandResult:
    interface = _current_interface(ctx, ifnet_provider, ifnet_admin_provider)
    if isinstance(interface, CommandResult):
        return interface
    unsupported = _unsupported_static_ipv4_interface(interface)
    if unsupported is not None:
        return unsupported

    try:
        address = parse_static_ipv4_address(ip_address, mask, secondary=secondary)
    except StaticIpv4ValidationError as exc:
        return CommandResult(ok=False, message=str(exc))

    result = static_ipv4_provider.set_static_ipv4(interface, address)
    if not result.ok:
        return CommandResult(ok=False, message=result.message)
    refresh_error = _refresh_ifnet(ctx, ifnet_provider, ifnet_admin_provider)
    if refresh_error is not None:
        return refresh_error
    dhcp_error = remove_interface_config_command(ctx, interface.name, "ip-address-dhcp")
    if dhcp_error:
        return CommandResult(ok=False, message=dhcp_error)
    line = f"ip address {address.address} {address.prefix_length}"
    if address.secondary:
        line += " sub"
    config_error = set_interface_config_command(
        ctx,
        interface.name,
        _static_ipv4_config_key(address),
        line,
    )
    return CommandResult(ok=not config_error, message=config_error or result.message)


def _remove_static_ipv4(
    ctx,
    ifnet_provider: InterfaceProvider | None,
    ifnet_admin_provider: InterfaceAdminProvider | None,
    static_ipv4_provider: StaticIpv4Provider,
    ip_address: str | None = None,
    mask: str | None = None,
    secondary: bool = False,
) -> CommandResult:
    interface = _current_interface(ctx, ifnet_provider, ifnet_admin_provider)
    if isinstance(interface, CommandResult):
        return interface
    unsupported = _unsupported_static_ipv4_interface(interface)
    if unsupported is not None:
        return unsupported

    address = None
    if ip_address is not None and mask is not None:
        try:
            address = parse_static_ipv4_address(ip_address, mask, secondary=secondary)
        except StaticIpv4ValidationError as exc:
            return CommandResult(ok=False, message=str(exc))

    result = static_ipv4_provider.remove_static_ipv4(interface, address)
    if not result.ok:
        return CommandResult(ok=False, message=result.message)
    refresh_error = _refresh_ifnet(ctx, ifnet_provider, ifnet_admin_provider)
    if refresh_error is not None:
        return refresh_error
    if address is None:
        config_error = remove_interface_config_prefix(ctx, interface.name, "ip-address:")
    else:
        config_error = remove_interface_config_command(
            ctx,
            interface.name,
            _static_ipv4_config_key(address),
        )
    return CommandResult(ok=not config_error, message=config_error or result.message)


def _static_ipv4_config_key(address) -> str:
    suffix = ":sub" if address.secondary else ""
    return f"ip-address:{address.address}/{address.prefix_length}{suffix}"


def _refresh_ifnet(
    ctx,
    ifnet_provider: InterfaceProvider | None,
    ifnet_admin_provider: InterfaceAdminProvider | None,
) -> CommandResult | None:
    try:
        get_ifnet_manager(
            ctx.state,
            provider=ifnet_provider,
            admin_provider=ifnet_admin_provider,
        ).refresh()
    except InterfaceDiscoveryError as exc:
        return CommandResult(ok=False, message=f"% {exc}")
    return None


def _filter_interface_kind(
    interfaces: tuple[NetworkInterface, ...],
    kind: str,
) -> tuple[NetworkInterface, ...]:
    return tuple(interface for interface in interfaces if interface.kind == kind)


def _exclude_interface_kind(
    interfaces: tuple[NetworkInterface, ...],
    kind: str,
) -> tuple[NetworkInterface, ...]:
    return tuple(interface for interface in interfaces if interface.kind != kind)


def _filter_ip_configured(
    interfaces: tuple[NetworkInterface, ...],
) -> tuple[NetworkInterface, ...]:
    return tuple(interface for interface in interfaces if _has_ipv4_address(interface))


def _format_ip_interface_brief(
    interfaces: tuple[NetworkInterface, ...],
    state: dict,
) -> str:
    physical_up = sum(1 for interface in interfaces if interface.is_up and not is_admin_down(state, interface.name))
    physical_down = len(interfaces) - physical_up
    protocol_up = sum(1 for interface in interfaces if _protocol_is_up(interface, state))
    protocol_down = len(interfaces) - protocol_up
    lines = [
        "*down: administratively down",
        "!down: FIB overload down",
        "^down: standby",
        "(l): loopback",
        "(s): spoofing",
        "(d): Dampening Suppressed",
        "(E): E-Trunk down",
        "(lcs): license not activated",
        f"The number of interface that is UP in Physical is {physical_up}",
        f"The number of interface that is DOWN in Physical is {physical_down}",
        f"The number of interface that is UP in Protocol is {protocol_up}",
        f"The number of interface that is DOWN in Protocol is {protocol_down}",
        "",
        f"{'Interface':<32} {'IP Address/Mask':<20} {'Physical':<10} {'Protocol':<10}",
    ]
    for interface in interfaces:
        lines.append(
            f"{interface.name:<32} "
            f"{_brief_ipv4_address(interface):<20} "
            f"{_display_physical(interface, state):<10} "
            f"{_display_protocol(interface, state):<10}"
        )
    return "\n".join(lines)


def _format_ip_interface_description(
    interfaces: tuple[NetworkInterface, ...],
    state: dict,
) -> str:
    physical_up = sum(1 for interface in interfaces if interface.is_up and not is_admin_down(state, interface.name))
    physical_down = len(interfaces) - physical_up
    protocol_up = sum(1 for interface in interfaces if _protocol_is_up(interface, state))
    protocol_down = len(interfaces) - protocol_up
    lines = [
        "Codes:",
        "      Eth(Ethernet),       Loop(LoopBack)",
        "",
        "      d(dampened),         D(down),                *D(administratively down),",
        "      l(loopback),         s(spoofing),            U(up)",
        "------------------------------------------------------------------------------",
        f"Number of interfaces whose physical status is Up: {physical_up}",
        f"Number of interfaces whose physical status is Down: {physical_down}",
        f"Number of interfaces whose protocol status is Up: {protocol_up}",
        f"Number of interfaces whose protocol status is Down: {protocol_down}",
        "",
        f"{'Interface':<30} {'IP Address/Mask':<18} {'Phy':<4} {'Prot':<5} Description",
    ]
    for interface in interfaces:
        lines.append(
            f"{interface.name:<30} "
            f"{_brief_ipv4_address(interface):<18} "
            f"{_display_short_physical(interface, state):<4} "
            f"{_display_short_protocol(interface, state):<5}"
        )
    return "\n".join(lines)


def _format_ip_interface_detail(
    interfaces: tuple[NetworkInterface, ...],
    state: dict,
) -> str:
    if not interfaces:
        return "No interfaces found"
    return "\n\n".join(_format_one_ip_interface_detail(interface, state) for interface in interfaces)


def _format_one_ip_interface_detail(interface: NetworkInterface, state: dict) -> str:
    ipv4_addresses = interface.addresses_by_family("ipv4")
    lines = [
        f"{interface.name} current state : {_display_detail_state(interface, state)}",
        f"Line protocol current state : {_display_detail_protocol(interface, state)}",
        f"The Maximum Transmit Unit : {_display_mtu(interface.mtu)}",
    ]
    if not ipv4_addresses:
        lines.extend(
            [
                "Internet protocol processing : disabled",
                "Broadcast address : 0.0.0.0",
            ]
        )
        return "\n".join(lines)

    lines.extend(
        [
            "Internet protocol processing : enabled",
            f"IPv4 address number : {len(ipv4_addresses)}",
        ]
    )
    for index, address in enumerate(ipv4_addresses):
        role = "Primary" if index == 0 else "Sub"
        lines.append(f"Internet Address is {address.display} {role}")
        broadcast = _broadcast_address(address)
        if broadcast:
            lines.append(f"Broadcast address : {broadcast}")
    return "\n".join(lines)


def _brief_ipv4_address(interface: NetworkInterface) -> str:
    addresses = interface.addresses_by_family("ipv4")
    if not addresses:
        return "unassigned"
    return addresses[0].display


def _has_ipv4_address(interface: NetworkInterface) -> bool:
    return bool(interface.addresses_by_family("ipv4"))


def _broadcast_address(address: InterfaceAddress) -> str:
    if address.prefix_length is None:
        return "-"
    try:
        return str(ipaddress.IPv4Interface(address.display).network.broadcast_address)
    except ValueError:
        return "-"


def _display_physical(interface: NetworkInterface, state: dict) -> str:
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
    if not _has_ipv4_address(interface):
        return "down"
    return _display_state(interface)


def _display_detail_protocol(interface: NetworkInterface, state: dict) -> str:
    protocol = _display_protocol(interface, state)
    if protocol == "up(s)":
        return "UP (spoofing)"
    return protocol.upper()


def _display_detail_state(interface: NetworkInterface, state: dict) -> str:
    if is_admin_down(state, interface.name):
        return "Administratively DOWN"
    return "UP" if interface.is_up else "DOWN"


def _display_state(interface: NetworkInterface) -> str:
    return "up" if interface.is_up else "down"


def _protocol_is_up(interface: NetworkInterface, state: dict) -> bool:
    return _display_protocol(interface, state).startswith("up")


def _display_short_physical(interface: NetworkInterface, state: dict) -> str:
    if is_admin_down(state, interface.name):
        return "*D"
    return "U" if interface.is_up else "D"


def _display_short_protocol(interface: NetworkInterface, state: dict) -> str:
    return "U" if _protocol_is_up(interface, state) else "D"


def _display_mtu(mtu: int | None) -> str:
    if mtu is None:
        return "-"
    return f"{mtu} bytes"
