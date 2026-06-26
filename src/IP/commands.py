from __future__ import annotations

import ipaddress
from collections.abc import Callable, Sequence
from dataclasses import replace
from datetime import datetime, timezone

from src.CCmd.models import CommandResult
from src.CCmd.registry import CommandRegistry
from src.CCmd.running_config import (
    host_interface_config_commands,
    interface_config_commands,
    remove_host_interface_config_command,
    remove_host_interface_config_prefix,
    remove_interface_config_command,
    remove_interface_config_prefix,
    set_host_interface_config_command,
    set_interface_config_command,
)
from src.IFNET.admin import InterfaceAdminProvider
from src.IFNET.discovery import InterfaceDiscoveryError, InterfaceProvider
from src.IFNET.interfaces import IFNET_ethernet_interface_snapshots
from src.IFNET.inventory import get_ifnet_manager
from src.IFNET.models import InterfaceAddress, NetworkInterface
from src.IFNET.state import IFNET_set_interface_protocol_state, is_admin_down

from .dhcp import IP_DhcpClientProvider
from .ICMP.ping import g_ICMP_PING_ARGUMENT_PATTERN, ICMP_run_ping
from .state import IP_set_interface_addresses
from .static import (
    IP_StaticIpv4Address,
    IP_StaticIpv4Provider,
    IP_StaticIpv4ValidationError,
    IP_has_secondary_static_ipv4,
    IP_parse_static_ipv4_address,
    IP_primary_static_ipv4_from_interface,
    IP_static_ipv4_addresses_from_interface,
    IP_validate_static_ipv4_address_for_interface,
    IP_validate_static_ipv4_interface_policy,
)


g_IP_DEFAULT_COMMAND_MODES = ("user", "privileged", "config", "interface", "hidden")
g_IP_HOST_SHOW_COMMAND_MODES = ("hidden", "interface", "host-interface")
g_IP_IPV4_ADDRESS_PATTERN = r"(?:\d{1,3}\.){3}\d{1,3}"
g_IP_IPV4_MASK_PATTERN = r"(?:(?:\d{1,3}\.){3}\d{1,3}|\d{1,2})"
g_IP_INTERFACE_NAME_PATTERN = r".+"


def IP_register_commands(
    registry: CommandRegistry,
    modes: Sequence[str] = g_IP_DEFAULT_COMMAND_MODES,
    ifnet_provider: InterfaceProvider | None = None,
    ifnet_admin_provider: InterfaceAdminProvider | None = None,
    dhcp_provider: IP_DhcpClientProvider | None = None,
    static_ipv4_provider: IP_StaticIpv4Provider | None = None,
    after_vvrp_ipv4_change: Callable | None = None,
    socket_forwarder_provider: Callable | None = None,
) -> None:
    active_dhcp_provider = dhcp_provider or _IP_NoopDhcpClientProvider()
    active_static_ipv4_provider = static_ipv4_provider or _IP_NoopStaticIpv4Provider()

    @registry.command(
        f"ping <arguments...:{g_ICMP_PING_ARGUMENT_PATTERN}>",
        help_text="Ping an IPv4 address or hostname",
        modes=tuple(modes),
    )
    def IP_ping_command(ctx, args):
        result = ICMP_run_ping(
            args["arguments"],
            ICMP_output=ctx.output,
            ICMP_ctx=ctx,
            ICMP_ifnet_provider=ifnet_provider,
            ICMP_ifnet_admin_provider=ifnet_admin_provider,
            ICMP_socket_forwarder=(
                socket_forwarder_provider(ctx)
                if socket_forwarder_provider is not None
                else None
            ),
        )
        return CommandResult(ok=result.ICMP_ok, message=result.ICMP_message)

    @registry.command(
        "show host ip interface",
        help_text="Show IPv4 interface information",
        modes=g_IP_HOST_SHOW_COMMAND_MODES,
    )
    def IP_show_ip_interface(ctx, args):
        result = _IP_list_interfaces(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(result, CommandResult):
            return result
        return CommandResult(message=_IP_format_ip_interface_detail(result, ctx.state))

    @registry.command(
        "show host ip interface brief",
        help_text="Show brief IPv4 interface summary",
        modes=g_IP_HOST_SHOW_COMMAND_MODES,
    )
    def IP_show_ip_interface_brief(ctx, args):
        result = _IP_list_interfaces(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(result, CommandResult):
            return result
        return CommandResult(message=_IP_format_ip_interface_brief(result, ctx.state))

    @registry.command(
        "show host ip interface brief ethernet",
        help_text="Show brief IPv4 summary for Ethernet interfaces",
        modes=g_IP_HOST_SHOW_COMMAND_MODES,
    )
    def IP_show_ip_interface_brief_ethernet(ctx, args):
        result = _IP_list_interfaces(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(result, CommandResult):
            return result
        result = _IP_filter_interface_kind(result, "ethernet")
        return CommandResult(message=_IP_format_ip_interface_brief(result, ctx.state))

    @registry.command(
        "show host ip interface brief loopback",
        help_text="Show brief IPv4 summary for loopback interfaces",
        modes=g_IP_HOST_SHOW_COMMAND_MODES,
    )
    def IP_show_ip_interface_brief_loopback(ctx, args):
        result = _IP_list_interfaces(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(result, CommandResult):
            return result
        result = _IP_filter_interface_kind(result, "loopback")
        return CommandResult(message=_IP_format_ip_interface_brief(result, ctx.state))

    @registry.command(
        "show host ip interface brief ip-configured",
        help_text="Show brief IPv4 summary for interfaces with IPv4 configured",
        modes=g_IP_HOST_SHOW_COMMAND_MODES,
    )
    def IP_show_ip_interface_brief_ip_configured(ctx, args):
        result = _IP_list_interfaces(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(result, CommandResult):
            return result
        result = _IP_filter_ip_configured(result)
        return CommandResult(message=_IP_format_ip_interface_brief(result, ctx.state))

    @registry.command(
        "show host ip interface brief ip-configured except ethernet",
        help_text="Show IPv4-configured interfaces except Ethernet",
        modes=g_IP_HOST_SHOW_COMMAND_MODES,
    )
    def IP_show_ip_interface_brief_ip_configured_except_ethernet(ctx, args):
        result = _IP_list_interfaces(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(result, CommandResult):
            return result
        result = _IP_exclude_interface_kind(_IP_filter_ip_configured(result), "ethernet")
        return CommandResult(message=_IP_format_ip_interface_brief(result, ctx.state))

    @registry.command(
        "show host ip interface brief ip-configured except loopback",
        help_text="Show IPv4-configured interfaces except loopback",
        modes=g_IP_HOST_SHOW_COMMAND_MODES,
    )
    def IP_show_ip_interface_brief_ip_configured_except_loopback(ctx, args):
        result = _IP_list_interfaces(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(result, CommandResult):
            return result
        result = _IP_exclude_interface_kind(_IP_filter_ip_configured(result), "loopback")
        return CommandResult(message=_IP_format_ip_interface_brief(result, ctx.state))

    @registry.command(
        f"show host ip interface brief <name:{g_IP_INTERFACE_NAME_PATTERN}>",
        help_text="Show brief IPv4 summary for an interface",
        modes=g_IP_HOST_SHOW_COMMAND_MODES,
    )
    def IP_show_ip_interface_brief_name(ctx, args):
        interface = _IP_get_interface(ctx, ifnet_provider, ifnet_admin_provider, args["name"])
        if isinstance(interface, CommandResult):
            return interface
        return CommandResult(message=_IP_format_ip_interface_brief((interface,), ctx.state))

    @registry.command(
        "show host ip interface description",
        help_text="Show IPv4 interface descriptions",
        modes=g_IP_HOST_SHOW_COMMAND_MODES,
    )
    def IP_show_ip_interface_description(ctx, args):
        result = _IP_list_interfaces(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(result, CommandResult):
            return result
        return CommandResult(message=_IP_format_ip_interface_description(result, ctx.state))

    @registry.command(
        "show host ip interface description ethernet",
        help_text="Show IPv4 descriptions for Ethernet interfaces",
        modes=g_IP_HOST_SHOW_COMMAND_MODES,
    )
    def IP_show_ip_interface_description_ethernet(ctx, args):
        result = _IP_list_interfaces(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(result, CommandResult):
            return result
        result = _IP_filter_interface_kind(result, "ethernet")
        return CommandResult(message=_IP_format_ip_interface_description(result, ctx.state))

    @registry.command(
        "show host ip interface description loopback",
        help_text="Show IPv4 descriptions for loopback interfaces",
        modes=g_IP_HOST_SHOW_COMMAND_MODES,
    )
    def IP_show_ip_interface_description_loopback(ctx, args):
        result = _IP_list_interfaces(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(result, CommandResult):
            return result
        result = _IP_filter_interface_kind(result, "loopback")
        return CommandResult(message=_IP_format_ip_interface_description(result, ctx.state))

    @registry.command(
        "show host ip interface description ip-configured",
        help_text="Show IPv4 descriptions for interfaces with IPv4 configured",
        modes=g_IP_HOST_SHOW_COMMAND_MODES,
    )
    def IP_show_ip_interface_description_ip_configured(ctx, args):
        result = _IP_list_interfaces(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(result, CommandResult):
            return result
        result = _IP_filter_ip_configured(result)
        return CommandResult(message=_IP_format_ip_interface_description(result, ctx.state))

    @registry.command(
        "show host ip interface description ip-configured except ethernet",
        help_text="Show IPv4-configured descriptions except Ethernet",
        modes=g_IP_HOST_SHOW_COMMAND_MODES,
    )
    def IP_show_ip_interface_description_ip_configured_except_ethernet(ctx, args):
        result = _IP_list_interfaces(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(result, CommandResult):
            return result
        result = _IP_exclude_interface_kind(_IP_filter_ip_configured(result), "ethernet")
        return CommandResult(message=_IP_format_ip_interface_description(result, ctx.state))

    @registry.command(
        "show host ip interface description ip-configured except loopback",
        help_text="Show IPv4-configured descriptions except loopback",
        modes=g_IP_HOST_SHOW_COMMAND_MODES,
    )
    def IP_show_ip_interface_description_ip_configured_except_loopback(ctx, args):
        result = _IP_list_interfaces(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(result, CommandResult):
            return result
        result = _IP_exclude_interface_kind(_IP_filter_ip_configured(result), "loopback")
        return CommandResult(message=_IP_format_ip_interface_description(result, ctx.state))

    @registry.command(
        f"show host ip interface description <name:{g_IP_INTERFACE_NAME_PATTERN}>",
        help_text="Show IPv4 description for an interface",
        modes=g_IP_HOST_SHOW_COMMAND_MODES,
    )
    def IP_show_ip_interface_description_name(ctx, args):
        interface = _IP_get_interface(ctx, ifnet_provider, ifnet_admin_provider, args["name"])
        if isinstance(interface, CommandResult):
            return interface
        return CommandResult(message=_IP_format_ip_interface_description((interface,), ctx.state))

    @registry.command(
        f"show host ip interface <name:{g_IP_INTERFACE_NAME_PATTERN}>",
        help_text="Show IPv4 information for an interface",
        modes=g_IP_HOST_SHOW_COMMAND_MODES,
    )
    def IP_show_ip_interface_name(ctx, args):
        interface = _IP_get_interface(ctx, ifnet_provider, ifnet_admin_provider, args["name"])
        if isinstance(interface, CommandResult):
            return interface
        return CommandResult(message=_IP_format_one_ip_interface_detail(interface, ctx.state))

    @registry.command(
        "show ip interface",
        help_text="Show IPv4 interface information",
        modes=tuple(modes),
    )
    def IP_show_vvrp_ip_interface(ctx, args):
        result = _IP_list_vvrp_interfaces(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(result, CommandResult):
            return result
        return CommandResult(message=_IP_format_ip_interface_detail(result, ctx.state))

    @registry.command(
        "show ip interface brief",
        help_text="Show brief IPv4 interface summary",
        modes=tuple(modes),
    )
    def IP_show_vvrp_ip_interface_brief(ctx, args):
        result = _IP_list_vvrp_interfaces(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(result, CommandResult):
            return result
        return CommandResult(message=_IP_format_ip_interface_brief(result, ctx.state))

    @registry.command(
        "show ip interface brief ethernet",
        help_text="Show brief IPv4 summary for Ethernet interfaces",
        modes=tuple(modes),
    )
    def IP_show_vvrp_ip_interface_brief_ethernet(ctx, args):
        result = _IP_list_vvrp_interfaces(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(result, CommandResult):
            return result
        return CommandResult(message=_IP_format_ip_interface_brief(_IP_filter_interface_kind(result, "ethernet"), ctx.state))

    @registry.command(
        "show ip interface brief loopback",
        help_text="Show brief IPv4 summary for loopback interfaces",
        modes=tuple(modes),
    )
    def IP_show_vvrp_ip_interface_brief_loopback(ctx, args):
        result = _IP_list_vvrp_interfaces(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(result, CommandResult):
            return result
        return CommandResult(message=_IP_format_ip_interface_brief(_IP_filter_interface_kind(result, "loopback"), ctx.state))

    @registry.command(
        "show ip interface brief ip-configured",
        help_text="Show brief IPv4 summary for interfaces with IPv4 configured",
        modes=tuple(modes),
    )
    def IP_show_vvrp_ip_interface_brief_ip_configured(ctx, args):
        result = _IP_list_vvrp_interfaces(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(result, CommandResult):
            return result
        return CommandResult(message=_IP_format_ip_interface_brief(_IP_filter_ip_configured(result), ctx.state))

    @registry.command(
        "show ip interface brief ip-configured except ethernet",
        help_text="Show IPv4-configured interfaces except Ethernet",
        modes=tuple(modes),
    )
    def IP_show_vvrp_ip_interface_brief_ip_configured_except_ethernet(ctx, args):
        result = _IP_list_vvrp_interfaces(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(result, CommandResult):
            return result
        result = _IP_exclude_interface_kind(_IP_filter_ip_configured(result), "ethernet")
        return CommandResult(message=_IP_format_ip_interface_brief(result, ctx.state))

    @registry.command(
        "show ip interface brief ip-configured except loopback",
        help_text="Show IPv4-configured interfaces except loopback",
        modes=tuple(modes),
    )
    def IP_show_vvrp_ip_interface_brief_ip_configured_except_loopback(ctx, args):
        result = _IP_list_vvrp_interfaces(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(result, CommandResult):
            return result
        result = _IP_exclude_interface_kind(_IP_filter_ip_configured(result), "loopback")
        return CommandResult(message=_IP_format_ip_interface_brief(result, ctx.state))

    @registry.command(
        f"show ip interface brief <name:{g_IP_INTERFACE_NAME_PATTERN}>",
        help_text="Show brief IPv4 summary for an interface",
        modes=tuple(modes),
    )
    def IP_show_vvrp_ip_interface_brief_name(ctx, args):
        interface = _IP_get_vvrp_interface(ctx, ifnet_provider, ifnet_admin_provider, args["name"])
        if isinstance(interface, CommandResult):
            return interface
        return CommandResult(message=_IP_format_ip_interface_brief((interface,), ctx.state))

    @registry.command(
        "show ip interface description",
        help_text="Show IPv4 interface descriptions",
        modes=tuple(modes),
    )
    def IP_show_vvrp_ip_interface_description(ctx, args):
        result = _IP_list_vvrp_interfaces(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(result, CommandResult):
            return result
        return CommandResult(message=_IP_format_ip_interface_description(result, ctx.state))

    @registry.command(
        "show ip interface description ethernet",
        help_text="Show IPv4 descriptions for Ethernet interfaces",
        modes=tuple(modes),
    )
    def IP_show_vvrp_ip_interface_description_ethernet(ctx, args):
        result = _IP_list_vvrp_interfaces(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(result, CommandResult):
            return result
        return CommandResult(message=_IP_format_ip_interface_description(_IP_filter_interface_kind(result, "ethernet"), ctx.state))

    @registry.command(
        "show ip interface description loopback",
        help_text="Show IPv4 descriptions for loopback interfaces",
        modes=tuple(modes),
    )
    def IP_show_vvrp_ip_interface_description_loopback(ctx, args):
        result = _IP_list_vvrp_interfaces(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(result, CommandResult):
            return result
        return CommandResult(message=_IP_format_ip_interface_description(_IP_filter_interface_kind(result, "loopback"), ctx.state))

    @registry.command(
        "show ip interface description ip-configured",
        help_text="Show IPv4 descriptions for interfaces with IPv4 configured",
        modes=tuple(modes),
    )
    def IP_show_vvrp_ip_interface_description_ip_configured(ctx, args):
        result = _IP_list_vvrp_interfaces(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(result, CommandResult):
            return result
        return CommandResult(message=_IP_format_ip_interface_description(_IP_filter_ip_configured(result), ctx.state))

    @registry.command(
        "show ip interface description ip-configured except ethernet",
        help_text="Show IPv4-configured descriptions except Ethernet",
        modes=tuple(modes),
    )
    def IP_show_vvrp_ip_interface_description_ip_configured_except_ethernet(ctx, args):
        result = _IP_list_vvrp_interfaces(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(result, CommandResult):
            return result
        result = _IP_exclude_interface_kind(_IP_filter_ip_configured(result), "ethernet")
        return CommandResult(message=_IP_format_ip_interface_description(result, ctx.state))

    @registry.command(
        "show ip interface description ip-configured except loopback",
        help_text="Show IPv4-configured descriptions except loopback",
        modes=tuple(modes),
    )
    def IP_show_vvrp_ip_interface_description_ip_configured_except_loopback(ctx, args):
        result = _IP_list_vvrp_interfaces(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(result, CommandResult):
            return result
        result = _IP_exclude_interface_kind(_IP_filter_ip_configured(result), "loopback")
        return CommandResult(message=_IP_format_ip_interface_description(result, ctx.state))

    @registry.command(
        f"show ip interface description <name:{g_IP_INTERFACE_NAME_PATTERN}>",
        help_text="Show IPv4 description for an interface",
        modes=tuple(modes),
    )
    def IP_show_vvrp_ip_interface_description_name(ctx, args):
        interface = _IP_get_vvrp_interface(ctx, ifnet_provider, ifnet_admin_provider, args["name"])
        if isinstance(interface, CommandResult):
            return interface
        return CommandResult(message=_IP_format_ip_interface_description((interface,), ctx.state))

    @registry.command(
        f"show ip interface <name:{g_IP_INTERFACE_NAME_PATTERN}>",
        help_text="Show IPv4 information for an interface",
        modes=tuple(modes),
    )
    def IP_show_vvrp_ip_interface_name(ctx, args):
        interface = _IP_get_vvrp_interface(ctx, ifnet_provider, ifnet_admin_provider, args["name"])
        if isinstance(interface, CommandResult):
            return interface
        return CommandResult(message=_IP_format_one_ip_interface_detail(interface, ctx.state))

    @registry.command(
        "ip",
        help_text="Configure IP features",
        modes=("interface", "host-interface"),
    )
    def IP_command_group(ctx, args):
        return _IP_format_command_group_help(registry, ctx, "ip ")

    @registry.command(
        "no",
        help_text="Negate a command or set its defaults",
        modes=("interface", "host-interface"),
    )
    def IP_no_command_group(ctx, args):
        return _IP_format_command_group_help(registry, ctx, "no ")

    @registry.command(
        "ip address dhcp-alloc",
        help_text="Obtain an IPv4 address with DHCP",
        modes=("host-interface",),
    )
    def IP_address_dhcp_alloc(ctx, args):
        interface = _IP_current_host_interface(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(interface, CommandResult):
            return interface
        unsupported = _IP_unsupported_dhcp_interface(interface)
        if unsupported is not None:
            return unsupported

        result = active_dhcp_provider.IP_enable_dhcp(interface)
        if not result.ok:
            return CommandResult(ok=False, message=result.message)
        refresh_error = _IP_refresh_ifnet(ctx, ifnet_provider, ifnet_admin_provider)
        if refresh_error is not None:
            return refresh_error
        remove_error = remove_host_interface_config_prefix(ctx, interface.name, "ip-address:")
        if remove_error:
            return CommandResult(ok=False, message=remove_error)
        config_error = set_host_interface_config_command(
            ctx,
            interface.name,
            "ip-address-dhcp",
            "ip address dhcp-alloc",
        )
        return CommandResult(ok=not config_error, message=config_error or result.message)

    @registry.command(
        "no ip address dhcp-alloc",
        help_text="Disable DHCP address allocation",
        modes=("host-interface",),
    )
    def IP_no_address_dhcp_alloc(ctx, args):
        interface = _IP_current_host_interface(ctx, ifnet_provider, ifnet_admin_provider)
        if isinstance(interface, CommandResult):
            return interface
        unsupported = _IP_unsupported_dhcp_interface(interface)
        if unsupported is not None:
            return unsupported

        result = active_dhcp_provider.IP_disable_dhcp(interface)
        if not result.ok:
            return CommandResult(ok=False, message=result.message)
        refresh_error = _IP_refresh_ifnet(ctx, ifnet_provider, ifnet_admin_provider)
        if refresh_error is not None:
            return refresh_error
        config_error = remove_host_interface_config_command(
            ctx,
            interface.name,
            "ip-address-dhcp",
        )
        return CommandResult(ok=not config_error, message=config_error or result.message)

    @registry.command(
        f"ip address <ip_address:{g_IP_IPV4_ADDRESS_PATTERN}> <mask:{g_IP_IPV4_MASK_PATTERN}>",
        help_text="Configure a primary static IPv4 address",
        modes=("interface", "host-interface"),
    )
    def IP_address_static(ctx, args):
        return _IP_set_static_ipv4(
            ctx,
            ifnet_provider,
            ifnet_admin_provider,
            active_static_ipv4_provider,
            after_vvrp_ipv4_change,
            args["ip_address"],
            args["mask"],
            secondary=False,
        )

    @registry.command(
        f"ip address <ip_address:{g_IP_IPV4_ADDRESS_PATTERN}> <mask:{g_IP_IPV4_MASK_PATTERN}> sub",
        help_text="Configure a secondary static IPv4 address",
        modes=("interface", "host-interface"),
    )
    def IP_address_static_sub(ctx, args):
        return _IP_set_static_ipv4(
            ctx,
            ifnet_provider,
            ifnet_admin_provider,
            active_static_ipv4_provider,
            after_vvrp_ipv4_change,
            args["ip_address"],
            args["mask"],
            secondary=True,
        )

    @registry.command(
        "no ip address",
        help_text="Remove all static IPv4 addresses",
        modes=("interface", "host-interface"),
    )
    def IP_no_address_all(ctx, args):
        return _IP_remove_static_ipv4(
            ctx,
            ifnet_provider,
            ifnet_admin_provider,
            active_static_ipv4_provider,
            after_vvrp_ipv4_change,
        )

    @registry.command(
        f"no ip address <ip_address:{g_IP_IPV4_ADDRESS_PATTERN}> <mask:{g_IP_IPV4_MASK_PATTERN}>",
        help_text="Remove a static IPv4 address",
        modes=("interface", "host-interface"),
    )
    def IP_no_address_static(ctx, args):
        return _IP_remove_static_ipv4(
            ctx,
            ifnet_provider,
            ifnet_admin_provider,
            active_static_ipv4_provider,
            after_vvrp_ipv4_change,
            args["ip_address"],
            args["mask"],
            secondary=False,
        )

    @registry.command(
        f"no ip address <ip_address:{g_IP_IPV4_ADDRESS_PATTERN}> <mask:{g_IP_IPV4_MASK_PATTERN}> sub",
        help_text="Remove a secondary static IPv4 address",
        modes=("interface", "host-interface"),
    )
    def IP_no_address_static_sub(ctx, args):
        return _IP_remove_static_ipv4(
            ctx,
            ifnet_provider,
            ifnet_admin_provider,
            active_static_ipv4_provider,
            after_vvrp_ipv4_change,
            args["ip_address"],
            args["mask"],
            secondary=True,
        )


def _IP_current_host_interface(
    ctx,
    ifnet_provider: InterfaceProvider | None,
    ifnet_admin_provider: InterfaceAdminProvider | None,
) -> NetworkInterface | CommandResult:
    return _IP_get_interface(ctx, ifnet_provider, ifnet_admin_provider, ctx.mode_label)


def _IP_format_command_group_help(
    registry: CommandRegistry,
    ctx,
    prefix: str,
) -> CommandResult:
    from src.CCmd.parser import CommandParser

    candidates = CommandParser(registry).help_candidates(prefix, mode=ctx.mode, ctx=ctx)
    lines = [f"Available {prefix.strip()} commands:"]
    for candidate in candidates:
        lines.append(f"  {candidate.display:<16} {candidate.help_text}".rstrip())
    return CommandResult(message="\n".join(lines))


def _IP_current_vvrp_interface(
    ctx,
    ifnet_provider: InterfaceProvider | None,
    ifnet_admin_provider: InterfaceAdminProvider | None,
) -> NetworkInterface | CommandResult:
    return _IP_get_vvrp_interface(ctx, ifnet_provider, ifnet_admin_provider, ctx.mode_label)


def _IP_current_interface(
    ctx,
    ifnet_provider: InterfaceProvider | None,
    ifnet_admin_provider: InterfaceAdminProvider | None,
) -> NetworkInterface | CommandResult:
    if ctx.mode == "host-interface":
        return _IP_current_host_interface(ctx, ifnet_provider, ifnet_admin_provider)
    return _IP_current_vvrp_interface(ctx, ifnet_provider, ifnet_admin_provider)


def _IP_list_interfaces(
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


def _IP_list_vvrp_interfaces(
    ctx,
    ifnet_provider: InterfaceProvider | None,
    ifnet_admin_provider: InterfaceAdminProvider | None,
) -> tuple[NetworkInterface, ...] | CommandResult:
    interfaces = _IP_list_interfaces(ctx, ifnet_provider, ifnet_admin_provider)
    if isinstance(interfaces, CommandResult):
        return interfaces
    return IFNET_ethernet_interface_snapshots(ctx.state, interfaces)


def _IP_get_interface(
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


def _IP_get_vvrp_interface(
    ctx,
    ifnet_provider: InterfaceProvider | None,
    ifnet_admin_provider: InterfaceAdminProvider | None,
    name: str,
) -> NetworkInterface | CommandResult:
    interfaces = _IP_list_vvrp_interfaces(ctx, ifnet_provider, ifnet_admin_provider)
    if isinstance(interfaces, CommandResult):
        return interfaces
    for interface in interfaces:
        if interface.name == name:
            return interface
    return CommandResult(ok=False, message=f"% Interface not found: {name}")


def _IP_unsupported_dhcp_interface(interface: NetworkInterface) -> CommandResult | None:
    if interface.kind == "ethernet":
        return None
    return CommandResult(
        ok=False,
        message=(
            f"% {interface.kind.capitalize()} interface does not support DHCP client: "
            f"{interface.name}"
        ),
    )


def _IP_unsupported_static_ipv4_interface(interface: NetworkInterface) -> CommandResult | None:
    if interface.kind in ("ethernet", "loopback"):
        return None
    return CommandResult(
        ok=False,
        message=(
            f"% {interface.kind.capitalize()} interface does not support static IPv4: "
            f"{interface.name}"
        ),
    )


def _IP_set_static_ipv4(
    ctx,
    ifnet_provider: InterfaceProvider | None,
    ifnet_admin_provider: InterfaceAdminProvider | None,
    static_ipv4_provider: IP_StaticIpv4Provider,
    after_vvrp_ipv4_change: Callable | None,
    ip_address: str,
    mask: str,
    secondary: bool,
) -> CommandResult:
    if ctx.mode == "host-interface":
        return _IP_set_host_static_ipv4(
            ctx,
            ifnet_provider,
            ifnet_admin_provider,
            static_ipv4_provider,
            ip_address,
            mask,
            secondary,
        )
    return _IP_set_vvrp_static_ipv4(
        ctx,
        ifnet_provider,
            ifnet_admin_provider,
            after_vvrp_ipv4_change,
            ip_address,
        mask,
        secondary,
    )


def _IP_set_host_static_ipv4(
    ctx,
    ifnet_provider: InterfaceProvider | None,
    ifnet_admin_provider: InterfaceAdminProvider | None,
    static_ipv4_provider: IP_StaticIpv4Provider,
    ip_address: str,
    mask: str,
    secondary: bool,
) -> CommandResult:
    interface = _IP_current_host_interface(ctx, ifnet_provider, ifnet_admin_provider)
    if isinstance(interface, CommandResult):
        return interface
    unsupported = _IP_unsupported_static_ipv4_interface(interface)
    if unsupported is not None:
        return unsupported
    interfaces = _IP_list_interfaces(ctx, ifnet_provider, ifnet_admin_provider)
    if isinstance(interfaces, CommandResult):
        return interfaces

    try:
        address = IP_parse_static_ipv4_address(ip_address, mask, secondary=secondary)
        IP_validate_static_ipv4_address_for_interface(address, interface, interfaces)
    except IP_StaticIpv4ValidationError as exc:
        return CommandResult(ok=False, message=str(exc))

    if not address.secondary:
        current_primary = IP_primary_static_ipv4_from_interface(interface)
        if current_primary is not None and current_primary != address:
            remove_result = static_ipv4_provider.IP_remove_static_ipv4(interface, current_primary)
            if not remove_result.ok:
                return CommandResult(ok=False, message=remove_result.message)

    result = static_ipv4_provider.IP_set_static_ipv4(interface, address)
    if not result.ok:
        return CommandResult(ok=False, message=result.message)
    refresh_error = _IP_refresh_ifnet(ctx, ifnet_provider, ifnet_admin_provider)
    if refresh_error is not None:
        return refresh_error
    dhcp_error = remove_host_interface_config_command(ctx, interface.name, "ip-address-dhcp")
    if dhcp_error:
        return CommandResult(ok=False, message=dhcp_error)
    line = f"ip address {address.address} {address.prefix_length}"
    if address.secondary:
        line += " sub"
    config_error = set_host_interface_config_command(
        ctx,
        interface.name,
        _IP_static_ipv4_config_key(address),
        line,
    )
    return CommandResult(ok=not config_error, message=config_error or result.message)


def _IP_set_vvrp_static_ipv4(
    ctx,
    ifnet_provider: InterfaceProvider | None,
    ifnet_admin_provider: InterfaceAdminProvider | None,
    after_vvrp_ipv4_change: Callable | None,
    ip_address: str,
    mask: str,
    secondary: bool,
) -> CommandResult:
    interface = _IP_current_vvrp_interface(ctx, ifnet_provider, ifnet_admin_provider)
    if isinstance(interface, CommandResult):
        return interface
    unsupported = _IP_unsupported_static_ipv4_interface(interface)
    if unsupported is not None:
        return unsupported
    interfaces = _IP_list_vvrp_interfaces(ctx, ifnet_provider, ifnet_admin_provider)
    if isinstance(interfaces, CommandResult):
        return interfaces

    try:
        address = IP_parse_static_ipv4_address(ip_address, mask, secondary=secondary)
        IP_validate_static_ipv4_address_for_interface(address, interface, interfaces)
    except IP_StaticIpv4ValidationError as exc:
        return CommandResult(ok=False, message=str(exc))

    current = list(IP_static_ipv4_addresses_from_interface(interface))
    if address.secondary:
        current.append(address)
    else:
        current = [address, *[item for item in current if item.secondary]]
    protocol_was_up = _IP_protocol_is_up(interface, ctx.state)
    _IP_apply_vvrp_static_ipv4_addresses(ctx, interface.name, tuple(current))
    _IP_call_after_vvrp_ipv4_change(ctx, after_vvrp_ipv4_change)

    dhcp_error = remove_interface_config_command(ctx, interface.name, "ip-address-dhcp")
    if dhcp_error:
        return CommandResult(ok=False, message=dhcp_error)
    line = f"ip address {address.address} {address.prefix_length}"
    if address.secondary:
        line += " sub"
    config_error = set_interface_config_command(
        ctx,
        interface.name,
        _IP_static_ipv4_config_key(address),
        line,
    )
    if config_error:
        return CommandResult(ok=False, message=config_error)
    return CommandResult(
        message=_IP_protocol_transition_message(
            ctx,
            interface,
            tuple(current),
            protocol_was_up,
        )
    )


def _IP_remove_static_ipv4(
    ctx,
    ifnet_provider: InterfaceProvider | None,
    ifnet_admin_provider: InterfaceAdminProvider | None,
    static_ipv4_provider: IP_StaticIpv4Provider,
    after_vvrp_ipv4_change: Callable | None,
    ip_address: str | None = None,
    mask: str | None = None,
    secondary: bool = False,
) -> CommandResult:
    if ctx.mode == "host-interface":
        return _IP_remove_host_static_ipv4(
            ctx,
            ifnet_provider,
            ifnet_admin_provider,
            static_ipv4_provider,
            ip_address,
            mask,
            secondary,
        )
    return _IP_remove_vvrp_static_ipv4(
        ctx,
        ifnet_provider,
            ifnet_admin_provider,
            after_vvrp_ipv4_change,
            ip_address,
        mask,
        secondary,
    )


def _IP_remove_host_static_ipv4(
    ctx,
    ifnet_provider: InterfaceProvider | None,
    ifnet_admin_provider: InterfaceAdminProvider | None,
    static_ipv4_provider: IP_StaticIpv4Provider,
    ip_address: str | None = None,
    mask: str | None = None,
    secondary: bool = False,
) -> CommandResult:
    interface = _IP_current_host_interface(ctx, ifnet_provider, ifnet_admin_provider)
    if isinstance(interface, CommandResult):
        return interface
    unsupported = _IP_unsupported_static_ipv4_interface(interface)
    if unsupported is not None:
        return unsupported

    address = None
    if ip_address is not None and mask is not None:
        try:
            address = IP_parse_static_ipv4_address(ip_address, mask, secondary=secondary)
            _IP_validate_static_ipv4_removal_target(
                address,
                interface,
                host_interface_config_commands(ctx, interface.name),
            )
        except IP_StaticIpv4ValidationError as exc:
            return CommandResult(ok=False, message=str(exc))

    result = static_ipv4_provider.IP_remove_static_ipv4(interface, address)
    if not result.ok:
        return CommandResult(ok=False, message=result.message)
    refresh_error = _IP_refresh_ifnet(ctx, ifnet_provider, ifnet_admin_provider)
    if refresh_error is not None:
        return refresh_error
    if address is None:
        config_error = remove_host_interface_config_prefix(ctx, interface.name, "ip-address:")
    else:
        config_error = remove_host_interface_config_command(
            ctx,
            interface.name,
            _IP_static_ipv4_config_key(address),
        )
    return CommandResult(ok=not config_error, message=config_error or result.message)


def _IP_remove_vvrp_static_ipv4(
    ctx,
    ifnet_provider: InterfaceProvider | None,
    ifnet_admin_provider: InterfaceAdminProvider | None,
    after_vvrp_ipv4_change: Callable | None,
    ip_address: str | None = None,
    mask: str | None = None,
    secondary: bool = False,
) -> CommandResult:
    interface = _IP_current_vvrp_interface(ctx, ifnet_provider, ifnet_admin_provider)
    if isinstance(interface, CommandResult):
        return interface
    unsupported = _IP_unsupported_static_ipv4_interface(interface)
    if unsupported is not None:
        return unsupported

    address = None
    if ip_address is not None and mask is not None:
        try:
            address = IP_parse_static_ipv4_address(ip_address, mask, secondary=secondary)
            _IP_validate_static_ipv4_removal_target(
                address,
                interface,
                interface_config_commands(ctx, interface.name),
            )
        except IP_StaticIpv4ValidationError as exc:
            return CommandResult(ok=False, message=str(exc))

    if address is None:
        protocol_was_up = _IP_protocol_is_up(interface, ctx.state)
        _IP_apply_vvrp_static_ipv4_addresses(ctx, interface.name, ())
        _IP_call_after_vvrp_ipv4_change(ctx, after_vvrp_ipv4_change)
        config_error = remove_interface_config_prefix(ctx, interface.name, "ip-address:")
        if config_error:
            return CommandResult(ok=False, message=config_error)
        return CommandResult(
            message=_IP_protocol_transition_message(
                ctx,
                interface,
                (),
                protocol_was_up,
            )
        )

    current = tuple(
        item
        for item in IP_static_ipv4_addresses_from_interface(interface)
        if not (
            item.address == address.address
            and item.prefix_length == address.prefix_length
            and item.secondary == address.secondary
        )
    )
    protocol_was_up = _IP_protocol_is_up(interface, ctx.state)
    _IP_apply_vvrp_static_ipv4_addresses(ctx, interface.name, current)
    _IP_call_after_vvrp_ipv4_change(ctx, after_vvrp_ipv4_change)
    config_error = remove_interface_config_command(
        ctx,
        interface.name,
        _IP_static_ipv4_config_key(address),
    )
    if config_error:
        return CommandResult(ok=False, message=config_error)
    return CommandResult(
        message=_IP_protocol_transition_message(
            ctx,
            interface,
            current,
            protocol_was_up,
        )
    )


def _IP_apply_vvrp_static_ipv4_addresses(
    ctx,
    interface_name: str,
    addresses: tuple[IP_StaticIpv4Address, ...],
) -> None:
    IP_set_interface_addresses(
        ctx.state,
        interface_name,
        tuple(_IP_interface_address_from_static(address) for address in addresses),
    )


def _IP_call_after_vvrp_ipv4_change(ctx, callback: Callable | None) -> None:
    if callback is None:
        return
    callback(ctx)


def _IP_interface_address_from_static(address: IP_StaticIpv4Address) -> InterfaceAddress:
    return InterfaceAddress(
        family="ipv4",
        address=address.address,
        prefix_length=address.prefix_length,
    )


def _IP_protocol_transition_message(
    ctx,
    interface: NetworkInterface,
    addresses: tuple[IP_StaticIpv4Address, ...],
    protocol_was_up: bool,
) -> str:
    updated = replace(
        interface,
        addresses=tuple(_IP_interface_address_from_static(address) for address in addresses),
    )
    protocol_is_up = _IP_protocol_is_up(updated, ctx.state)
    if not protocol_was_up and protocol_is_up:
        IFNET_set_interface_protocol_state(ctx.state, interface.name, "up")
        return _IP_format_line_protocol_log(ctx.hostname, interface.name, "UP")
    if protocol_was_up and not protocol_is_up:
        IFNET_set_interface_protocol_state(ctx.state, interface.name, "down")
        return _IP_format_line_protocol_log(ctx.hostname, interface.name, "DOWN")
    IFNET_set_interface_protocol_state(ctx.state, interface.name, "up" if protocol_is_up else "down")
    return ""


def _IP_format_line_protocol_log(hostname: str, interface_name: str, state: str) -> str:
    event_index = "1" if state == "UP" else "2"
    timestamp = datetime.now(timezone.utc).astimezone().strftime("%b %d %Y %H:%M:%S%z")
    timestamp = f"{timestamp[:-2]}:{timestamp[-2:]}"
    return (
        f"{timestamp} {hostname} %%01IFNET/4/LINK_STATE(l)[{event_index}]:"
        f"The line protocol IP on the interface {interface_name} has entered the {state} state."
    )


def _IP_static_ipv4_config_key(address) -> str:
    if not address.secondary:
        return "ip-address:primary"
    suffix = ":sub" if address.secondary else ""
    return f"ip-address:{address.address}/{address.prefix_length}{suffix}"


def _IP_validate_static_ipv4_removal_target(
    address: IP_StaticIpv4Address,
    interface: NetworkInterface,
    commands: dict[str, str],
) -> None:
    IP_validate_static_ipv4_interface_policy(address, interface)
    configured = IP_static_ipv4_addresses_from_interface(interface)
    if configured and not any(
        item.address == address.address and item.prefix_length == address.prefix_length
        for item in configured
    ):
        raise IP_StaticIpv4ValidationError(
            f"% IPv4 address not found on interface {interface.name}: "
            f"{address.address}/{address.prefix_length}"
        )

    if address.secondary:
        return

    configured_secondary = any(
        key.startswith("ip-address:") and key.endswith(":sub")
        for key in commands
    )
    if configured_secondary or IP_has_secondary_static_ipv4(interface):
        raise IP_StaticIpv4ValidationError(
            "% Please delete all secondary IPv4 addresses before deleting the primary address"
        )


def _IP_refresh_ifnet(
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


def _IP_filter_interface_kind(
    interfaces: tuple[NetworkInterface, ...],
    kind: str,
) -> tuple[NetworkInterface, ...]:
    return tuple(interface for interface in interfaces if interface.kind == kind)


def _IP_exclude_interface_kind(
    interfaces: tuple[NetworkInterface, ...],
    kind: str,
) -> tuple[NetworkInterface, ...]:
    return tuple(interface for interface in interfaces if interface.kind != kind)


def _IP_filter_ip_configured(
    interfaces: tuple[NetworkInterface, ...],
) -> tuple[NetworkInterface, ...]:
    return tuple(interface for interface in interfaces if _IP_has_ipv4_address(interface))


def _IP_format_ip_interface_brief(
    interfaces: tuple[NetworkInterface, ...],
    state: dict,
) -> str:
    physical_up = sum(1 for interface in interfaces if interface.is_up and not is_admin_down(state, interface.name))
    physical_down = len(interfaces) - physical_up
    protocol_up = sum(1 for interface in interfaces if _IP_protocol_is_up(interface, state))
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
            f"{_IP_brief_ipv4_address(interface):<20} "
            f"{_IP_display_physical(interface, state):<10} "
            f"{_IP_display_protocol(interface, state):<10}"
        )
    return "\n".join(lines)


def _IP_format_ip_interface_description(
    interfaces: tuple[NetworkInterface, ...],
    state: dict,
) -> str:
    physical_up = sum(1 for interface in interfaces if interface.is_up and not is_admin_down(state, interface.name))
    physical_down = len(interfaces) - physical_up
    protocol_up = sum(1 for interface in interfaces if _IP_protocol_is_up(interface, state))
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
            f"{_IP_brief_ipv4_address(interface):<18} "
            f"{_IP_display_short_physical(interface, state):<4} "
            f"{_IP_display_short_protocol(interface, state):<5}"
        )
    return "\n".join(lines)


def _IP_format_ip_interface_detail(
    interfaces: tuple[NetworkInterface, ...],
    state: dict,
) -> str:
    if not interfaces:
        return "No interfaces found"
    return "\n\n".join(_IP_format_one_ip_interface_detail(interface, state) for interface in interfaces)


def _IP_format_one_ip_interface_detail(interface: NetworkInterface, state: dict) -> str:
    ipv4_addresses = interface.addresses_by_family("ipv4")
    lines = [
        f"{interface.name} current state : {_IP_display_detail_state(interface, state)}",
        f"Line protocol current state : {_IP_display_detail_protocol(interface, state)}",
        f"The Maximum Transmit Unit : {_IP_display_mtu(interface.mtu)}",
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
        broadcast = _IP_broadcast_address(address)
        if broadcast:
            lines.append(f"Broadcast address : {broadcast}")
    return "\n".join(lines)


def _IP_brief_ipv4_address(interface: NetworkInterface) -> str:
    addresses = interface.addresses_by_family("ipv4")
    if not addresses:
        return "unassigned"
    return addresses[0].display


def _IP_has_ipv4_address(interface: NetworkInterface) -> bool:
    return bool(interface.addresses_by_family("ipv4"))


def _IP_broadcast_address(address: InterfaceAddress) -> str:
    if address.prefix_length is None:
        return "-"
    try:
        return str(ipaddress.IPv4Interface(address.display).network.broadcast_address)
    except ValueError:
        return "-"


def _IP_display_physical(interface: NetworkInterface, state: dict) -> str:
    if is_admin_down(state, interface.name):
        return "*down"
    if interface.kind == "loopback":
        return f"{_IP_display_state(interface)}(l)"
    return _IP_display_state(interface)


def _IP_display_protocol(interface: NetworkInterface, state: dict) -> str:
    if is_admin_down(state, interface.name):
        return "down"
    if interface.kind == "loopback" and interface.is_up:
        return "up(s)"
    if not _IP_has_ipv4_address(interface):
        return "down"
    return _IP_display_state(interface)


def _IP_display_detail_protocol(interface: NetworkInterface, state: dict) -> str:
    protocol = _IP_display_protocol(interface, state)
    if protocol == "up(s)":
        return "UP (spoofing)"
    return protocol.upper()


def _IP_display_detail_state(interface: NetworkInterface, state: dict) -> str:
    if is_admin_down(state, interface.name):
        return "Administratively DOWN"
    return "UP" if interface.is_up else "DOWN"


def _IP_display_state(interface: NetworkInterface) -> str:
    return "up" if interface.is_up else "down"


def _IP_protocol_is_up(interface: NetworkInterface, state: dict) -> bool:
    return _IP_display_protocol(interface, state).startswith("up")


def _IP_display_short_physical(interface: NetworkInterface, state: dict) -> str:
    if is_admin_down(state, interface.name):
        return "*D"
    return "U" if interface.is_up else "D"


def _IP_display_short_protocol(interface: NetworkInterface, state: dict) -> str:
    return "U" if _IP_protocol_is_up(interface, state) else "D"


def _IP_display_mtu(mtu: int | None) -> str:
    if mtu is None:
        return "-"
    return f"{mtu} bytes"


class _IP_NoopDhcpClientProvider:
    def IP_enable_dhcp(self, interface: NetworkInterface):
        from .dhcp import IP_DhcpClientResult

        return IP_DhcpClientResult(ok=False, message="% DHCP provider is not available")

    def IP_disable_dhcp(self, interface: NetworkInterface):
        from .dhcp import IP_DhcpClientResult

        return IP_DhcpClientResult(ok=False, message="% DHCP provider is not available")


class _IP_NoopStaticIpv4Provider:
    def IP_set_static_ipv4(self, interface: NetworkInterface, address: IP_StaticIpv4Address):
        from .static import IP_StaticIpv4Result

        return IP_StaticIpv4Result(ok=False, message="% static IPv4 provider is not available")

    def IP_remove_static_ipv4(
        self,
        interface: NetworkInterface,
        address: IP_StaticIpv4Address | None = None,
    ):
        from .static import IP_StaticIpv4Result

        return IP_StaticIpv4Result(ok=False, message="% static IPv4 provider is not available")



