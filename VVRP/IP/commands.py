from __future__ import annotations

from collections.abc import Sequence

from VVRP.CCmd.models import CommandResult
from VVRP.CCmd.registry import CommandRegistry
from VVRP.IFNET.admin import InterfaceAdminProvider
from VVRP.IFNET.discovery import InterfaceDiscoveryError, InterfaceProvider
from VVRP.IFNET.inventory import get_ifnet_manager
from VVRP.IFNET.models import NetworkInterface

from .dhcp import DhcpClientProvider, OsDhcpClientProvider
from .ping import PING_TARGET_PATTERN, run_ping
from .static import (
    OsStaticIpv4Provider,
    StaticIpv4Provider,
    StaticIpv4ValidationError,
    parse_static_ipv4_address,
)


DEFAULT_IP_COMMAND_MODES = ("user", "privileged", "config", "interface", "hidden")
IPV4_ADDRESS_PATTERN = r"(?:\d{1,3}\.){3}\d{1,3}"
IPV4_MASK_PATTERN = r"(?:(?:\d{1,3}\.){3}\d{1,3}|\d{1,2})"


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
        f"ping <target:{PING_TARGET_PATTERN}>",
        help_text="Ping an IPv4, IPv6, hostname, or domain",
        modes=tuple(modes),
    )
    def ping(ctx, args):
        result = run_ping(args["target"])
        return CommandResult(ok=result.ok, message=result.message)

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
        return CommandResult(message=result.message)

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
        return CommandResult(message=result.message)

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
    return CommandResult(message=result.message)


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
    return CommandResult(message=result.message)


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
