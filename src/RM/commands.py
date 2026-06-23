from __future__ import annotations

from collections.abc import Callable, Sequence
from ipaddress import IPv4Network

from src.CCmd.models import CommandResult
from src.CCmd.registry import CommandRegistry
from src.IFNET.models import InterfaceAddress
from src.IFNET.models import NetworkInterface

from .IM import RM_IM_Interface, RM_IM_interface_table_from_ifnet
from .rib import RM_RouteTable, RM_route_table_from_routes
from .routes import RM_connected_routes_from_im


RM_INTERFACE_NAME_PATTERN = r".+"
RM_SHOW_MODES = ("hidden",)


def RM_register_commands(
    RM_registry: CommandRegistry,
    RM_interfaces_provider: Callable | None = None,
    RM_fib_devices_provider: Callable | None = None,
    RM_fib_backend=None,
    RM_modes: Sequence[str] = RM_SHOW_MODES,
) -> None:
    @RM_registry.command(
        "show rm interface",
        help_text="Show RM interface information",
        modes=tuple(RM_modes),
    )
    def RM_show_rm_interface(RM_ctx, RM_args):
        RM_interfaces = RM_get_im_interfaces(RM_ctx, RM_interfaces_provider)
        if isinstance(RM_interfaces, CommandResult):
            return RM_interfaces
        return CommandResult(message=RM_format_rm_interfaces_detail(RM_interfaces))

    @RM_registry.command(
        "show rm interface brief",
        help_text="Show brief RM interface information",
        modes=tuple(RM_modes),
    )
    def RM_show_rm_interface_brief(RM_ctx, RM_args):
        RM_interfaces = RM_get_im_interfaces(RM_ctx, RM_interfaces_provider)
        if isinstance(RM_interfaces, CommandResult):
            return RM_interfaces
        return CommandResult(message=RM_format_rm_interfaces_brief(RM_interfaces))

    @RM_registry.command(
        f"show rm interface <name:{RM_INTERFACE_NAME_PATTERN}>",
        help_text="Show RM interface information for an interface",
        modes=tuple(RM_modes),
    )
    def RM_show_rm_interface_name(RM_ctx, RM_args):
        RM_interfaces = RM_get_im_interfaces(RM_ctx, RM_interfaces_provider)
        if isinstance(RM_interfaces, CommandResult):
            return RM_interfaces
        RM_name = RM_args["name"]
        for RM_interface in RM_interfaces:
            if RM_interface.name == RM_name:
                return CommandResult(message=RM_format_rm_interfaces_detail((RM_interface,)))
        return CommandResult(ok=False, message=f"% RM interface not found: {RM_name}")

    def RM_interface_name_values(RM_ctx):
        RM_interfaces = RM_get_im_interfaces(RM_ctx, RM_interfaces_provider)
        if isinstance(RM_interfaces, CommandResult):
            return ()
        return tuple(RM_interface.name for RM_interface in RM_interfaces)

    RM_registry.parameter_values(("show", "rm", "interface"), "name", RM_interface_name_values)

    @RM_registry.command(
        "show ip",
        help_text="Show IP information",
        modes=("user", "privileged", "config", "interface", "host-interface", "hidden"),
    )
    def RM_show_ip_command_group(RM_ctx, RM_args):
        from src.CCmd.parser import CommandParser

        RM_candidates = CommandParser(RM_registry).help_candidates("show ip ", mode=RM_ctx.mode, ctx=RM_ctx)
        RM_lines = ["Available show ip commands:"]
        for RM_candidate in RM_candidates:
            RM_lines.append(f"  {RM_candidate.display:<16} {RM_candidate.help_text}".rstrip())
        return CommandResult(message="\n".join(RM_lines))

    @RM_registry.command(
        "show ip routing-table",
        help_text="Show IPv4 routing table",
        modes=("user", "privileged", "config", "interface", "host-interface", "hidden"),
    )
    def RM_show_ip_routing_table(RM_ctx, RM_args):
        RM_table = RM_get_route_table(
            RM_ctx,
            RM_interfaces_provider,
            RM_fib_devices_provider,
            RM_fib_backend,
        )
        if isinstance(RM_table, CommandResult):
            return RM_table
        return CommandResult(message=RM_format_ip_routing_table(RM_table.RM_active_routes()))

    @RM_registry.command(
        "show ip routing-table protocol <protocol:connected|direct|static|dynamic>",
        help_text="Show IPv4 routing table by protocol",
        modes=("user", "privileged", "config", "interface", "host-interface", "hidden"),
    )
    def RM_show_ip_routing_table_protocol(RM_ctx, RM_args):
        RM_table = RM_get_route_table(
            RM_ctx,
            RM_interfaces_provider,
            RM_fib_devices_provider,
            RM_fib_backend,
        )
        if isinstance(RM_table, CommandResult):
            return RM_table
        RM_source = RM_source_from_protocol_token(RM_args["protocol"])
        return CommandResult(message=RM_format_ip_routing_table(RM_table.RM_routes_for_source(RM_source)))


def RM_get_im_interfaces(
    RM_ctx,
    RM_interfaces_provider: Callable | None,
) -> tuple[RM_IM_Interface, ...] | CommandResult:
    if RM_interfaces_provider is None:
        return ()
    try:
        RM_interfaces = RM_interfaces_provider(RM_ctx)
    except Exception as RM_exc:
        return CommandResult(ok=False, message=f"% RM interface discovery failed: {RM_exc}")
    if isinstance(RM_interfaces, CommandResult):
        return RM_interfaces
    return RM_IM_interface_table_from_ifnet(tuple(RM_interfaces)).RM_IM_list()


def RM_get_route_table(
    RM_ctx,
    RM_interfaces_provider: Callable | None,
    RM_fib_devices_provider: Callable | None = None,
    RM_fib_backend=None,
) -> RM_RouteTable | CommandResult:
    RM_existing_table = RM_ctx.state.get("rm.route_table")
    if isinstance(RM_existing_table, RM_RouteTable):
        RM_sync_fib_from_route_table(RM_ctx, RM_existing_table, RM_fib_devices_provider, RM_fib_backend)
        return RM_existing_table
    RM_interfaces = RM_get_im_interfaces(RM_ctx, RM_interfaces_provider)
    if isinstance(RM_interfaces, CommandResult):
        return RM_interfaces
    RM_table = RM_route_table_from_routes(RM_connected_routes_from_im(RM_ctx.state, RM_interfaces))
    RM_ctx.state["rm.route_table"] = RM_table
    RM_sync_fib_from_route_table(RM_ctx, RM_table, RM_fib_devices_provider, RM_fib_backend)
    return RM_table


def RM_sync_fib_from_route_table(
    RM_ctx,
    RM_table: RM_RouteTable,
    RM_fib_devices_provider: Callable | None,
    RM_fib_backend,
) -> None:
    if RM_fib_devices_provider is None:
        return
    from src.FIB import FIB_sync_active_routes

    RM_fib_devices = tuple(RM_fib_devices_provider(RM_ctx))
    FIB_sync_active_routes(
        RM_ctx.state,
        RM_table.RM_active_routes(),
        RM_fib_devices,
        RM_fib_backend,
    )


def RM_format_ip_routing_table(RM_routes) -> str:
    RM_routes = tuple(RM_routes)
    if not RM_routes:
        return "Route Flags: R - relay, D - download to fib\n------------------------------------------------------------------------------\nRouting Tables: Public\n         Destinations : 0        Routes : 0"

    RM_lines = [
        "Route Flags: R - relay, D - download to fib",
        "------------------------------------------------------------------------------",
        "Routing Tables: Public",
        f"         Destinations : {len({RM_route.destination for RM_route in RM_routes})}        Routes : {len(RM_routes)}",
        "",
        "Destination/Mask    Proto   Pre  Cost        Flags NextHop         Interface",
    ]
    for RM_route in sorted(
        RM_routes,
        key=lambda RM_route: (
            int(RM_route.destination.network_address),
            RM_route.destination.prefixlen,
            RM_route.interface.name,
        ),
    ):
        RM_lines.append(
            f"{str(RM_route.destination):<19} "
            f"{RM_display_route_protocol(RM_route.source):<7} "
            f"{RM_route.preference:<4} "
            f"{RM_display_route_cost(RM_route):<11} "
            f"D     "
            f"{RM_display_next_hop(RM_route):<15} "
            f"{RM_route.interface.name}"
        )
    return "\n".join(RM_lines)


def RM_source_from_protocol_token(RM_protocol: str) -> str:
    if RM_protocol in {"connected", "direct"}:
        return "connected"
    return RM_protocol


def RM_display_route_protocol(RM_source: str) -> str:
    if RM_source == "connected":
        return "Direct"
    return RM_source.capitalize()


def RM_display_route_cost(RM_route) -> str:
    return "0"


def RM_display_next_hop(RM_route) -> str:
    return RM_route.next_hop or RM_route.source_ip


def RM_format_rm_interfaces_brief(RM_interfaces: tuple[RM_IM_Interface, ...]) -> str:
    if not RM_interfaces:
        return "No RM interfaces found"

    RM_lines = [
        f"{'Interface':<28} {'IfIndex':<10} {'Phy':<6} {'Protocol':<8} {'IPv4 Address':<24} {'MTU':<8}",
    ]
    for RM_interface in RM_interfaces:
        RM_lines.append(
            f"{RM_interface.name:<28} "
            f"{RM_display_ifnet_index(RM_interface.ifnet_index):<10} "
            f"{RM_display_state(RM_interface):<6} "
            f"{RM_display_protocol(RM_interface):<8} "
            f"{RM_display_ipv4_addresses(RM_interface):<24} "
            f"{RM_display_mtu(RM_interface.mtu):<8}"
        )
    return "\n".join(RM_lines)


def RM_format_rm_interfaces_detail(RM_interfaces: tuple[RM_IM_Interface, ...]) -> str:
    if not RM_interfaces:
        return "No RM interfaces found"
    return "\n\n".join(RM_format_rm_interface_detail(RM_interface) for RM_interface in RM_interfaces)


def RM_format_rm_interface_detail(RM_interface: RM_IM_Interface) -> str:
    RM_ipv4_addresses = RM_interface.RM_IM_addresses_by_family("ipv4")
    RM_lines = [
        f"Name: {RM_interface.name}",
        "Physical IF Info:",
        f" IfnetIndex: {RM_display_ifnet_index(RM_interface.ifnet_index)}",
        f" State: {RM_display_rm_state_flags(RM_interface)}",
        f" Slot: {RM_display_slot(RM_interface)}",
        (
            f" IntType: {RM_display_int_type(RM_interface)}, PriLog: {RM_display_prilog(RM_interface)}, "
            f"MTU: {RM_display_mtu(RM_interface.mtu)}, Reference Count {RM_display_blank()}"
        ),
        " Bandwidth: , ",
        " Baudrate: , ",
        " Delay: , Reliability: , Load: ",
        " LDP-ISIS sync capability: disabled",
        " LDP-OSPF sync capability: disabled",
        " InstanceID: 0, Instance Name: Public",
        " Age: sec",
        "Logical IF Info:",
        (
            f" IfnetIndex: {RM_display_ifnet_index(RM_interface.ifnet_index)}, "
            f"PhyIndex: {RM_display_phy_index(RM_interface)} "
            f"Logical Index : {RM_display_logical_index(RM_interface)},"
        ),
    ]
    if RM_ipv4_addresses:
        for RM_address in RM_ipv4_addresses:
            RM_lines.append(
                f" Dest: {RM_address.address}, Mask: {RM_display_ipv4_mask(RM_address)}"
            )
    else:
        RM_lines.append(" Dest: , Mask: ")
    RM_lines.extend(
        [
            f" State: {RM_display_rm_logical_state_flags(RM_interface)} , Reference Count ",
            " Age: sec",
        ]
    )
    return "\n".join(RM_lines)


def RM_display_ifnet_index(RM_ifnet_index: int) -> str:
    return f"0x{RM_ifnet_index:x}"


def RM_display_state(RM_interface: RM_IM_Interface) -> str:
    return "up" if RM_interface.is_up else "down"


def RM_display_protocol(RM_interface: RM_IM_Interface) -> str:
    if RM_interface.kind == "loopback" and RM_interface.is_up:
        return "up(s)"
    return RM_display_state(RM_interface)


def RM_display_slot(RM_interface: RM_IM_Interface) -> str:
    if RM_interface.kind == "loopback":
        return "0(Logic Slot: 0)"
    return ""


def RM_display_ipv4_addresses(RM_interface: RM_IM_Interface) -> str:
    RM_addresses = RM_interface.RM_IM_addresses_by_family("ipv4")
    if not RM_addresses:
        return "-"
    return ",".join(RM_address.display for RM_address in RM_addresses)


def RM_display_mtu(RM_mtu: int | None) -> str:
    if RM_mtu is None:
        return ""
    return str(RM_mtu)


def RM_display_value(RM_value: object) -> str:
    if RM_value is None or RM_value == "":
        return "-"
    return str(RM_value)


def RM_display_blank() -> str:
    return ""


def RM_display_int_type(RM_interface: RM_IM_Interface) -> str:
    if RM_interface.kind == "loopback":
        return "26"
    if RM_interface.kind == "ethernet":
        return ""
    return ""


def RM_display_prilog(RM_interface: RM_IM_Interface) -> str:
    if RM_interface.kind == "loopback":
        return "1"
    return ""


def RM_display_phy_index(RM_interface: RM_IM_Interface) -> str:
    if RM_interface.kind == "loopback":
        return str(max(RM_interface.ifnet_index, 1))
    return ""


def RM_display_logical_index(RM_interface: RM_IM_Interface) -> str:
    if RM_interface.kind == "loopback":
        return str(max(RM_interface.ifnet_index, 1))
    return ""


def RM_display_rm_state_flags(RM_interface: RM_IM_Interface) -> str:
    RM_flags = ["UP" if RM_interface.is_up else "DOWN"]
    if RM_interface.kind == "loopback":
        RM_flags.extend(("LOOP", "MULT"))
    return " ".join(RM_flags)


def RM_display_rm_logical_state_flags(RM_interface: RM_IM_Interface) -> str:
    RM_flags = ["UP" if RM_interface.is_up else "DOWN"]
    if RM_interface.kind == "loopback":
        RM_flags.extend(("LOOP", "PRM", "MULT"))
    return " ".join(RM_flags)


def RM_display_ipv4_mask(RM_address: InterfaceAddress) -> str:
    if RM_address.prefix_length is None:
        return ""
    return str(IPv4Network(f"0.0.0.0/{RM_address.prefix_length}").netmask)
