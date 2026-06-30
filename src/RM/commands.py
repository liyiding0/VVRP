from __future__ import annotations

from collections.abc import Callable, Sequence
from ipaddress import AddressValueError, IPv4Address, IPv4Network, NetmaskValueError
import re
import shlex
import time

from src.CMD.models import CommandResult
from src.CMD.registry import CommandRegistry
from src.CMD.running_config import (
    remove_global_config_command,
    set_global_config_command,
)
from src.IFNET.models import InterfaceAddress
from src.IFNET.models import NetworkInterface

from .IM import (
    RM_IM_Interface,
    RM_IM_ReconcileResult,
    RM_IM_interface_table,
    RM_IM_reconcile_from_ifnet,
)
from .rib import RM_RouteTable, RM_route_table_from_routes
from .routes import (
    RM_connected_routes_from_im,
    RM_sync_connected_routes_for_interface,
)
from .state import RM_clear_router_id, RM_router_id, RM_set_router_id
from .static import (
    RM_StaticRouteConfig,
    RM_find_interface,
    RM_remove_static_route_configs,
    RM_set_static_route_config,
    RM_static_route_configs,
    RM_static_route_config_key,
    RM_static_route_config_line,
    RM_sync_static_routes,
)


RM_INTERFACE_NAME_PATTERN = r".+"
RM_ROUTER_ID_PATTERN = r"(?:\d{1,3}\.){3}\d{1,3}"
RM_IPV4_ADDRESS_PATTERN = r"(?:\d{1,3}\.){3}\d{1,3}"
RM_IPV4_MASK_PATTERN = rf"(?:{RM_IPV4_ADDRESS_PATTERN}|[0-9]{{1,2}})"
RM_SHOW_MODES = ("hidden",)
RM_ALL_SHOW_MODES = ("user", "privileged", "config", "interface", "host-interface", "hidden")


def RM_register_commands(
    RM_registry: CommandRegistry,
    RM_interfaces_provider: Callable | None = None,
    RM_modes: Sequence[str] = RM_SHOW_MODES,
    RM_after_route_change: Callable | None = None,
    **RM_ignored_legacy_kwargs,
) -> None:
    @RM_registry.command(
        f"ip route-static <destination:{RM_IPV4_ADDRESS_PATTERN}> "
        f"<mask:{RM_IPV4_MASK_PATTERN}> <arguments...:.+>",
        help_text="Configure an IPv4 static route",
        modes=("config",),
    )
    def RM_configure_static_route(RM_ctx, RM_args):
        RM_interfaces = RM_get_im_interfaces(RM_ctx, RM_interfaces_provider)
        if isinstance(RM_interfaces, CommandResult):
            return RM_interfaces
        RM_config = RM_parse_static_route_config(
            RM_args["destination"],
            RM_args["mask"],
            RM_args["arguments"],
            RM_interfaces,
        )
        if isinstance(RM_config, CommandResult):
            return RM_config
        RM_set_static_route_config(RM_ctx.state, RM_config)
        RM_message = set_global_config_command(
            RM_ctx,
            RM_static_route_config_key(RM_config),
            RM_static_route_config_line(RM_config),
        )
        RM_refresh_static_route_control_plane(RM_ctx, RM_after_route_change)
        return CommandResult(ok=not RM_message, message=RM_message)

    @RM_registry.command(
        f"no ip route-static <destination:{RM_IPV4_ADDRESS_PATTERN}> "
        f"<mask:{RM_IPV4_MASK_PATTERN}> <arguments...:.*>",
        help_text="Remove an IPv4 static route",
        modes=("config",),
    )
    def RM_remove_static_route(RM_ctx, RM_args):
        RM_interfaces = RM_get_im_interfaces(RM_ctx, RM_interfaces_provider)
        if isinstance(RM_interfaces, CommandResult):
            return RM_interfaces
        RM_selector = RM_parse_static_route_selector(
            RM_args["destination"],
            RM_args["mask"],
            RM_args["arguments"],
            RM_interfaces,
        )
        if isinstance(RM_selector, CommandResult):
            return RM_selector
        RM_destination, RM_interface_name, RM_next_hop = RM_selector
        RM_removed = RM_remove_static_route_configs(
            RM_ctx.state,
            RM_destination,
            RM_interface_name,
            RM_next_hop,
        )
        if not RM_removed:
            return CommandResult(ok=False, message="% Static route not found")
        RM_messages = [
            remove_global_config_command(RM_ctx, RM_static_route_config_key(RM_config))
            for RM_config in RM_removed
        ]
        RM_refresh_static_route_control_plane(RM_ctx, RM_after_route_change)
        RM_message = next((RM_value for RM_value in RM_messages if RM_value), "")
        return CommandResult(ok=not RM_message, message=RM_message)

    @RM_registry.command(
        f"no ip route-static <destination:{RM_IPV4_ADDRESS_PATTERN}> "
        f"<mask:{RM_IPV4_MASK_PATTERN}>",
        help_text="Remove all matching IPv4 static routes",
        modes=("config",),
    )
    def RM_remove_static_routes_for_destination(RM_ctx, RM_args):
        return RM_remove_static_route(
            RM_ctx,
            {
                "destination": RM_args["destination"],
                "mask": RM_args["mask"],
                "arguments": "",
            },
        )

    @RM_registry.command(
        f"router id <router_id:{RM_ROUTER_ID_PATTERN}>",
        help_text="Configure router ID",
        modes=("config",),
    )
    def RM_configure_router_id(RM_ctx, RM_args):
        RM_router_id_value = RM_normalize_router_id(RM_args["router_id"])
        if RM_router_id_value is None:
            return CommandResult(ok=False, message="% Invalid router ID")
        RM_set_router_id(RM_ctx.state, RM_router_id_value)
        RM_message = set_global_config_command(
            RM_ctx,
            "router id",
            f"router id {RM_router_id_value}",
        )
        return CommandResult(ok=not RM_message, message=RM_message)

    @RM_registry.command(
        "no router id",
        help_text="Remove configured router ID",
        modes=("config",),
    )
    def RM_remove_router_id(RM_ctx, RM_args):
        RM_clear_router_id(RM_ctx.state)
        RM_message = remove_global_config_command(RM_ctx, "router id")
        return CommandResult(ok=not RM_message, message=RM_message)

    @RM_registry.command(
        "show router id",
        help_text="Show configured router ID",
        modes=RM_ALL_SHOW_MODES,
    )
    def RM_show_router_id(RM_ctx, RM_args):
        return CommandResult(message=f"RouterID:{RM_router_id(RM_ctx.state) or '0.0.0.0'}")

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
        modes=RM_ALL_SHOW_MODES,
    )
    def RM_show_ip_command_group(RM_ctx, RM_args):
        from src.CMD.parser import CommandParser

        RM_candidates = CommandParser(RM_registry).help_candidates("show ip ", mode=RM_ctx.mode, ctx=RM_ctx)
        RM_lines = ["Available show ip commands:"]
        for RM_candidate in RM_candidates:
            RM_lines.append(f"  {RM_candidate.display:<16} {RM_candidate.help_text}".rstrip())
        return CommandResult(message="\n".join(RM_lines))

    @RM_registry.command(
        "show ip routing-table",
        help_text="Show IPv4 routing table",
        modes=RM_ALL_SHOW_MODES,
    )
    def RM_show_ip_routing_table(RM_ctx, RM_args):
        RM_table = RM_get_route_table(
            RM_ctx,
            RM_interfaces_provider,
        )
        if isinstance(RM_table, CommandResult):
            return RM_table
        return CommandResult(message=RM_format_ip_routing_table(RM_table.RM_active_routes()))

    @RM_registry.command(
        "show ip routing-table verbose",
        help_text="Show verbose information of routing table",
        modes=RM_ALL_SHOW_MODES,
    )
    def RM_show_ip_routing_table_verbose(RM_ctx, RM_args):
        RM_table = RM_get_route_table(
            RM_ctx,
            RM_interfaces_provider,
        )
        if isinstance(RM_table, CommandResult):
            return RM_table
        return CommandResult(
            message=RM_format_ip_routing_table_verbose(RM_ctx.state, RM_table)
        )

    @RM_registry.command(
        "show ip routing-table protocol direct",
        help_text="Show Direct routes",
        modes=RM_ALL_SHOW_MODES,
    )
    def RM_show_ip_routing_table_protocol_direct(RM_ctx, RM_args):
        RM_table = RM_get_route_table(
            RM_ctx,
            RM_interfaces_provider,
        )
        if isinstance(RM_table, CommandResult):
            return RM_table
        RM_routes = RM_table.RM_routes_for_source("connected")
        RM_active_routes = tuple(
            RM_route
            for RM_route in RM_table.RM_active_routes()
            if RM_route.source == "connected"
        )
        return CommandResult(
            message=RM_format_direct_routing_table(RM_routes, RM_active_routes)
        )

    def RM_static_route_status(RM_ctx):
        RM_table = RM_get_route_table(RM_ctx, RM_interfaces_provider)
        if isinstance(RM_table, CommandResult):
            return RM_table
        return RM_static_route_status_entries(RM_ctx.state, RM_table)

    @RM_registry.command(
        "show ip routing-table protocol static",
        help_text="Show Static routes",
        modes=RM_ALL_SHOW_MODES,
    )
    def RM_show_ip_routing_table_protocol_static(RM_ctx, RM_args):
        RM_entries = RM_static_route_status(RM_ctx)
        if isinstance(RM_entries, CommandResult):
            return RM_entries
        return CommandResult(message=RM_format_static_routing_table(RM_entries))

    @RM_registry.command(
        "show ip routing-table protocol static inactive",
        help_text="Show inactive Static route information",
        modes=RM_ALL_SHOW_MODES,
    )
    def RM_show_ip_routing_table_protocol_static_inactive(RM_ctx, RM_args):
        RM_entries = RM_static_route_status(RM_ctx)
        if isinstance(RM_entries, CommandResult):
            return RM_entries
        return CommandResult(message=RM_format_static_routing_table_inactive(RM_entries))

    @RM_registry.command(
        "show ip routing-table protocol static verbose",
        help_text="Show verbose Static route information",
        modes=RM_ALL_SHOW_MODES,
    )
    def RM_show_ip_routing_table_protocol_static_verbose(RM_ctx, RM_args):
        RM_entries = RM_static_route_status(RM_ctx)
        if isinstance(RM_entries, CommandResult):
            return RM_entries
        return CommandResult(message=RM_format_static_routing_table_verbose(RM_entries))


def RM_static_route_status_entries(RM_state: dict, RM_table: RM_RouteTable) -> tuple:
    RM_routes = RM_table.RM_routes_for_source("static")
    RM_active_routes = RM_table.RM_active_routes()
    RM_entries = []
    for RM_config in RM_static_route_configs(RM_state):
        RM_matching_routes = tuple(
            RM_route
            for RM_route in RM_routes
            if RM_route.destination == RM_config.destination
            and RM_route.next_hop == RM_config.next_hop
            and (
                RM_config.interface_name is None
                or RM_route.interface.name.casefold() == RM_config.interface_name.casefold()
            )
        )
        RM_active_route = next(
            (
                RM_route
                for RM_route in RM_matching_routes
                if RM_route in RM_active_routes
            ),
            None,
        )
        RM_display_route = RM_active_route or (RM_matching_routes[0] if RM_matching_routes else None)
        RM_entries.append((RM_config, RM_display_route, RM_active_route is not None))
    return tuple(RM_entries)


def RM_format_direct_routing_table(
    RM_routes: tuple,
    RM_active_routes: tuple,
) -> str:
    RM_routes = tuple(RM_routes)
    RM_active_routes = tuple(RM_active_routes)
    RM_inactive_routes = tuple(
        RM_route
        for RM_route in RM_routes
        if RM_route not in RM_active_routes
    )
    RM_destinations = len({RM_route.destination for RM_route in RM_routes})
    RM_lines = [
        "Route Flags: R - relay, D - download to fib",
        "------------------------------------------------------------------------------",
        "Public routing table : Direct",
        f"         Destinations : {RM_destinations}        Routes : {len(RM_routes)}",
        "",
        "Direct routing table status : <Active>",
        (
            f"         Destinations : "
            f"{len({RM_route.destination for RM_route in RM_active_routes})}        "
            f"Routes : {len(RM_active_routes)}"
        ),
    ]
    if RM_active_routes:
        RM_lines.extend(("", *RM_direct_route_table_lines(RM_active_routes, True)))
    RM_lines.extend(
        (
            "",
            "Direct routing table status : <Inactive>",
            (
                f"         Destinations : "
                f"{len({RM_route.destination for RM_route in RM_inactive_routes})}        "
                f"Routes : {len(RM_inactive_routes)}"
            ),
        )
    )
    if RM_inactive_routes:
        RM_lines.extend(("", *RM_direct_route_table_lines(RM_inactive_routes, False)))
    return "\n".join(RM_lines)


def RM_direct_route_table_lines(
    RM_routes: tuple,
    RM_is_active: bool,
) -> tuple[str, ...]:
    RM_lines = [
        "Destination/Mask    Proto   Pre  Cost      Flags NextHop         Interface",
        "",
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
            f"{str(RM_route.destination):>19}  "
            f"{'Direct':<7} "
            f"{RM_route.preference:<4} "
            f"{0:<9} "
            f"{('D' if RM_is_active else ''):<5} "
            f"{RM_display_next_hop(RM_route):<15} "
            f"{RM_route.interface.name}"
        )
    return tuple(RM_lines)


def RM_format_ip_routing_table_verbose(
    RM_state: dict,
    RM_table: RM_RouteTable,
) -> str:
    RM_direct_routes = RM_table.RM_routes_for_source("connected")
    RM_active_direct_routes = tuple(
        RM_route
        for RM_route in RM_table.RM_active_routes()
        if RM_route.source == "connected"
    )
    RM_static_entries = RM_static_route_status_entries(RM_state, RM_table)
    RM_records = [
        (
            RM_route.destination,
            0,
            (RM_route, RM_route in RM_active_direct_routes),
        )
        for RM_route in RM_direct_routes
    ]
    RM_records.extend(
        (RM_entry[0].destination, 1, RM_entry)
        for RM_entry in RM_static_entries
    )
    RM_records.sort(
        key=lambda RM_record: (
            int(RM_record[0].network_address),
            RM_record[0].prefixlen,
            RM_record[1],
        )
    )
    RM_destinations = len({RM_record[0] for RM_record in RM_records})
    RM_static_indices = {
        RM_config.RM_identity: RM_index
        for RM_index, RM_config in enumerate(
            (RM_entry[0] for RM_entry in RM_static_entries),
            start=1,
        )
    }
    RM_lines = [
        "Route Flags: R - relay, D - download to fib",
        "------------------------------------------------------------------------------",
        "Routing Tables: Public",
        f"         Destinations : {RM_destinations}        Routes : {len(RM_records)}",
        "",
        "",
    ]
    for _, RM_kind, RM_value in RM_records:
        if RM_kind == 0:
            RM_lines.extend(RM_verbose_direct_route_lines(*RM_value))
        else:
            RM_config = RM_value[0]
            RM_lines.extend(
                RM_verbose_static_route_lines(
                    RM_value,
                    RM_static_indices[RM_config.RM_identity],
                )
            )
        RM_lines.append("")
    return "\n".join(RM_lines).rstrip()


def RM_verbose_direct_route_lines(
    RM_route,
    RM_is_active: bool,
) -> tuple[str, ...]:
    RM_no_advertise = (
        RM_route.next_hop == "127.0.0.1"
        or RM_route.interface.name == "InLoopBack0"
    )
    RM_state_prefix = "Active" if RM_is_active else "Inactive"
    RM_state = (
        f"{RM_state_prefix} NoAdv"
        if RM_no_advertise
        else f"{RM_state_prefix} Adv"
    )
    return (
        f"Destination: {RM_route.destination}",
        "     Protocol: Direct          Process ID: 0",
        f"   Preference: {RM_route.preference:<22} Cost: 0",
        (
            f"      NextHop: {RM_display_next_hop(RM_route):<15} "
            "Neighbour: 0.0.0.0"
        ),
        f"        State: {RM_state:<22} Age: {RM_route_age(RM_route.created_at)}",
        f"          Tag: {(RM_route.tag or 0):<17} Priority: high",
        "        Label: NULL               QoSInfo: 0x0",
        "   IndirectID: 0x0",
        (
            " RelayNextHop: 0.0.0.0          "
            f"Interface: {RM_route.interface.name}"
        ),
        f"     TunnelID: 0x0                  Flags: {' D' if RM_is_active else ''}",
    )


def RM_format_static_routing_table(RM_entries: tuple) -> str:
    RM_active = tuple(RM_entry for RM_entry in RM_entries if RM_entry[2])
    RM_inactive = tuple(RM_entry for RM_entry in RM_entries if not RM_entry[2])
    RM_lines = [
        "Route Flags: R - relay, D - download to fib",
        "------------------------------------------------------------------------------",
        "Public routing table : Static",
        RM_static_summary_line(RM_entries, len(RM_entries)),
        "",
        "Static routing table status : <Active>",
        RM_static_summary_line(RM_active, len(RM_active), RM_include_configured=False),
    ]
    if RM_active:
        RM_lines.extend(("", *RM_static_route_table_lines(RM_active)))
    RM_lines.extend(
        (
            "",
            "Static routing table status : <Inactive>",
            RM_static_summary_line(RM_inactive, len(RM_inactive), RM_include_configured=False),
        )
    )
    if RM_inactive:
        RM_lines.extend(("", *RM_static_route_table_lines(RM_inactive)))
    return "\n".join(RM_lines)


def RM_format_static_routing_table_inactive(RM_entries: tuple) -> str:
    RM_inactive = tuple(RM_entry for RM_entry in RM_entries if not RM_entry[2])
    RM_lines = [
        "Route Flags: R - relay, D - download to fib",
        "------------------------------------------------------------------------------",
        "Static routing table",
        RM_static_summary_line(
            RM_inactive,
            len(RM_entries),
        ),
    ]
    if RM_inactive:
        RM_lines.extend(("", *RM_static_route_table_lines(RM_inactive)))
    return "\n".join(RM_lines)


def RM_format_static_routing_table_verbose(RM_entries: tuple) -> str:
    RM_lines = [
        "Route Flags: R - relay, D - download to fib",
        "------------------------------------------------------------------------------",
        "Routing Tables: Public",
        RM_static_summary_line(RM_entries, len(RM_entries)),
        "",
    ]
    for RM_index, RM_entry in enumerate(RM_entries, start=1):
        RM_lines.extend((*RM_verbose_static_route_lines(RM_entry, RM_index), ""))
    return "\n".join(RM_lines).rstrip()


def RM_verbose_static_route_lines(
    RM_entry: tuple,
    RM_index: int,
) -> tuple[str, ...]:
    RM_config, RM_route, RM_is_active = RM_entry
    RM_flags = RM_static_route_flags(RM_config, RM_is_active)
    RM_state = "Active"
    if RM_is_active:
        RM_state += " NoAdv" if RM_config.no_advertise else " Adv"
        if RM_config.next_hop:
            RM_state += " Relied"
    else:
        RM_state = "Invalid"
        RM_state += " NoAdv" if RM_config.no_advertise else " Adv"
    return (
        f"Destination: {RM_config.destination}",
        "     Protocol: Static          Process ID: 0",
        f"   Preference: {RM_config.preference:<22} Cost: 0",
        (
            f"      NextHop: {(RM_config.next_hop or '0.0.0.0'):<15} "
            "Neighbour: 0.0.0.0"
        ),
        f"        State: {RM_state:<22} Age: {RM_static_route_age(RM_config)}",
        f"          Tag: {(RM_config.tag or 0):<17} Priority: medium",
        "        Label: NULL               QoSInfo: 0x0",
        f"   IndirectID: 0x{0x80000000 + RM_index:x}",
        (
            f" RelayNextHop: 0.0.0.0          "
            f"Interface: {RM_static_route_interface(RM_route)}"
        ),
        f"     TunnelID: 0x0                  Flags: {RM_flags}",
    )


def RM_static_summary_line(
    RM_entries: tuple,
    RM_configured_routes: int,
    RM_include_configured: bool = True,
) -> str:
    RM_destinations = len({RM_entry[0].destination for RM_entry in RM_entries})
    RM_line = f"         Destinations : {RM_destinations}        Routes : {len(RM_entries)}"
    if RM_include_configured:
        RM_line += f"        Configured Routes : {RM_configured_routes}"
    return RM_line


def RM_static_route_table_lines(RM_entries: tuple) -> tuple[str, ...]:
    RM_lines = [
        "Destination/Mask    Proto   Pre  Cost      Flags NextHop         Interface",
        "",
    ]
    for RM_config, RM_route, RM_is_active in RM_entries:
        RM_lines.append(
            f"{str(RM_config.destination):>19}  "
            f"{'Static':<7} "
            f"{RM_config.preference:<4} "
            f"{0:<9} "
            f"{RM_static_route_flags(RM_config, RM_is_active):<5} "
            f"{(RM_config.next_hop or '0.0.0.0'):<15} "
            f"{RM_static_route_interface(RM_route)}"
        )
    return tuple(RM_lines)


def RM_static_route_flags(RM_config: RM_StaticRouteConfig, RM_is_active: bool) -> str:
    if not RM_is_active:
        return ""
    return ("R" if RM_config.next_hop else "") + "D"


def RM_static_route_interface(RM_route) -> str:
    if RM_route is None:
        return "Unknown"
    return RM_route.interface.name


def RM_static_route_age(RM_config: RM_StaticRouteConfig) -> str:
    return RM_route_age(RM_config.configured_at)


def RM_route_age(RM_created_at: float) -> str:
    RM_seconds = max(0, int(time.monotonic() - RM_created_at))
    RM_days, RM_seconds = divmod(RM_seconds, 86400)
    RM_hours, RM_remainder = divmod(RM_seconds, 3600)
    RM_minutes, RM_seconds = divmod(RM_remainder, 60)
    RM_age = f"{RM_hours:02d}h{RM_minutes:02d}m{RM_seconds:02d}s"
    if RM_days:
        return f"{RM_days}d{RM_age}"
    return RM_age


def RM_normalize_router_id(RM_router_id_value: str) -> str | None:
    try:
        RM_address = IPv4Address(RM_router_id_value)
    except AddressValueError:
        return None
    if RM_address.is_unspecified or RM_address.is_multicast or RM_address == IPv4Address("255.255.255.255"):
        return None
    return str(RM_address)


def RM_parse_static_route_config(
    RM_destination_text: str,
    RM_mask_text: str,
    RM_arguments_text: str,
    RM_interfaces: tuple[RM_IM_Interface, ...],
) -> RM_StaticRouteConfig | CommandResult:
    try:
        RM_tokens = shlex.split(RM_arguments_text)
    except ValueError as RM_exc:
        return CommandResult(ok=False, message=f"% Invalid static route: {RM_exc}")
    if not RM_tokens:
        return CommandResult(ok=False, message="% Incomplete static route")

    RM_destination = RM_parse_static_destination(RM_destination_text, RM_mask_text)
    if isinstance(RM_destination, CommandResult):
        return RM_destination

    RM_target = RM_parse_static_target(RM_tokens, RM_interfaces)
    if isinstance(RM_target, CommandResult):
        return RM_target
    RM_interface, RM_next_hop = RM_target

    RM_preference = 60
    RM_preference_configured = False
    RM_tag = None
    RM_description = ""
    RM_permanent = False
    RM_no_advertise = False
    RM_seen: set[str] = set()

    while RM_tokens:
        RM_option = RM_tokens.pop(0).casefold()
        if RM_option in RM_seen:
            return CommandResult(ok=False, message=f"% Duplicate static route option: {RM_option}")
        RM_seen.add(RM_option)
        if RM_option == "preference":
            RM_value = RM_pop_static_integer(RM_tokens, "preference", 1, 255)
            if isinstance(RM_value, CommandResult):
                return RM_value
            RM_preference = RM_value
            RM_preference_configured = True
        elif RM_option == "tag":
            RM_value = RM_pop_static_integer(RM_tokens, "tag", 1, 4294967295)
            if isinstance(RM_value, CommandResult):
                return RM_value
            RM_tag = RM_value
        elif RM_option == "permanent":
            RM_permanent = True
        elif RM_option == "no-advertise":
            RM_no_advertise = True
        elif RM_option == "description":
            if not RM_tokens:
                return CommandResult(ok=False, message="% Static route description is required")
            RM_description = " ".join(RM_tokens)
            if len(RM_description) > 80:
                return CommandResult(ok=False, message="% Static route description is too long")
            RM_tokens.clear()
        else:
            return CommandResult(ok=False, message=f"% Unknown static route option: {RM_option}")

    return RM_StaticRouteConfig(
        destination=RM_destination,
        next_hop=RM_next_hop,
        interface_name=RM_interface.name if RM_interface is not None else None,
        preference=RM_preference,
        preference_configured=RM_preference_configured,
        tag=RM_tag,
        description=RM_description,
        permanent=RM_permanent,
        no_advertise=RM_no_advertise,
    )


def RM_parse_static_route_selector(
    RM_destination_text: str,
    RM_mask_text: str,
    RM_arguments_text: str,
    RM_interfaces: tuple[RM_IM_Interface, ...],
) -> tuple[IPv4Network, str | None, str | None] | CommandResult:
    try:
        RM_tokens = shlex.split(RM_arguments_text)
    except ValueError as RM_exc:
        return CommandResult(ok=False, message=f"% Invalid static route: {RM_exc}")
    RM_destination = RM_parse_static_destination(RM_destination_text, RM_mask_text)
    if isinstance(RM_destination, CommandResult):
        return RM_destination
    if not RM_tokens:
        return RM_destination, None, None
    RM_target = RM_parse_static_target(RM_tokens, RM_interfaces)
    if isinstance(RM_target, CommandResult):
        return RM_target
    RM_interface, RM_next_hop = RM_target
    return RM_destination, RM_interface.name if RM_interface else None, RM_next_hop


def RM_parse_static_destination(
    RM_destination_text: str,
    RM_mask_text: str,
) -> IPv4Network | CommandResult:
    try:
        RM_address = IPv4Address(RM_destination_text)
        RM_destination = IPv4Network(f"{RM_address}/{RM_mask_text}", strict=False)
    except (AddressValueError, NetmaskValueError, ValueError):
        return CommandResult(ok=False, message="% Invalid destination address or mask")
    if RM_address.is_multicast:
        return CommandResult(ok=False, message="% Invalid static route destination")
    return RM_destination


def RM_parse_static_target(
    RM_tokens: list[str],
    RM_interfaces: tuple[RM_IM_Interface, ...],
) -> tuple[RM_IM_Interface | None, str | None] | CommandResult:
    if not RM_tokens:
        return CommandResult(ok=False, message="% Static route next hop or interface is required")

    RM_first = RM_tokens.pop(0)
    if ":" in RM_first:
        return CommandResult(ok=False, message="% IPv6 next-hop addresses are not supported")
    RM_next_hop = RM_normalize_static_next_hop(RM_first)
    if RM_next_hop is not None:
        return None, RM_next_hop
    if re.fullmatch(r"[0-9.]+", RM_first):
        return CommandResult(ok=False, message="% Invalid static route next-hop address")

    RM_interface = RM_find_interface(RM_interfaces, RM_first)
    if RM_interface is None and RM_tokens:
        RM_interface = RM_find_interface(RM_interfaces, f"{RM_first}{RM_tokens[0]}")
        if RM_interface is not None:
            RM_tokens.pop(0)
    if RM_interface is None:
        return CommandResult(ok=False, message=f"% Interface not found: {RM_first}")

    RM_next_hop = None
    if RM_tokens:
        RM_possible_next_hop = RM_normalize_static_next_hop(RM_tokens[0])
        if RM_possible_next_hop is not None:
            RM_next_hop = RM_possible_next_hop
            RM_tokens.pop(0)
        elif re.fullmatch(r"[0-9.:]+", RM_tokens[0]):
            return CommandResult(ok=False, message="% Invalid static route next-hop address")
    if RM_interface.kind == "ethernet" and RM_next_hop is None:
        return CommandResult(
            ok=False,
            message="% An Ethernet static route requires a next-hop address",
        )
    if RM_interface.kind not in {"serial", "null", "ethernet"} and RM_next_hop is None:
        return CommandResult(ok=False, message="% This interface requires a next-hop address")
    return RM_interface, RM_next_hop


def RM_normalize_static_next_hop(RM_value: str) -> str | None:
    try:
        RM_address = IPv4Address(RM_value)
    except AddressValueError:
        return None
    if RM_address.is_unspecified or RM_address.is_multicast or RM_address == IPv4Address("255.255.255.255"):
        return None
    return str(RM_address)


def RM_pop_static_integer(
    RM_tokens: list[str],
    RM_name: str,
    RM_minimum: int,
    RM_maximum: int,
) -> int | CommandResult:
    if not RM_tokens:
        return CommandResult(ok=False, message=f"% Static route {RM_name} is required")
    try:
        RM_value = int(RM_tokens.pop(0), 10)
    except ValueError:
        return CommandResult(ok=False, message=f"% Invalid static route {RM_name}")
    if not RM_minimum <= RM_value <= RM_maximum:
        return CommandResult(ok=False, message=f"% Invalid static route {RM_name}")
    return RM_value


def RM_refresh_static_route_control_plane(RM_ctx, RM_callback: Callable | None) -> None:
    if RM_callback is not None:
        RM_callback(RM_ctx)


def RM_get_im_interfaces(
    RM_ctx,
    RM_interfaces_provider: Callable | None,
) -> tuple[RM_IM_Interface, ...] | CommandResult:
    RM_im_table = RM_IM_interface_table(RM_ctx.state)
    RM_existing_interfaces = RM_im_table.RM_IM_list()
    if RM_existing_interfaces or RM_interfaces_provider is None:
        return RM_existing_interfaces
    RM_reconcile_result = RM_reconcile_im_interfaces(
        RM_ctx,
        RM_interfaces_provider,
    )
    if isinstance(RM_reconcile_result, CommandResult):
        return RM_reconcile_result
    return RM_reconcile_result.RM_IM_table.RM_IM_list()


def RM_reconcile_im_interfaces(
    RM_ctx,
    RM_interfaces_provider: Callable,
) -> RM_IM_ReconcileResult | CommandResult:
    try:
        RM_interfaces = RM_interfaces_provider(RM_ctx)
    except Exception as RM_exc:
        return CommandResult(ok=False, message=f"% RM interface discovery failed: {RM_exc}")
    if isinstance(RM_interfaces, CommandResult):
        return RM_interfaces
    return RM_IM_reconcile_from_ifnet(
        RM_ctx.state,
        tuple(RM_interfaces),
    )


def RM_get_route_table(
    RM_ctx,
    RM_interfaces_provider: Callable | None,
) -> RM_RouteTable | CommandResult:
    RM_existing_table = RM_ctx.state.get("rm.route_table")
    if isinstance(RM_existing_table, RM_RouteTable):
        return RM_existing_table
    RM_interfaces = RM_get_im_interfaces(RM_ctx, RM_interfaces_provider)
    if isinstance(RM_interfaces, CommandResult):
        return RM_interfaces
    RM_table = RM_route_table_from_routes(RM_connected_routes_from_im(RM_ctx.state, RM_interfaces))
    RM_sync_static_routes(RM_ctx.state, RM_interfaces, RM_table)
    RM_ctx.state["rm.route_table"] = RM_table
    return RM_table


def RM_refresh_connected_routes_from_interfaces(
    RM_ctx,
    RM_interfaces_provider: Callable | None,
) -> RM_RouteTable | CommandResult:
    if RM_interfaces_provider is None:
        RM_im_table = RM_IM_interface_table(RM_ctx.state)
        RM_changed_interfaces = RM_im_table.RM_IM_list()
        RM_deleted_interfaces = ()
    else:
        RM_reconcile_result = RM_reconcile_im_interfaces(
            RM_ctx,
            RM_interfaces_provider,
        )
        if isinstance(RM_reconcile_result, CommandResult):
            return RM_reconcile_result
        RM_im_table = RM_reconcile_result.RM_IM_table
        RM_changed_interfaces = RM_reconcile_result.RM_IM_changed
        RM_deleted_interfaces = RM_reconcile_result.RM_IM_deleted
    from .rib import RM_route_table

    RM_table = RM_route_table(RM_ctx.state)
    for RM_interface_name in RM_deleted_interfaces:
        RM_table.RM_replace_routes_for_interface_source(
            RM_interface_name,
            "connected",
            (),
        )
    RM_changed_names = {
        RM_interface.name
        for RM_interface in RM_changed_interfaces
    }
    for RM_interface in RM_im_table.RM_IM_list():
        RM_has_connected_routes = any(
            RM_route.source == "connected"
            for RM_route in RM_table.RM_routes_for_interface(RM_interface.name)
        )
        if RM_interface.name not in RM_changed_names and RM_has_connected_routes:
            continue
        RM_sync_connected_routes_for_interface(
            RM_ctx.state,
            RM_table,
            RM_interface,
        )
    RM_sync_static_routes(
        RM_ctx.state,
        RM_im_table.RM_IM_list(),
        RM_table,
    )
    return RM_table


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
        "",
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
    RM_lines.append("")
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
