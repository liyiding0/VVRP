from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass, field

from src.IFNET.state import IFNET_is_protocol_up
from src.RM.IM import RM_IM_Interface

from .models import RMRoute
from .rib import RM_RouteTable


g_RM_STATIC_ROUTE_STATE_KEY = "rm.static_routes"
g_RM_STATIC_ROUTE_RESOLUTION_CACHE_STATE_KEY = "rm.static_route_resolution_cache"
g_RM_STATIC_ROUTE_DEFAULT_PREFERENCE = 60


@dataclass(frozen=True)
class RM_StaticRouteConfig:
    destination: ipaddress.IPv4Network
    next_hop: str | None = None
    interface_name: str | None = None
    preference: int = g_RM_STATIC_ROUTE_DEFAULT_PREFERENCE
    preference_configured: bool = False
    tag: int | None = None
    description: str = ""
    permanent: bool = False
    no_advertise: bool = False
    configured_at: float = field(default_factory=time.monotonic, compare=False)

    @property
    def RM_identity(self) -> tuple[str, str, str]:
        return (
            str(self.destination),
            self.interface_name or "",
            self.next_hop or "",
        )


def RM_static_route_configs(RM_state: dict) -> tuple[RM_StaticRouteConfig, ...]:
    RM_store = RM_state.get(g_RM_STATIC_ROUTE_STATE_KEY)
    if not isinstance(RM_store, dict):
        return ()
    return tuple(RM_store[RM_key] for RM_key in sorted(RM_store))


def RM_set_static_route_config(RM_state: dict, RM_config: RM_StaticRouteConfig) -> None:
    RM_store = RM_state.get(g_RM_STATIC_ROUTE_STATE_KEY)
    if not isinstance(RM_store, dict):
        RM_store = {}
        RM_state[g_RM_STATIC_ROUTE_STATE_KEY] = RM_store
    RM_store[RM_config.RM_identity] = RM_config


def RM_remove_static_route_configs(
    RM_state: dict,
    RM_destination: ipaddress.IPv4Network,
    RM_interface_name: str | None = None,
    RM_next_hop: str | None = None,
) -> tuple[RM_StaticRouteConfig, ...]:
    RM_store = RM_state.get(g_RM_STATIC_ROUTE_STATE_KEY)
    if not isinstance(RM_store, dict):
        return ()
    RM_removed = []
    for RM_key, RM_config in tuple(RM_store.items()):
        if RM_config.destination != RM_destination:
            continue
        if RM_interface_name is not None and RM_config.interface_name != RM_interface_name:
            continue
        if RM_next_hop is not None and RM_config.next_hop != RM_next_hop:
            continue
        RM_removed.append(RM_store.pop(RM_key))
    RM_cache = RM_state.get(g_RM_STATIC_ROUTE_RESOLUTION_CACHE_STATE_KEY)
    if isinstance(RM_cache, dict):
        for RM_config in RM_removed:
            RM_cache.pop(RM_config.RM_identity, None)
    return tuple(RM_removed)


def RM_sync_static_routes(
    RM_state: dict,
    RM_interfaces: tuple[RM_IM_Interface, ...],
    RM_table: RM_RouteTable,
) -> tuple[RMRoute, ...]:
    RM_table.RM_replace_routes_for_source("static", ())
    RM_pending = list(RM_static_route_configs(RM_state))
    RM_resolved: list[RMRoute] = []
    RM_cache = RM_state.get(g_RM_STATIC_ROUTE_RESOLUTION_CACHE_STATE_KEY)
    if not isinstance(RM_cache, dict):
        RM_cache = {}
        RM_state[g_RM_STATIC_ROUTE_RESOLUTION_CACHE_STATE_KEY] = RM_cache
    RM_config_identities = {RM_config.RM_identity for RM_config in RM_pending}
    for RM_identity in tuple(RM_cache):
        if RM_identity not in RM_config_identities:
            RM_cache.pop(RM_identity, None)

    while RM_pending:
        RM_progress = False
        for RM_config in tuple(RM_pending):
            RM_route = RM_resolve_static_route(RM_state, RM_config, RM_interfaces, RM_table)
            if RM_route is None and RM_config.permanent:
                RM_route = RM_cache.get(RM_config.RM_identity)
            if RM_route is None:
                continue
            RM_table.RM_add_route(RM_route)
            RM_cache[RM_config.RM_identity] = RM_route
            RM_resolved.append(RM_route)
            RM_pending.remove(RM_config)
            RM_progress = True
        if not RM_progress:
            break

    return tuple(RM_resolved)


def RM_resolve_static_route(
    RM_state: dict,
    RM_config: RM_StaticRouteConfig,
    RM_interfaces: tuple[RM_IM_Interface, ...],
    RM_table: RM_RouteTable,
) -> RMRoute | None:
    RM_interface = None
    RM_source_ip = ""

    if RM_config.interface_name:
        RM_interface = RM_find_interface(RM_interfaces, RM_config.interface_name)
        if RM_interface is None or not IFNET_is_protocol_up(RM_state, RM_interface.name):
            return None
        RM_source_ip = RM_static_source_ip(RM_interface, RM_config.next_hop)
        if RM_interface.kind not in {"null", "serial"} and not RM_source_ip:
            return None
    elif RM_config.next_hop:
        RM_recursive_route = RM_table.RM_lookup(RM_config.next_hop)
        if RM_recursive_route is None:
            return None
        RM_interface = RM_recursive_route.interface
        RM_source_ip = RM_recursive_route.source_ip

    if RM_interface is None:
        return None

    return RMRoute(
        destination=RM_config.destination,
        source="static",
        interface=RM_interface,
        source_ip=RM_source_ip or "0.0.0.0",
        next_hop=RM_config.next_hop,
        preference=RM_config.preference,
        tag=RM_config.tag,
        description=RM_config.description,
        permanent=RM_config.permanent,
        no_advertise=RM_config.no_advertise,
    )


def RM_find_interface(
    RM_interfaces: tuple[RM_IM_Interface, ...],
    RM_name: str,
) -> RM_IM_Interface | None:
    RM_folded_name = RM_name.casefold()
    return next(
        (
            RM_interface
            for RM_interface in RM_interfaces
            if RM_interface.name.casefold() == RM_folded_name
        ),
        None,
    )


def RM_static_source_ip(
    RM_interface: RM_IM_Interface,
    RM_next_hop: str | None,
) -> str:
    RM_addresses = RM_interface.RM_IM_addresses_by_family("ipv4")
    if RM_next_hop:
        RM_next_hop_address = ipaddress.IPv4Address(RM_next_hop)
        for RM_address in RM_addresses:
            if RM_address.prefix_length is None:
                continue
            RM_network = ipaddress.IPv4Interface(
                f"{RM_address.address}/{RM_address.prefix_length}"
            ).network
            if RM_next_hop_address in RM_network:
                return RM_address.address
        if RM_interface.kind == "ethernet":
            return ""
    if RM_addresses:
        return RM_addresses[0].address
    return ""


def RM_static_route_config_line(RM_config: RM_StaticRouteConfig) -> str:
    RM_parts = [
        "ip",
        "route-static",
        str(RM_config.destination.network_address),
        str(RM_config.destination.prefixlen),
    ]
    if RM_config.interface_name:
        RM_parts.append(RM_config.interface_name)
    if RM_config.next_hop:
        RM_parts.append(RM_config.next_hop)
    if RM_config.preference_configured:
        RM_parts.extend(("preference", str(RM_config.preference)))
    if RM_config.tag is not None:
        RM_parts.extend(("tag", str(RM_config.tag)))
    if RM_config.permanent:
        RM_parts.append("permanent")
    if RM_config.no_advertise:
        RM_parts.append("no-advertise")
    if RM_config.description:
        RM_parts.extend(("description", RM_config.description))
    return " ".join(RM_parts)


def RM_static_route_config_key(RM_config: RM_StaticRouteConfig) -> str:
    RM_destination, RM_interface, RM_next_hop = RM_config.RM_identity
    return f"ip route-static:{RM_destination}:{RM_interface}:{RM_next_hop}"
