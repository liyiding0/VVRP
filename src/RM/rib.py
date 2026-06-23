from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from .models import RMRoute


g_RM_ROUTE_TABLE_STATE_KEY = "rm.route_table"


@dataclass
class RM_RadixNode:
    RM_route: RMRoute | None = None
    RM_children: dict[int, "RM_RadixNode"] = field(default_factory=dict)


class RM_IPv4RadixTree:
    def __init__(self) -> None:
        self._RM_root = RM_RadixNode()

    def RM_insert(self, RM_route: RMRoute) -> None:
        RM_network = RM_route.destination
        RM_node = self._RM_root
        RM_address = int(RM_network.network_address)
        for RM_bit_index in range(RM_network.prefixlen):
            RM_bit = (RM_address >> (31 - RM_bit_index)) & 1
            RM_node = RM_node.RM_children.setdefault(RM_bit, RM_RadixNode())
        RM_node.RM_route = RM_route

    def RM_lookup(self, RM_address: str | ipaddress.IPv4Address) -> RMRoute | None:
        RM_ip = ipaddress.IPv4Address(RM_address)
        RM_value = int(RM_ip)
        RM_node = self._RM_root
        RM_best = RM_node.RM_route
        for RM_bit_index in range(32):
            RM_bit = (RM_value >> (31 - RM_bit_index)) & 1
            RM_node = RM_node.RM_children.get(RM_bit)
            if RM_node is None:
                break
            if RM_node.RM_route is not None:
                RM_best = RM_node.RM_route
        return RM_best


class RM_RouteTable:
    def __init__(self) -> None:
        self._RM_routes_by_key: dict[tuple, RMRoute] = {}
        self._RM_routes_by_prefix: dict[ipaddress.IPv4Network, list[RMRoute]] = {}
        self._RM_routes_by_interface: dict[str, set[tuple]] = {}
        self._RM_routes_by_source: dict[str, set[tuple]] = {}
        self._RM_active_by_prefix: dict[ipaddress.IPv4Network, RMRoute] = {}
        self._RM_ipv4_active_tree = RM_IPv4RadixTree()

    def RM_add_route(self, RM_route: RMRoute) -> None:
        RM_key = RM_route_key(RM_route)
        RM_old_route = self._RM_routes_by_key.get(RM_key)
        if RM_old_route is not None:
            self.RM_delete_route(RM_old_route)

        self._RM_routes_by_key[RM_key] = RM_route
        self._RM_routes_by_prefix.setdefault(RM_route.destination, []).append(RM_route)
        self._RM_routes_by_interface.setdefault(RM_route.interface.name, set()).add(RM_key)
        self._RM_routes_by_source.setdefault(RM_route.source, set()).add(RM_key)
        self._RM_rebuild_active_index()

    def RM_add_routes(self, RM_routes: tuple[RMRoute, ...]) -> None:
        for RM_route in RM_routes:
            RM_key = RM_route_key(RM_route)
            RM_old_route = self._RM_routes_by_key.get(RM_key)
            if RM_old_route is not None:
                self.RM_delete_route(RM_old_route, RM_rebuild=False)
            self._RM_routes_by_key[RM_key] = RM_route
            self._RM_routes_by_prefix.setdefault(RM_route.destination, []).append(RM_route)
            self._RM_routes_by_interface.setdefault(RM_route.interface.name, set()).add(RM_key)
            self._RM_routes_by_source.setdefault(RM_route.source, set()).add(RM_key)
        self._RM_rebuild_active_index()

    def RM_delete_route(self, RM_route: RMRoute, RM_rebuild: bool = True) -> None:
        RM_key = RM_route_key(RM_route)
        RM_existing = self._RM_routes_by_key.pop(RM_key, None)
        if RM_existing is None:
            return

        RM_prefix_routes = self._RM_routes_by_prefix.get(RM_existing.destination, [])
        self._RM_routes_by_prefix[RM_existing.destination] = [
            RM_candidate for RM_candidate in RM_prefix_routes if RM_route_key(RM_candidate) != RM_key
        ]
        if not self._RM_routes_by_prefix[RM_existing.destination]:
            self._RM_routes_by_prefix.pop(RM_existing.destination, None)

        self._RM_remove_index_key(self._RM_routes_by_interface, RM_existing.interface.name, RM_key)
        self._RM_remove_index_key(self._RM_routes_by_source, RM_existing.source, RM_key)
        if RM_rebuild:
            self._RM_rebuild_active_index()

    def RM_routes(self) -> tuple[RMRoute, ...]:
        return tuple(self._RM_routes_by_key[RM_key] for RM_key in sorted(self._RM_routes_by_key))

    def RM_active_routes(self) -> tuple[RMRoute, ...]:
        return tuple(
            self._RM_active_by_prefix[RM_prefix]
            for RM_prefix in sorted(
                self._RM_active_by_prefix,
                key=lambda RM_prefix: (int(RM_prefix.network_address), RM_prefix.prefixlen),
            )
        )

    def RM_routes_for_prefix(self, RM_prefix: ipaddress.IPv4Network) -> tuple[RMRoute, ...]:
        return tuple(self._RM_routes_by_prefix.get(RM_prefix, ()))

    def RM_routes_for_interface(self, RM_interface_name: str) -> tuple[RMRoute, ...]:
        return self._RM_routes_from_keys(self._RM_routes_by_interface.get(RM_interface_name, set()))

    def RM_routes_for_source(self, RM_source: str) -> tuple[RMRoute, ...]:
        return self._RM_routes_from_keys(self._RM_routes_by_source.get(RM_source, set()))

    def RM_replace_routes_for_source(self, RM_source: str, RM_routes: tuple[RMRoute, ...]) -> None:
        for RM_route in self.RM_routes_for_source(RM_source):
            self.RM_delete_route(RM_route, RM_rebuild=False)
        self.RM_add_routes(RM_routes)

    def RM_replace_routes_for_interface_source(
        self,
        RM_interface_name: str,
        RM_source: str,
        RM_routes: tuple[RMRoute, ...],
    ) -> None:
        for RM_route in tuple(self.RM_routes_for_interface(RM_interface_name)):
            if RM_route.source == RM_source:
                self.RM_delete_route(RM_route, RM_rebuild=False)
        self.RM_add_routes(RM_routes)

    def RM_lookup(self, RM_destination_ip: str) -> RMRoute | None:
        return self._RM_ipv4_active_tree.RM_lookup(RM_destination_ip)

    def _RM_routes_from_keys(self, RM_keys: set[tuple]) -> tuple[RMRoute, ...]:
        return tuple(self._RM_routes_by_key[RM_key] for RM_key in sorted(RM_keys) if RM_key in self._RM_routes_by_key)

    def _RM_rebuild_active_index(self) -> None:
        self._RM_active_by_prefix = {}
        self._RM_ipv4_active_tree = RM_IPv4RadixTree()
        for RM_prefix, RM_routes in self._RM_routes_by_prefix.items():
            RM_active_route = RM_select_active_route(tuple(RM_routes))
            if RM_active_route is None:
                continue
            self._RM_active_by_prefix[RM_prefix] = RM_active_route
            self._RM_ipv4_active_tree.RM_insert(RM_active_route)

    @staticmethod
    def _RM_remove_index_key(RM_index: dict[str, set[tuple]], RM_name: str, RM_key: tuple) -> None:
        RM_keys = RM_index.get(RM_name)
        if RM_keys is None:
            return
        RM_keys.discard(RM_key)
        if not RM_keys:
            RM_index.pop(RM_name, None)


def RM_route_key(RM_route: RMRoute) -> tuple:
    return (
        str(RM_route.destination),
        RM_route.source,
        RM_route.interface.name,
        RM_route.source_ip,
        RM_route.next_hop or "",
        RM_route.preference,
    )


def RM_select_active_route(RM_routes: tuple[RMRoute, ...]) -> RMRoute | None:
    if not RM_routes:
        return None
    return min(
        RM_routes,
        key=lambda RM_route: (
            RM_route.preference,
            RM_source_rank(RM_route.source),
            RM_route.interface.name,
            RM_route.next_hop or "",
            RM_route.source_ip,
        ),
    )


def RM_source_rank(RM_source: str) -> int:
    RM_ranks = {
        "connected": 0,
        "static": 1,
        "dynamic": 2,
    }
    return RM_ranks.get(RM_source, 100)


def RM_route_table_from_routes(RM_routes: tuple[RMRoute, ...]) -> RM_RouteTable:
    RM_table = RM_RouteTable()
    RM_table.RM_add_routes(RM_routes)
    return RM_table


def RM_route_table(RM_state: dict) -> RM_RouteTable:
    RM_table = RM_state.get(g_RM_ROUTE_TABLE_STATE_KEY)
    if isinstance(RM_table, RM_RouteTable):
        return RM_table
    RM_table = RM_RouteTable()
    RM_state[g_RM_ROUTE_TABLE_STATE_KEY] = RM_table
    return RM_table
