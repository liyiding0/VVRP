from __future__ import annotations

import ipaddress

from src.IFNET.imports import imported_interfaces
from src.IFNET.models import NetworkInterface
from src.IFNET.state import is_admin_down

from .models import RMRoute


def RM_connected_routes(
    RM_state: dict,
    RM_host_interfaces: tuple[NetworkInterface, ...],
) -> tuple[RMRoute, ...]:
    RM_routes: list[RMRoute] = []
    for RM_interface in imported_interfaces(RM_state, RM_host_interfaces):
        if not RM_interface.is_up or is_admin_down(RM_state, RM_interface.name):
            continue
        for RM_address in RM_interface.addresses_by_family("ipv4"):
            if RM_address.prefix_length is None:
                continue
            RM_network = ipaddress.IPv4Interface(
                f"{RM_address.address}/{RM_address.prefix_length}"
            ).network
            RM_routes.append(
                RMRoute(
                    destination=RM_network,
                    source="connected",
                    interface=RM_interface,
                    source_ip=RM_address.address,
                    preference=0,
                )
            )
    return tuple(RM_routes)


def RM_lookup_route(
    RM_state: dict,
    RM_host_interfaces: tuple[NetworkInterface, ...],
    RM_destination_ip: str,
) -> RMRoute | None:
    RM_destination = ipaddress.IPv4Address(RM_destination_ip)
    RM_candidates = tuple(
        RM_route
        for RM_route in RM_connected_routes(RM_state, RM_host_interfaces)
        if RM_destination in RM_route.destination
    )
    if not RM_candidates:
        return None
    return max(
        RM_candidates,
        key=lambda RM_route: (RM_route.prefix_length, -RM_route.preference),
    )
