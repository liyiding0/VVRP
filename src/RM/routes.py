from __future__ import annotations

import ipaddress

from src.IFNET.models import NetworkInterface
from src.IFNET.state import IFNET_is_protocol_up, IFNET_refresh_interface_status, apply_vvrp_interface_state
from src.RM.IM import (
    RM_IM_Interface,
    RM_IM_InterfaceAddressAdded,
    RM_IM_InterfaceChanged,
    RM_IM_InterfaceDeleted,
    RM_IM_InterfaceTable,
    RM_IM_interface_table_from_ifnet,
)
from src.events import VVRP_EventBus

from .models import RMRoute, RM_route_interface_addresses_by_family
from .rib import RM_RouteTable, RM_route_table, RM_route_table_from_routes


def RM_connected_routes(
    RM_state: dict,
    RM_host_interfaces: tuple[NetworkInterface, ...],
) -> tuple[RMRoute, ...]:
    RM_interfaces = tuple(
        apply_vvrp_interface_state(RM_state, RM_interface)
        for RM_interface in RM_host_interfaces
    )
    RM_interface_table = RM_IM_interface_table_from_ifnet(RM_interfaces)
    return RM_connected_routes_from_im(RM_state, RM_interface_table.RM_IM_list())


def RM_connected_routes_from_im(
    RM_state: dict,
    RM_interfaces: tuple[NetworkInterface | RM_IM_Interface, ...],
) -> tuple[RMRoute, ...]:
    RM_routes: list[RMRoute] = []
    for RM_interface in RM_interfaces:
        IFNET_refresh_interface_status(
            RM_state,
            RM_interface,
            IFNET_recompute_protocol=True,
        )
        if not IFNET_is_protocol_up(RM_state, RM_interface.name):
            continue
        for RM_address in RM_route_interface_addresses_by_family(RM_interface, "ipv4"):
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
    RM_existing_table = RM_state.get("rm.route_table")
    if isinstance(RM_existing_table, RM_RouteTable):
        return RM_existing_table.RM_lookup(RM_destination_ip)
    RM_route_table = RM_route_table_from_routes(
        RM_connected_routes(RM_state, RM_host_interfaces)
    )
    return RM_route_table.RM_lookup(RM_destination_ip)


def RM_route_table_from_im(
    RM_state: dict,
    RM_interfaces: tuple[NetworkInterface | RM_IM_Interface, ...],
) -> RM_RouteTable:
    return RM_route_table_from_routes(RM_connected_routes_from_im(RM_state, RM_interfaces))


def RM_sync_connected_routes_for_interface(
    RM_state: dict,
    RM_table: RM_RouteTable,
    RM_interface: NetworkInterface | RM_IM_Interface,
) -> None:
    RM_table.RM_replace_routes_for_interface_source(
        RM_interface.name,
        "connected",
        RM_connected_routes_from_im(RM_state, (RM_interface,)),
    )


def RM_sync_connected_routes_from_im_table(
    RM_state: dict,
    RM_im_table: RM_IM_InterfaceTable,
    RM_table: RM_RouteTable,
) -> None:
    RM_table.RM_replace_routes_for_source(
        "connected",
        RM_connected_routes_from_im(RM_state, RM_im_table.RM_IM_list()),
    )


def RM_register_route_event_handlers(
    RM_bus: VVRP_EventBus,
    RM_state: dict,
    RM_im_table: RM_IM_InterfaceTable,
    RM_table: RM_RouteTable | None = None,
    **RM_ignored_legacy_kwargs,
) -> RM_RouteTable:
    RM_active_table = RM_table or RM_route_table(RM_state)

    def RM_handle_interface_changed(RM_event: RM_IM_InterfaceChanged) -> None:
        RM_interface = RM_im_table.RM_IM_get(RM_event.interface.name)
        if RM_interface is None:
            return
        RM_sync_connected_routes_for_interface(RM_state, RM_active_table, RM_interface)

    def RM_handle_interface_deleted(RM_event: RM_IM_InterfaceDeleted) -> None:
        RM_active_table.RM_replace_routes_for_interface_source(RM_event.name, "connected", ())

    def RM_handle_address_added(RM_event: RM_IM_InterfaceAddressAdded) -> None:
        RM_interface = RM_im_table.RM_IM_get(RM_event.name)
        if RM_interface is None:
            return
        RM_sync_connected_routes_for_interface(RM_state, RM_active_table, RM_interface)

    RM_bus.VVRP_subscribe(RM_IM_InterfaceChanged, RM_handle_interface_changed)
    RM_bus.VVRP_subscribe(RM_IM_InterfaceDeleted, RM_handle_interface_deleted)
    RM_bus.VVRP_subscribe(RM_IM_InterfaceAddressAdded, RM_handle_address_added)
    return RM_active_table
