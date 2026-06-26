from __future__ import annotations

from dataclasses import replace

from src.IP.state import IP_apply_interface_state

from .models import NetworkInterface
from .InLoopBack import IFNET_inloopback0_interface, g_IFNET_INLOOPBACK0_NAME
from .Null import IFNET_null0_interface
from .state import IFNET_refresh_interface_status, apply_vvrp_interface_state


def IFNET_interface_snapshots(
    IFNET_state: dict,
    IFNET_media_interfaces: tuple[NetworkInterface, ...],
) -> tuple[NetworkInterface, ...]:
    IFNET_snapshots: list[NetworkInterface] = []
    for IFNET_interface in IFNET_media_interfaces:
        IFNET_snapshot = IP_apply_interface_state(
            IFNET_state,
            apply_vvrp_interface_state(IFNET_state, IFNET_interface),
        )
        IFNET_refresh_interface_status(IFNET_state, IFNET_snapshot)
        IFNET_snapshots.append(IFNET_snapshot)
    IFNET_null0 = IFNET_null0_interface()
    IFNET_inloopback0 = IP_apply_interface_state(IFNET_state, IFNET_inloopback0_interface())
    IFNET_refresh_interface_status(IFNET_state, IFNET_null0)
    IFNET_refresh_interface_status(IFNET_state, IFNET_inloopback0)
    return assign_ifnet_indices((IFNET_null0, IFNET_inloopback0, *tuple(IFNET_snapshots)))


def IFNET_ethernet_interface_snapshots(
    IFNET_state: dict,
    IFNET_host_interfaces: tuple[NetworkInterface, ...],
) -> tuple[NetworkInterface, ...]:
    from src.ETHERNET.device import ETHERNET_installed_device_names

    IFNET_installed = ETHERNET_installed_device_names(IFNET_state)
    return IFNET_interface_snapshots(
        IFNET_state,
        tuple(
            IFNET_interface
            for IFNET_interface in IFNET_host_interfaces
            if IFNET_interface.name in IFNET_installed
        ),
    )


def IFNET_ifnet_index_map(
    IFNET_state: dict,
    IFNET_interfaces: tuple[NetworkInterface, ...],
) -> dict[str, int]:
    return {IFNET_interface.name: IFNET_interface.ifnet_index for IFNET_interface in IFNET_interfaces}


def IFNET_ethernet_ifnet_index_map(
    IFNET_state: dict,
    IFNET_host_interfaces: tuple[NetworkInterface, ...],
) -> dict[str, int]:
    return IFNET_ifnet_index_map(
        IFNET_state,
        IFNET_ethernet_interface_snapshots(IFNET_state, IFNET_host_interfaces),
    )


def assign_ifnet_indices(
    IFNET_interfaces: tuple[NetworkInterface, ...],
) -> tuple[NetworkInterface, ...]:
    IFNET_ordered = sorted(
        IFNET_interfaces,
        key=lambda IFNET_interface: (
            0 if IFNET_interface.kind == "null" else 1 if IFNET_interface.kind == "loopback" else 2,
            IFNET_interface.name.lower(),
        ),
    )
    IFNET_assigned: list[NetworkInterface] = []
    IFNET_next_index = 1
    for IFNET_interface in IFNET_ordered:
        if IFNET_interface.name == g_IFNET_INLOOPBACK0_NAME:
            IFNET_assigned.append(replace(IFNET_interface, ifnet_index=0))
            continue
        if IFNET_interface.kind == "null":
            IFNET_assigned.append(replace(IFNET_interface, ifnet_index=0xFFFF))
            continue
        IFNET_assigned.append(replace(IFNET_interface, ifnet_index=IFNET_next_index))
        IFNET_next_index += 1
    return tuple(IFNET_assigned)
