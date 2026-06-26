from __future__ import annotations

from dataclasses import replace

from src.ETHERNET.device import ETHERNET_installed_device_names
from src.IP.state import IP_apply_interface_state

from .models import NetworkInterface
from .state import apply_vvrp_interface_state


def IFNET_interface_snapshots(
    IFNET_state: dict,
    IFNET_media_interfaces: tuple[NetworkInterface, ...],
) -> tuple[NetworkInterface, ...]:
    return assign_ifnet_indices(
        tuple(
            IP_apply_interface_state(
                IFNET_state,
                apply_vvrp_interface_state(IFNET_state, IFNET_interface),
            )
            for IFNET_interface in IFNET_media_interfaces
        )
    )


def IFNET_ethernet_interface_snapshots(
    IFNET_state: dict,
    IFNET_host_interfaces: tuple[NetworkInterface, ...],
) -> tuple[NetworkInterface, ...]:
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
            0 if IFNET_interface.kind == "loopback" else 1,
            IFNET_interface.name.lower(),
        ),
    )
    return tuple(
        replace(IFNET_interface, ifnet_index=IFNET_index)
        for IFNET_index, IFNET_interface in enumerate(IFNET_ordered, start=1)
    )
