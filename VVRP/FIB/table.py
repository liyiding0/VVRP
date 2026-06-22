from __future__ import annotations

from VVRP.DPlane.Windows.npcap import NpcapDevice, find_npcap_device_for_interface
from VVRP.IFNET.models import NetworkInterface
from VVRP.RM import RM_lookup_route

from .models import FIBEntry


def FIB_resolve_forwarding(
    FIB_state: dict,
    FIB_host_interfaces: tuple[NetworkInterface, ...],
    FIB_npcap_devices: tuple[NpcapDevice, ...],
    FIB_destination_ip: str,
) -> FIBEntry | None:
    FIB_route = RM_lookup_route(FIB_state, FIB_host_interfaces, FIB_destination_ip)
    if FIB_route is None:
        return None
    FIB_device = find_npcap_device_for_interface(FIB_route.interface, FIB_npcap_devices)
    if FIB_device is None:
        return None
    return FIBEntry(
        route=FIB_route,
        interface=FIB_route.interface,
        source_ip=FIB_route.source_ip,
        next_hop_ip=FIB_route.next_hop or FIB_destination_ip,
        device=FIB_device,
    )
