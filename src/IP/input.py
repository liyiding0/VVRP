from __future__ import annotations

from collections.abc import Iterable

from src.IFNET.models import NetworkInterface

from .ICMP.input import ICMP_handle_ipv4_packet
from .ipv4 import IP_parse_ipv4_packet


def IP_handle_local_ipv4_packet(
    IP_state: dict,
    IP_interfaces: Iterable[NetworkInterface],
    IP_packet: bytes,
) -> bytes | None:
    try:
        IP_parsed = IP_parse_ipv4_packet(IP_packet)
    except ValueError:
        return None
    IP_interface = _IP_local_destination_interface(
        IP_interfaces,
        IP_parsed.IP_destination,
    )
    if IP_interface is None:
        return None
    if IP_parsed.IP_protocol == 1:
        return ICMP_handle_ipv4_packet(IP_interface, IP_packet, IP_state)
    return None


def _IP_local_destination_interface(
    IP_interfaces: Iterable[NetworkInterface],
    IP_destination: str,
) -> NetworkInterface | None:
    for IP_interface in IP_interfaces:
        if any(
            IP_address.address == IP_destination
            for IP_address in IP_interface.addresses_by_family("ipv4")
        ):
            return IP_interface
    return None
