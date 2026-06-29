from __future__ import annotations

from dataclasses import dataclass

from src.FIB import FIBEntry
from src.IP.ipv4 import IP_parse_ipv4_packet


@dataclass(frozen=True)
class ETHERNET_Adjacency:
    ETHERNET_target_ip: str


def ETHERNET_resolve_adjacency(
    ETHERNET_packet: bytes,
    ETHERNET_route: FIBEntry,
) -> ETHERNET_Adjacency:
    if ETHERNET_route.next_hop_ip:
        return ETHERNET_Adjacency(ETHERNET_target_ip=ETHERNET_route.next_hop_ip)
    return ETHERNET_Adjacency(
        ETHERNET_target_ip=IP_parse_ipv4_packet(ETHERNET_packet).IP_destination,
    )
