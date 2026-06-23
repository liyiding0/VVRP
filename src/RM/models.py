from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Literal

from src.IFNET.models import NetworkInterface
from src.RM.IM import RM_IM_Interface


RMRouteSource = Literal["connected", "static", "dynamic"]


@dataclass(frozen=True)
class RMRoute:
    destination: ipaddress.IPv4Network
    source: RMRouteSource
    interface: NetworkInterface
    source_ip: str
    next_hop: str | None = None
    preference: int = 0

    @property
    def prefix_length(self) -> int:
        return self.destination.prefixlen


def RM_route_interface_addresses_by_family(
    RM_interface: NetworkInterface | RM_IM_Interface,
    RM_family: str,
):
    if isinstance(RM_interface, RM_IM_Interface):
        return RM_interface.RM_IM_addresses_by_family(RM_family)
    return RM_interface.addresses_by_family(RM_family)
