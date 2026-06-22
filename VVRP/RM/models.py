from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Literal

from VVRP.IFNET.models import NetworkInterface


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
