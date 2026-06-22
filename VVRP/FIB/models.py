from __future__ import annotations

from dataclasses import dataclass

from VVRP.DPlane.Windows.npcap import NpcapDevice
from VVRP.IFNET.models import NetworkInterface
from VVRP.RM import RMRoute


@dataclass(frozen=True)
class FIBEntry:
    route: RMRoute
    interface: NetworkInterface
    source_ip: str
    next_hop_ip: str
    device: NpcapDevice
