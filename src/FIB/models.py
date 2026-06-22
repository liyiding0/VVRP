from __future__ import annotations

from dataclasses import dataclass

from src.DPlane.Windows.npcap import NpcapDevice
from src.IFNET.models import NetworkInterface
from src.RM import RMRoute


@dataclass(frozen=True)
class FIBEntry:
    route: RMRoute
    interface: NetworkInterface
    source_ip: str
    next_hop_ip: str
    device: NpcapDevice
