from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Network


@dataclass(frozen=True)
class FIBEntry:
    destination: IPv4Network
    out_if_name: str
    out_if_index: int | None
    source_ip: str
    source_mac: str
    next_hop_ip: str
    mtu: int | None = None
    flags: str = "D"


@dataclass(frozen=True)
class FIB_InstallRequest:
    destination: IPv4Network
    out_if_name: str
    out_if_index: int | None
    source_ip: str
    source_mac: str
    next_hop_ip: str = ""
    mtu: int | None = None
    flags: str = "D"
