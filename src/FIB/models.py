from __future__ import annotations

import time
from dataclasses import dataclass, field
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
    flags: str = "U"
    installed_at: float = field(default_factory=time.monotonic, compare=False)


@dataclass(frozen=True)
class FIB_InstallRequest:
    destination: IPv4Network
    out_if_name: str
    out_if_index: int | None
    source_ip: str
    source_mac: str
    next_hop_ip: str = ""
    mtu: int | None = None
    flags: str = "U"
