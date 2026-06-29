from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


InterfaceKind = Literal["ethernet", "loopback", "null", "serial"]
AddressFamily = Literal["ipv4", "ipv6"]


@dataclass(frozen=True)
class InterfaceAddress:
    family: AddressFamily
    address: str
    prefix_length: int | None = None

    @property
    def display(self) -> str:
        if self.prefix_length is None:
            return self.address
        return f"{self.address}/{self.prefix_length}"


@dataclass(frozen=True)
class NetworkInterface:
    name: str
    ifnet_index: int
    index: int | None
    kind: InterfaceKind
    is_up: bool
    mac_address: str
    mtu: int | None
    speed_mbps: int | None
    addresses: tuple[InterfaceAddress, ...] = ()

    def addresses_by_family(self, family: AddressFamily) -> tuple[InterfaceAddress, ...]:
        return tuple(address for address in self.addresses if address.family == family)
