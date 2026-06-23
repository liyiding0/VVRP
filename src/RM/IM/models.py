from __future__ import annotations

from dataclasses import dataclass

from src.IFNET.models import InterfaceAddress


@dataclass(frozen=True)
class RM_IM_Interface:
    name: str
    ifnet_index: int
    kind: str
    is_up: bool
    mac_address: str
    mtu: int | None
    addresses: tuple[InterfaceAddress, ...] = ()
    os_id: str = ""
    os_aliases: tuple[str, ...] = ()

    def RM_IM_addresses_by_family(self, RM_IM_family: str) -> tuple[InterfaceAddress, ...]:
        return tuple(RM_IM_address for RM_IM_address in self.addresses if RM_IM_address.family == RM_IM_family)
