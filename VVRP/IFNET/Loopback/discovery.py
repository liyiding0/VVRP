from __future__ import annotations

import ipaddress

from VVRP.IFNET.models import InterfaceAddress


LOOPBACK_NAMES = {"lo", "loopback", "loopback_0"}


def is_loopback_interface(
    name: str,
    addresses: tuple[InterfaceAddress, ...],
) -> bool:
    normalized = name.lower()
    if normalized in LOOPBACK_NAMES or "loopback" in normalized:
        return True

    return bool(addresses) and all(
        _address_is_loopback(address.address) for address in addresses
    )


def _address_is_loopback(address: str) -> bool:
    try:
        return ipaddress.ip_address(address.split("%", 1)[0]).is_loopback
    except ValueError:
        return False
