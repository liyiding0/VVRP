from __future__ import annotations

from .Ethernet import can_shutdown_ethernet
from .Loopback import can_shutdown_loopback
from .models import NetworkInterface


def interface_can_shutdown(interface: NetworkInterface) -> bool:
    if interface.kind == "loopback":
        return can_shutdown_loopback(interface)
    if interface.kind == "null":
        return False
    if interface.kind == "ethernet":
        return can_shutdown_ethernet(interface)
    return True

