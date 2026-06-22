from __future__ import annotations

from src.IFNET.models import NetworkInterface


def can_shutdown_ethernet(interface: NetworkInterface) -> bool:
    return True

