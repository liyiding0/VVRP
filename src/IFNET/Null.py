from __future__ import annotations

from .models import NetworkInterface


g_IFNET_NULL0_NAME = "NULL0"


def IFNET_null0_interface() -> NetworkInterface:
    return NetworkInterface(
        name=g_IFNET_NULL0_NAME,
        ifnet_index=0,
        index=None,
        kind="null",
        is_up=True,
        mac_address="",
        mtu=1500,
        speed_mbps=None,
        addresses=(),
    )
