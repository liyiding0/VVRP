from __future__ import annotations

from .models import NetworkInterface


g_IFNET_INLOOPBACK0_NAME = "InLoopBack0"


def IFNET_inloopback0_interface() -> NetworkInterface:
    return NetworkInterface(
        name=g_IFNET_INLOOPBACK0_NAME,
        ifnet_index=0,
        index=None,
        kind="loopback",
        is_up=True,
        mac_address="",
        mtu=1500,
        speed_mbps=None,
        addresses=(),
    )
