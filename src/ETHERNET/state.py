from __future__ import annotations

from dataclasses import replace
from typing import Any

from src.IFNET.models import NetworkInterface


g_ETHERNET_INTERFACE_MACS_STATE_KEY = "ethernet.interface_macs"


def ETHERNET_interface_mac_addresses(
    ETHERNET_state: dict[str, Any],
) -> dict[str, str]:
    ETHERNET_value = ETHERNET_state.setdefault(
        g_ETHERNET_INTERFACE_MACS_STATE_KEY,
        {},
    )
    if not isinstance(ETHERNET_value, dict):
        ETHERNET_value = {}
        ETHERNET_state[g_ETHERNET_INTERFACE_MACS_STATE_KEY] = ETHERNET_value
    return ETHERNET_value


def ETHERNET_set_interface_mac_address(
    ETHERNET_state: dict[str, Any],
    ETHERNET_name: str,
    ETHERNET_mac_address: str,
) -> None:
    ETHERNET_interface_mac_addresses(ETHERNET_state)[ETHERNET_name] = ETHERNET_mac_address


def ETHERNET_remove_interface_mac_address(
    ETHERNET_state: dict[str, Any],
    ETHERNET_name: str,
) -> None:
    ETHERNET_interface_mac_addresses(ETHERNET_state).pop(ETHERNET_name, None)


def ETHERNET_mac_address_for_interface(
    ETHERNET_state: dict[str, Any],
    ETHERNET_name: str,
    ETHERNET_default: str,
) -> str:
    ETHERNET_value = ETHERNET_interface_mac_addresses(ETHERNET_state).get(ETHERNET_name)
    if isinstance(ETHERNET_value, str) and ETHERNET_value:
        return ETHERNET_value
    return ETHERNET_default


def ETHERNET_apply_interface_state(
    ETHERNET_state: dict[str, Any],
    ETHERNET_interface: NetworkInterface,
) -> NetworkInterface:
    return replace(
        ETHERNET_interface,
        mac_address=ETHERNET_mac_address_for_interface(
            ETHERNET_state,
            ETHERNET_interface.name,
            ETHERNET_interface.mac_address,
        ),
    )
