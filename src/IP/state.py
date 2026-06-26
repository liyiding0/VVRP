from __future__ import annotations

from dataclasses import replace
from typing import Any

from src.IFNET.models import InterfaceAddress, NetworkInterface


g_IP_INTERFACE_ADDRESSES_STATE_KEY = "ip.interface_addresses"


def IP_set_interface_addresses(
    IP_state: dict[str, Any],
    IP_interface_name: str,
    IP_addresses: tuple[InterfaceAddress, ...],
) -> None:
    IP_interface_addresses(IP_state)[IP_interface_name] = tuple(IP_addresses)


def IP_interface_addresses(IP_state: dict[str, Any]) -> dict[str, tuple[InterfaceAddress, ...]]:
    IP_value = IP_state.setdefault(g_IP_INTERFACE_ADDRESSES_STATE_KEY, {})
    if not isinstance(IP_value, dict):
        IP_value = {}
        IP_state[g_IP_INTERFACE_ADDRESSES_STATE_KEY] = IP_value
    return IP_value


def IP_addresses_for_interface(
    IP_state: dict[str, Any],
    IP_interface_name: str,
) -> tuple[InterfaceAddress, ...]:
    IP_value = IP_interface_addresses(IP_state).get(IP_interface_name, ())
    if not isinstance(IP_value, tuple):
        IP_value = tuple(IP_value)
        IP_interface_addresses(IP_state)[IP_interface_name] = IP_value
    return IP_value


def IP_apply_interface_state(
    IP_state: dict[str, Any],
    IP_interface: NetworkInterface,
) -> NetworkInterface:
    return replace(
        IP_interface,
        addresses=IP_addresses_for_interface(IP_state, IP_interface.name),
    )
