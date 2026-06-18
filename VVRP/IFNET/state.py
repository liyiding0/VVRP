from __future__ import annotations

from dataclasses import replace
from typing import Any

from .models import InterfaceAddress, NetworkInterface


IFNET_ADMIN_DOWN_STATE_KEY = "ifnet.admin_down"
IFNET_INTERFACE_ADDRESSES_STATE_KEY = "ifnet.interface_addresses"


def admin_down_interfaces(state: dict[str, Any]) -> set[str]:
    value = state.setdefault(IFNET_ADMIN_DOWN_STATE_KEY, set())
    if not isinstance(value, set):
        value = set()
        state[IFNET_ADMIN_DOWN_STATE_KEY] = value
    return value


def is_admin_down(state: dict[str, Any], name: str) -> bool:
    return name in admin_down_interfaces(state)


def shutdown_interface(state: dict[str, Any], name: str) -> None:
    admin_down_interfaces(state).add(name)


def no_shutdown_interface(state: dict[str, Any], name: str) -> None:
    admin_down_interfaces(state).discard(name)


def set_interface_addresses(
    state: dict[str, Any],
    name: str,
    addresses: tuple[InterfaceAddress, ...],
) -> None:
    interface_addresses(state)[name] = tuple(addresses)


def interface_addresses(state: dict[str, Any]) -> dict[str, tuple[InterfaceAddress, ...]]:
    value = state.setdefault(IFNET_INTERFACE_ADDRESSES_STATE_KEY, {})
    if not isinstance(value, dict):
        value = {}
        state[IFNET_INTERFACE_ADDRESSES_STATE_KEY] = value
    return value


def addresses_for_interface(
    state: dict[str, Any],
    name: str,
) -> tuple[InterfaceAddress, ...]:
    value = interface_addresses(state).get(name, ())
    if not isinstance(value, tuple):
        value = tuple(value)
        interface_addresses(state)[name] = value
    return value


def apply_vvrp_interface_state(
    state: dict[str, Any],
    interface: NetworkInterface,
) -> NetworkInterface:
    return replace(interface, addresses=addresses_for_interface(state, interface.name))
