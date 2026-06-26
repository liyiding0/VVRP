from __future__ import annotations

from dataclasses import replace
from typing import Any

from .models import NetworkInterface


IFNET_ADMIN_DOWN_STATE_KEY = "ifnet.admin_down"
IFNET_INTERFACE_MACS_STATE_KEY = "ifnet.interface_macs"
IFNET_INTERFACE_MTUS_STATE_KEY = "ifnet.interface_mtus"
IFNET_INTERFACE_PROTOCOLS_STATE_KEY = "ifnet.interface_protocols"


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


def set_interface_mac_address(
    state: dict[str, Any],
    name: str,
    mac_address: str,
) -> None:
    interface_mac_addresses(state)[name] = mac_address


def remove_interface_mac_address(
    state: dict[str, Any],
    name: str,
) -> None:
    interface_mac_addresses(state).pop(name, None)


def IFNET_set_interface_mtu(
    state: dict[str, Any],
    name: str,
    mtu: int,
) -> None:
    IFNET_interface_mtus(state)[name] = int(mtu)


def IFNET_remove_interface_mtu(
    state: dict[str, Any],
    name: str,
) -> None:
    IFNET_interface_mtus(state).pop(name, None)


def IFNET_set_interface_protocol_state(
    state: dict[str, Any],
    name: str,
    protocol_state: str,
) -> None:
    if protocol_state not in {"up", "down"}:
        raise ValueError(f"unsupported IFNET protocol state: {protocol_state}")
    IFNET_interface_protocols(state)[name] = protocol_state


def interface_mac_addresses(state: dict[str, Any]) -> dict[str, str]:
    value = state.setdefault(IFNET_INTERFACE_MACS_STATE_KEY, {})
    if not isinstance(value, dict):
        value = {}
        state[IFNET_INTERFACE_MACS_STATE_KEY] = value
    return value


def IFNET_interface_mtus(state: dict[str, Any]) -> dict[str, int]:
    value = state.setdefault(IFNET_INTERFACE_MTUS_STATE_KEY, {})
    if not isinstance(value, dict):
        value = {}
        state[IFNET_INTERFACE_MTUS_STATE_KEY] = value
    return value


def IFNET_interface_protocols(state: dict[str, Any]) -> dict[str, str]:
    value = state.setdefault(IFNET_INTERFACE_PROTOCOLS_STATE_KEY, {})
    if not isinstance(value, dict):
        value = {}
        state[IFNET_INTERFACE_PROTOCOLS_STATE_KEY] = value
    return value


def IFNET_protocol_state_for_interface(
    state: dict[str, Any],
    name: str,
) -> str:
    value = IFNET_interface_protocols(state).get(name)
    if value in {"up", "down"}:
        return value
    return "down"


def mac_address_for_interface(
    state: dict[str, Any],
    name: str,
    default: str,
) -> str:
    value = interface_mac_addresses(state).get(name)
    if isinstance(value, str) and value:
        return value
    return default


def IFNET_mtu_for_interface(
    state: dict[str, Any],
    name: str,
    default: int | None,
) -> int | None:
    value = IFNET_interface_mtus(state).get(name)
    if isinstance(value, int):
        return value
    return default


def apply_vvrp_interface_state(
    state: dict[str, Any],
    interface: NetworkInterface,
) -> NetworkInterface:
    return replace(
        interface,
        mac_address=mac_address_for_interface(state, interface.name, interface.mac_address),
        mtu=IFNET_mtu_for_interface(state, interface.name, interface.mtu),
    )
