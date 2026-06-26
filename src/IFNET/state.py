from __future__ import annotations

from dataclasses import replace
from typing import Any

from .models import NetworkInterface


IFNET_ADMIN_DOWN_STATE_KEY = "ifnet.admin_down"
IFNET_INTERFACE_ADMINS_STATE_KEY = "ifnet.interface_admins"
IFNET_INTERFACE_PHYSICALS_STATE_KEY = "ifnet.interface_physicals"
IFNET_INTERFACE_MACS_STATE_KEY = "ifnet.interface_macs"
IFNET_INTERFACE_MTUS_STATE_KEY = "ifnet.interface_mtus"
IFNET_INTERFACE_PROTOCOLS_STATE_KEY = "ifnet.interface_protocols"


IFNET_STATUS_VALUES = {"up", "down"}


def IFNET_validate_status(IFNET_status: str, IFNET_kind: str) -> None:
    if IFNET_status not in IFNET_STATUS_VALUES:
        raise ValueError(f"unsupported IFNET {IFNET_kind} status: {IFNET_status}")


def admin_down_interfaces(state: dict[str, Any]) -> set[str]:
    value = state.setdefault(IFNET_ADMIN_DOWN_STATE_KEY, set())
    if not isinstance(value, set):
        value = set()
        state[IFNET_ADMIN_DOWN_STATE_KEY] = value
    return value


def is_admin_down(state: dict[str, Any], name: str) -> bool:
    return IFNET_admin_status_for_interface(state, name) == "down"


def shutdown_interface(state: dict[str, Any], name: str) -> None:
    admin_down_interfaces(state).add(name)
    IFNET_set_interface_admin_status(state, name, "down")


def no_shutdown_interface(state: dict[str, Any], name: str) -> None:
    admin_down_interfaces(state).discard(name)
    IFNET_set_interface_admin_status(state, name, "up")


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
    IFNET_validate_status(protocol_state, "protocol")
    IFNET_interface_protocols(state)[name] = protocol_state


def IFNET_set_interface_physical_state(
    state: dict[str, Any],
    name: str,
    physical_state: str,
) -> None:
    IFNET_validate_status(physical_state, "physical")
    IFNET_interface_physicals(state)[name] = physical_state


def IFNET_set_interface_admin_status(
    state: dict[str, Any],
    name: str,
    admin_status: str,
) -> None:
    IFNET_validate_status(admin_status, "admin")
    IFNET_interface_admins(state)[name] = admin_status


def IFNET_refresh_interface_status(
    state: dict[str, Any],
    interface: NetworkInterface,
    IFNET_recompute_protocol: bool = False,
) -> None:
    if interface.name not in IFNET_interface_admins(state):
        IFNET_set_interface_admin_status(
            state,
            interface.name,
            "down" if interface.name in admin_down_interfaces(state) else "up",
        )
    IFNET_set_interface_physical_state(
        state,
        interface.name,
        "up" if interface.is_up else "down",
    )
    if IFNET_recompute_protocol or interface.name not in IFNET_interface_protocols(state):
        IFNET_set_interface_protocol_state(
            state,
            interface.name,
            _IFNET_initial_protocol_state(state, interface),
        )


def _IFNET_initial_protocol_state(
    state: dict[str, Any],
    interface: NetworkInterface,
) -> str:
    if IFNET_admin_status_for_interface(state, interface.name) == "down":
        return "down"
    if not interface.is_up:
        return "down"
    if interface.kind in {"loopback", "null"}:
        return "up"
    if _IFNET_interface_has_ipv4_address(interface):
        return "up"
    return "down"


def _IFNET_interface_has_ipv4_address(interface: NetworkInterface) -> bool:
    addresses_by_family = getattr(interface, "addresses_by_family", None)
    if callable(addresses_by_family):
        return bool(addresses_by_family("ipv4"))
    im_addresses_by_family = getattr(interface, "RM_IM_addresses_by_family", None)
    if callable(im_addresses_by_family):
        return bool(im_addresses_by_family("ipv4"))
    return False


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


def IFNET_interface_admins(state: dict[str, Any]) -> dict[str, str]:
    value = state.setdefault(IFNET_INTERFACE_ADMINS_STATE_KEY, {})
    if not isinstance(value, dict):
        value = {}
        state[IFNET_INTERFACE_ADMINS_STATE_KEY] = value
    return value


def IFNET_interface_physicals(state: dict[str, Any]) -> dict[str, str]:
    value = state.setdefault(IFNET_INTERFACE_PHYSICALS_STATE_KEY, {})
    if not isinstance(value, dict):
        value = {}
        state[IFNET_INTERFACE_PHYSICALS_STATE_KEY] = value
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
    if value in IFNET_STATUS_VALUES:
        return value
    return "down"


def IFNET_physical_state_for_interface(
    state: dict[str, Any],
    name: str,
) -> str:
    value = IFNET_interface_physicals(state).get(name)
    if value in IFNET_STATUS_VALUES:
        return value
    return "down"


def IFNET_admin_status_for_interface(
    state: dict[str, Any],
    name: str,
) -> str:
    value = IFNET_interface_admins(state).get(name)
    if value in IFNET_STATUS_VALUES:
        return value
    if name in admin_down_interfaces(state):
        return "down"
    return "up"


def IFNET_is_physical_up(
    state: dict[str, Any],
    name: str,
) -> bool:
    return IFNET_physical_state_for_interface(state, name) == "up"


def IFNET_is_protocol_up(
    state: dict[str, Any],
    name: str,
) -> bool:
    return (
        IFNET_admin_status_for_interface(state, name) == "up"
        and IFNET_physical_state_for_interface(state, name) == "up"
        and IFNET_protocol_state_for_interface(state, name) == "up"
    )


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
