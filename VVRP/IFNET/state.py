from __future__ import annotations

from typing import Any


IFNET_ADMIN_DOWN_STATE_KEY = "ifnet.admin_down"


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

