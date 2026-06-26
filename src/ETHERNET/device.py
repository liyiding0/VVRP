from __future__ import annotations


g_ETHERNET_DEVICE_STATE_KEY = "ethernet.devices"


def ETHERNET_installed_device_names(ETHERNET_state: dict) -> frozenset[str]:
    return frozenset(_ETHERNET_device_state(ETHERNET_state)["active"])


def ETHERNET_pending_device_names(ETHERNET_state: dict) -> frozenset[str]:
    ETHERNET_state_map = _ETHERNET_device_state(ETHERNET_state)
    ETHERNET_pending = ETHERNET_state_map.get("pending")
    if isinstance(ETHERNET_pending, set):
        return frozenset(ETHERNET_pending)
    return frozenset(ETHERNET_state_map["active"])


def ETHERNET_stage_device_install(ETHERNET_state: dict, ETHERNET_name: str) -> None:
    ETHERNET_pending_set(ETHERNET_state).add(ETHERNET_name)


def ETHERNET_stage_device_uninstall(ETHERNET_state: dict, ETHERNET_name: str) -> None:
    ETHERNET_pending_set(ETHERNET_state).discard(ETHERNET_name)


def ETHERNET_commit_device_changes(ETHERNET_state: dict) -> None:
    ETHERNET_state_map = _ETHERNET_device_state(ETHERNET_state)
    ETHERNET_pending = ETHERNET_state_map.get("pending")
    if isinstance(ETHERNET_pending, set):
        ETHERNET_state_map["active"] = set(ETHERNET_pending)
    ETHERNET_state_map["pending"] = None


def ETHERNET_has_pending_device_changes(
    ETHERNET_state: dict,
    ETHERNET_active: frozenset[str] | None = None,
    ETHERNET_pending: frozenset[str] | None = None,
) -> bool:
    ETHERNET_state_map = ETHERNET_state.get(g_ETHERNET_DEVICE_STATE_KEY)
    if not isinstance(ETHERNET_state_map, dict):
        return False
    ETHERNET_active = ETHERNET_active or ETHERNET_installed_device_names(ETHERNET_state)
    ETHERNET_pending = ETHERNET_pending or ETHERNET_pending_device_names(ETHERNET_state)
    return ETHERNET_state_map.get("pending") is not None and ETHERNET_pending != ETHERNET_active


def ETHERNET_pending_set(ETHERNET_state: dict) -> set[str]:
    ETHERNET_state_map = _ETHERNET_device_state(ETHERNET_state)
    ETHERNET_pending = ETHERNET_state_map.get("pending")
    if isinstance(ETHERNET_pending, set):
        return ETHERNET_pending
    ETHERNET_pending = set(ETHERNET_state_map["active"])
    ETHERNET_state_map["pending"] = ETHERNET_pending
    return ETHERNET_pending


def _ETHERNET_device_state(ETHERNET_state: dict) -> dict:
    ETHERNET_state_map = ETHERNET_state.get(g_ETHERNET_DEVICE_STATE_KEY)
    if isinstance(ETHERNET_state_map, dict):
        ETHERNET_active = ETHERNET_state_map.get("active")
        if not isinstance(ETHERNET_active, set):
            ETHERNET_state_map["active"] = set(ETHERNET_active or ())
        return ETHERNET_state_map

    ETHERNET_state_map = {"active": set(), "pending": None}
    ETHERNET_state[g_ETHERNET_DEVICE_STATE_KEY] = ETHERNET_state_map
    return ETHERNET_state_map
