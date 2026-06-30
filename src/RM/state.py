from __future__ import annotations

from collections.abc import MutableMapping
from typing import Any


g_RM_ROUTER_ID_STATE_KEY = "rm.router_id"


def RM_router_id(RM_state: MutableMapping[str, Any]) -> str | None:
    RM_value = RM_state.get(g_RM_ROUTER_ID_STATE_KEY)
    if not isinstance(RM_value, str) or not RM_value:
        return None
    return RM_value


def RM_set_router_id(RM_state: MutableMapping[str, Any], RM_router_id_value: str) -> None:
    RM_state[g_RM_ROUTER_ID_STATE_KEY] = RM_router_id_value


def RM_clear_router_id(RM_state: MutableMapping[str, Any]) -> None:
    RM_state.pop(g_RM_ROUTER_ID_STATE_KEY, None)
