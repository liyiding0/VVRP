from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


g_VVRP_EVENT_BUS_STATE_KEY = "vvrp.event_bus"


@dataclass(frozen=True)
class VVRP_Event:
    source: str = ""


class VVRP_EventBus:
    def __init__(self) -> None:
        self._VVRP_handlers: dict[type, list[Callable[[Any], None]]] = {}

    def VVRP_subscribe(self, VVRP_event_type: type, VVRP_handler: Callable[[Any], None]) -> None:
        self._VVRP_handlers.setdefault(VVRP_event_type, []).append(VVRP_handler)

    def VVRP_unsubscribe(self, VVRP_event_type: type, VVRP_handler: Callable[[Any], None]) -> None:
        VVRP_handlers = self._VVRP_handlers.get(VVRP_event_type)
        if VVRP_handlers is None:
            return
        try:
            VVRP_handlers.remove(VVRP_handler)
        except ValueError:
            return

    def VVRP_publish(self, VVRP_event: Any) -> None:
        for VVRP_handler in tuple(self._VVRP_handlers.get(type(VVRP_event), ())):
            VVRP_handler(VVRP_event)


def VVRP_event_bus(VVRP_state: dict) -> VVRP_EventBus:
    VVRP_bus = VVRP_state.get(g_VVRP_EVENT_BUS_STATE_KEY)
    if isinstance(VVRP_bus, VVRP_EventBus):
        return VVRP_bus
    VVRP_bus = VVRP_EventBus()
    VVRP_state[g_VVRP_EVENT_BUS_STATE_KEY] = VVRP_bus
    return VVRP_bus
