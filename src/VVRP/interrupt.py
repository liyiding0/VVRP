from __future__ import annotations

import threading


g_VVRP_INTERRUPT_EVENT_STATE_KEY = "vvrp.interrupt_event"


def VVRP_interrupt_event(VVRP_state: dict) -> threading.Event:
    VVRP_event = VVRP_state.get(g_VVRP_INTERRUPT_EVENT_STATE_KEY)
    if isinstance(VVRP_event, threading.Event):
        return VVRP_event
    VVRP_event = threading.Event()
    VVRP_state[g_VVRP_INTERRUPT_EVENT_STATE_KEY] = VVRP_event
    return VVRP_event


def VVRP_request_interrupt(VVRP_state: dict) -> None:
    VVRP_interrupt_event(VVRP_state).set()


def VVRP_clear_interrupt(VVRP_state: dict) -> None:
    VVRP_interrupt_event(VVRP_state).clear()


def VVRP_interrupt_requested(VVRP_state: dict) -> bool:
    return VVRP_interrupt_event(VVRP_state).is_set()
