from __future__ import annotations

from dataclasses import replace

from .models import NetworkInterface
from .state import apply_vvrp_interface_state


IFNET_IMPORT_STATE_KEY = "ifnet.imports"


def imported_interface_names(state: dict) -> frozenset[str]:
    return frozenset(_import_state(state)["active"])


def pending_import_names(state: dict) -> frozenset[str]:
    import_state = _import_state(state)
    pending = import_state.get("pending")
    if isinstance(pending, set):
        return frozenset(pending)
    return frozenset(import_state["active"])


def stage_import_interface(state: dict, name: str) -> None:
    pending = _pending_set(state)
    pending.add(name)


def stage_unimport_interface(state: dict, name: str) -> None:
    pending = _pending_set(state)
    pending.discard(name)


def commit_imports(state: dict) -> None:
    import_state = _import_state(state)
    pending = import_state.get("pending")
    if isinstance(pending, set):
        import_state["active"] = set(pending)
    import_state["pending"] = None


def imported_interfaces(
    state: dict,
    host_interfaces: tuple[NetworkInterface, ...],
) -> tuple[NetworkInterface, ...]:
    imported = imported_interface_names(state)
    return assign_imported_ifnet_indices(
        tuple(
            apply_vvrp_interface_state(state, interface)
            for interface in host_interfaces
            if interface.name in imported
        )
    )


def imported_ifnet_index_map(
    state: dict,
    host_interfaces: tuple[NetworkInterface, ...],
) -> dict[str, int]:
    return {
        interface.name: interface.ifnet_index
        for interface in imported_interfaces(state, host_interfaces)
    }


def assign_imported_ifnet_indices(
    interfaces: tuple[NetworkInterface, ...],
) -> tuple[NetworkInterface, ...]:
    ordered = sorted(
        interfaces,
        key=lambda interface: (
            0 if interface.kind == "loopback" else 1,
            interface.name.lower(),
        ),
    )
    return tuple(
        replace(interface, ifnet_index=ifnet_index)
        for ifnet_index, interface in enumerate(ordered, start=1)
    )


def _pending_set(state: dict) -> set[str]:
    import_state = _import_state(state)
    pending = import_state.get("pending")
    if isinstance(pending, set):
        return pending
    pending = set(import_state["active"])
    import_state["pending"] = pending
    return pending


def _import_state(state: dict) -> dict:
    import_state = state.get(IFNET_IMPORT_STATE_KEY)
    if isinstance(import_state, dict):
        active = import_state.get("active")
        if not isinstance(active, set):
            import_state["active"] = set(active or ())
        return import_state

    import_state = {"active": set(), "pending": None}
    state[IFNET_IMPORT_STATE_KEY] = import_state
    return import_state
