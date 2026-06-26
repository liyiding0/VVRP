from __future__ import annotations

from dataclasses import replace
from typing import Any

from .admin import InterfaceAdminProvider
from .discovery import InterfaceProvider, assign_ifnet_indices
from .models import NetworkInterface


IFNET_MANAGER_STATE_KEY = "ifnet.manager"


class IfnetManager:
    def __init__(
        self,
        provider: InterfaceProvider | None = None,
        admin_provider: InterfaceAdminProvider | None = None,
    ) -> None:
        self.provider = provider
        self.admin_provider = admin_provider
        self._interfaces_by_name: dict[str, NetworkInterface] = {}
        self._loaded = False

    def list_interfaces(self) -> tuple[NetworkInterface, ...]:
        self.ensure_loaded()
        return tuple(
            sorted(
                self._interfaces_by_name.values(),
                key=lambda interface: interface.ifnet_index,
            )
        )

    def get_interface(self, name: str) -> NetworkInterface | None:
        self.ensure_loaded()
        return self._interfaces_by_name.get(name)

    def ensure_loaded(self) -> None:
        if not self._loaded:
            self.refresh()

    def refresh(self) -> tuple[NetworkInterface, ...]:
        interfaces = assign_ifnet_indices(self.provider.list_interfaces()) if self.provider else ()
        self.merge(interfaces)
        self._loaded = True
        return interfaces

    def merge(self, interfaces: tuple[NetworkInterface, ...]) -> None:
        for interface in interfaces:
            existing = self._interfaces_by_name.get(interface.name)
            if existing is not None:
                interface = replace(
                    interface,
                    ifnet_index=existing.ifnet_index,
                    index=interface.index if interface.index is not None else existing.index,
                )
            self._interfaces_by_name[interface.name] = interface

        self._reindex()

    def _reindex(self) -> None:
        ordered = sorted(
            self._interfaces_by_name.values(),
            key=lambda interface: (
                0 if interface.kind == "loopback" else 1,
                interface.name.lower(),
            ),
        )
        self._interfaces_by_name = {
            interface.name: replace(interface, ifnet_index=ifnet_index)
            for ifnet_index, interface in enumerate(ordered, start=1)
        }


def get_ifnet_manager(
    state: dict[str, Any],
    provider: InterfaceProvider | None = None,
    admin_provider: InterfaceAdminProvider | None = None,
) -> IfnetManager:
    manager = state.get(IFNET_MANAGER_STATE_KEY)
    if isinstance(manager, IfnetManager):
        return manager

    manager = IfnetManager(provider=provider, admin_provider=admin_provider)
    state[IFNET_MANAGER_STATE_KEY] = manager
    return manager
