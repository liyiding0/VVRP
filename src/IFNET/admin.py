from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .models import NetworkInterface


@dataclass(frozen=True)
class InterfaceAdminResult:
    ok: bool
    message: str = ""


class InterfaceAdminProvider(Protocol):
    def shutdown(self, interface: NetworkInterface) -> InterfaceAdminResult:
        """Administratively shut down the OS interface."""

    def no_shutdown(self, interface: NetworkInterface) -> InterfaceAdminResult:
        """Administratively enable the OS interface."""


class OsInterfaceAdminProvider:
    def __init__(self, dplane_backend=None) -> None:
        from src.DPlane.interface_admin import DPlane_InterfaceAdminProvider

        self._provider = DPlane_InterfaceAdminProvider(dplane_backend)

    def shutdown(self, interface: NetworkInterface) -> InterfaceAdminResult:
        return self._provider.shutdown(interface)

    def no_shutdown(self, interface: NetworkInterface) -> InterfaceAdminResult:
        return self._provider.no_shutdown(interface)
