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
    def __init__(self) -> None:
        self._ethernet = None

    def shutdown(self, interface: NetworkInterface) -> InterfaceAdminResult:
        if interface.kind == "ethernet":
            return self._ethernet_provider().shutdown(interface)
        return InterfaceAdminResult(
            ok=False,
            message=f"% Unsupported interface type for shutdown: {interface.kind}",
        )

    def no_shutdown(self, interface: NetworkInterface) -> InterfaceAdminResult:
        if interface.kind == "ethernet":
            return self._ethernet_provider().no_shutdown(interface)
        return InterfaceAdminResult(
            ok=False,
            message=f"% Unsupported interface type for no shutdown: {interface.kind}",
        )

    def _ethernet_provider(self):
        if self._ethernet is None:
            from .Ethernet.admin import EthernetAdminProvider

            self._ethernet = EthernetAdminProvider()
        return self._ethernet
