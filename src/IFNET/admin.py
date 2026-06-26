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
        """Administratively shut down an injected interface."""

    def no_shutdown(self, interface: NetworkInterface) -> InterfaceAdminResult:
        """Administratively enable an injected interface."""
