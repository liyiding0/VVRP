from __future__ import annotations

from typing import Protocol

from .models import NetworkInterface
from .interfaces import assign_ifnet_indices


class InterfaceDiscoveryError(RuntimeError):
    """Raised when an injected interface provider cannot run."""


class InterfaceProvider(Protocol):
    def list_interfaces(self) -> tuple[NetworkInterface, ...]:
        """Return interfaces already supplied to IFNET by the runtime."""
