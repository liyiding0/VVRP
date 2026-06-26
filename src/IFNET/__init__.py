"""Interface network discovery and CCmd registrations for VVRP."""

from .commands import register_ifnet_commands
from .admin import InterfaceAdminProvider, InterfaceAdminResult
from .discovery import (
    InterfaceDiscoveryError,
    InterfaceProvider,
    assign_ifnet_indices,
)
from .models import InterfaceAddress, InterfaceKind, NetworkInterface

__all__ = [
    "InterfaceAddress",
    "InterfaceAdminProvider",
    "InterfaceAdminResult",
    "InterfaceDiscoveryError",
    "InterfaceKind",
    "InterfaceProvider",
    "NetworkInterface",
    "assign_ifnet_indices",
    "register_ifnet_commands",
]
