"""Interface network discovery and CCmd registrations for VVRP."""

from .commands import register_ifnet_commands
from .admin import InterfaceAdminProvider, InterfaceAdminResult, OsInterfaceAdminProvider
from .discovery import (
    InterfaceDiscoveryError,
    InterfaceProvider,
    PsutilInterfaceProvider,
    discover_interfaces,
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
    "OsInterfaceAdminProvider",
    "PsutilInterfaceProvider",
    "discover_interfaces",
    "register_ifnet_commands",
]
