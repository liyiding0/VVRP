"""Ethernet interface discovery helpers for IFNET."""

from .discovery import is_ethernet_interface
from .policy import can_shutdown_ethernet

__all__ = [
    "can_shutdown_ethernet",
    "is_ethernet_interface",
]
