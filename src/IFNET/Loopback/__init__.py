"""Loopback interface discovery helpers for IFNET."""

from .discovery import is_loopback_interface
from .policy import can_shutdown_loopback

__all__ = ["can_shutdown_loopback", "is_loopback_interface"]
