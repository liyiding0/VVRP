"""Forwarding Information Base module for VVRP."""

from .models import FIBEntry
from .table import FIB_resolve_forwarding

__all__ = [
    "FIBEntry",
    "FIB_resolve_forwarding",
]
