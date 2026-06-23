from __future__ import annotations

from typing import Protocol

from .models import NetworkInterface


class InterfaceDiscoveryError(RuntimeError):
    """Raised when interface discovery cannot run."""


class InterfaceProvider(Protocol):
    def list_interfaces(self) -> tuple[NetworkInterface, ...]:
        """Return VVRP-visible kernel interfaces."""


class PsutilInterfaceProvider:
    def __init__(self) -> None:
        from src.DPlane.interface_discovery import PsutilInterfaceProvider as DPlane_PsutilInterfaceProvider

        self._IFNET_provider = DPlane_PsutilInterfaceProvider()

    def list_interfaces(self) -> tuple[NetworkInterface, ...]:
        try:
            return self._IFNET_provider.list_interfaces()
        except Exception as IFNET_exc:
            raise InterfaceDiscoveryError(str(IFNET_exc)) from IFNET_exc


def discover_interfaces(
    provider: InterfaceProvider | None = None,
) -> tuple[NetworkInterface, ...]:
    from src.DPlane.interface_discovery import assign_ifnet_indices

    return assign_ifnet_indices((provider or PsutilInterfaceProvider()).list_interfaces())


def assign_ifnet_indices(
    interfaces: tuple[NetworkInterface, ...],
) -> tuple[NetworkInterface, ...]:
    from src.DPlane.interface_discovery import assign_ifnet_indices as DPlane_assign_ifnet_indices

    return DPlane_assign_ifnet_indices(interfaces)


def _interface_index(name: str, mac_address: str = "", index_map=None) -> int | None:
    from src.DPlane.interface_discovery import _interface_index as DPlane_interface_index

    return DPlane_interface_index(name, mac_address, index_map)


def _interface_index_map(psutil, raw_addresses) -> dict[str, int]:
    from src.DPlane.interface_discovery import _interface_index_map as DPlane_interface_index_map

    return DPlane_interface_index_map(psutil, raw_addresses)


def _interface_metadata_map(psutil, raw_addresses):
    from src.DPlane.interface_discovery import _interface_metadata_map as DPlane_interface_metadata_map

    return DPlane_interface_metadata_map(psutil, raw_addresses)
