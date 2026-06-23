from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Network
from typing import Literal, Protocol

from src.ETHERNET.port import RawEthernetPort
from src.IFNET.models import NetworkInterface


DPlane_PlatformKind = Literal["windows", "linux", "openwrt", "unsupported"]


@dataclass(frozen=True)
class DPlane_PlatformInfo:
    kind: DPlane_PlatformKind
    system: str
    release: str = ""
    description: str = ""


@dataclass(frozen=True)
class DPlane_Result:
    ok: bool
    message: str = ""


@dataclass(frozen=True)
class DPlane_PacketDevice:
    name: str
    description: str = ""
    backend: str = ""


@dataclass(frozen=True)
class DPlane_ForwardingEntry:
    destination: IPv4Network
    interface_name: str
    source_ip: str
    next_hop_ip: str
    device_name: str


class DPlane_Backend(Protocol):
    @property
    def DPlane_platform(self) -> DPlane_PlatformInfo:
        """Return the backend platform identity."""

    def DPlane_list_host_interfaces(self) -> tuple[NetworkInterface, ...]:
        """Return kernel interfaces visible to VVRP."""

    def DPlane_list_packet_devices(self) -> tuple[DPlane_PacketDevice, ...]:
        """Return packet I/O devices exposed by this backend."""

    def DPlane_find_packet_device(
        self,
        DPlane_interface: NetworkInterface,
        DPlane_devices: tuple[DPlane_PacketDevice, ...] | None = None,
    ) -> DPlane_PacketDevice | None:
        """Find the packet device that can carry frames for a kernel interface."""

    def DPlane_open_packet_port(self, DPlane_device: DPlane_PacketDevice) -> RawEthernetPort:
        """Open a raw Ethernet port for the packet device."""

    def DPlane_set_interface_enabled(
        self,
        DPlane_interface: NetworkInterface,
        DPlane_enabled: bool,
    ) -> DPlane_Result:
        """Set kernel interface administrative state."""

    def DPlane_install_forwarding_entry(
        self,
        DPlane_entry: DPlane_ForwardingEntry,
    ) -> DPlane_Result:
        """Install a forwarding entry into the data-plane backend."""

    def DPlane_delete_forwarding_entry(
        self,
        DPlane_entry: DPlane_ForwardingEntry,
    ) -> DPlane_Result:
        """Delete a forwarding entry from the data-plane backend."""
