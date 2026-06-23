from __future__ import annotations

import importlib
import ipaddress
import platform
import socket
from dataclasses import replace
from typing import Any, Protocol

from .Ethernet import is_ethernet_interface
from .Loopback import is_loopback_interface
from .models import InterfaceAddress, InterfaceKind, NetworkInterface


class InterfaceDiscoveryError(RuntimeError):
    """Raised when OS interface discovery cannot run."""


class InterfaceProvider(Protocol):
    def list_interfaces(self) -> tuple[NetworkInterface, ...]:
        """Return VVRP-visible OS interfaces."""


class PsutilInterfaceProvider:
    def list_interfaces(self) -> tuple[NetworkInterface, ...]:
        psutil = _load_psutil()
        raw_addresses = psutil.net_if_addrs()
        raw_stats = psutil.net_if_stats()
        metadata_map = _interface_metadata_map(psutil, raw_addresses)
        interfaces: list[NetworkInterface] = []

        for name in sorted(raw_addresses):
            addresses = tuple(_ip_addresses(raw_addresses[name]))
            mac_address = _mac_address(psutil, raw_addresses[name])
            kind = _classify_interface(name, mac_address, addresses)
            if kind is None:
                continue

            stats = raw_stats.get(name)
            interfaces.append(
                NetworkInterface(
                    name=name,
                    ifnet_index=0,
                    index=_interface_index(name, mac_address, metadata_map),
                    kind=kind,
                    is_up=bool(stats.isup) if stats is not None else False,
                    mac_address=mac_address,
                    mtu=int(stats.mtu) if stats is not None and stats.mtu else None,
                    speed_mbps=int(stats.speed) if stats is not None and stats.speed else None,
                    addresses=addresses,
                )
            )

        return assign_ifnet_indices(tuple(interfaces))


def discover_interfaces(
    provider: InterfaceProvider | None = None,
) -> tuple[NetworkInterface, ...]:
    return assign_ifnet_indices((provider or PsutilInterfaceProvider()).list_interfaces())


def assign_ifnet_indices(
    interfaces: tuple[NetworkInterface, ...],
) -> tuple[NetworkInterface, ...]:
    ordered = sorted(
        interfaces,
        key=lambda interface: (
            0 if interface.kind == "loopback" else 1,
            interface.name.lower(),
        ),
    )
    return tuple(
        replace(interface, ifnet_index=ifnet_index)
        for ifnet_index, interface in enumerate(ordered, start=1)
    )


def _load_psutil() -> Any:
    try:
        return importlib.import_module("psutil")
    except ImportError as exc:
        raise InterfaceDiscoveryError(
            "psutil is required for IFNET interface discovery. "
            "Install dependencies with: python -m pip install -e ."
        ) from exc


def _ip_addresses(raw_addresses: list[Any]) -> list[InterfaceAddress]:
    addresses: list[InterfaceAddress] = []
    for raw_address in raw_addresses:
        if raw_address.family == socket.AF_INET:
            addresses.append(
                InterfaceAddress(
                    family="ipv4",
                    address=raw_address.address,
                    prefix_length=_prefix_length("ipv4", raw_address.netmask),
                )
            )
        elif raw_address.family == socket.AF_INET6:
            addresses.append(
                InterfaceAddress(
                    family="ipv6",
                    address=raw_address.address,
                    prefix_length=_prefix_length("ipv6", raw_address.netmask),
                )
            )
    return addresses


def _mac_address(psutil: Any, raw_addresses: list[Any]) -> str:
    for raw_address in raw_addresses:
        if _is_mac_family(psutil, raw_address.family) and raw_address.address:
            return raw_address.address.upper().replace("-", ":")
    return ""


def _is_mac_family(psutil: Any, family: Any) -> bool:
    mac_families = [getattr(psutil, "AF_LINK", None), getattr(socket, "AF_PACKET", None)]
    return family in [item for item in mac_families if item is not None]


def _prefix_length(family: str, netmask: str | None) -> int | None:
    if not netmask:
        return None

    base = "0.0.0.0" if family == "ipv4" else "::"
    try:
        return ipaddress.ip_network(f"{base}/{netmask}", strict=False).prefixlen
    except ValueError:
        return None


def _interface_index(
    name: str,
    mac_address: str = "",
    index_map: dict[str, Any] | None = None,
) -> int | None:
    if index_map:
        metadata = index_map.get(_normalize_lookup_key(name))
        index = _metadata_index(metadata)
        if index is not None:
            return index

        if mac_address:
            metadata = index_map.get(_normalize_mac_lookup_key(mac_address))
            index = _metadata_index(metadata)
            if index is not None:
                return index

    try:
        return socket.if_nametoindex(name)
    except OSError:
        return None


def _interface_index_map(
    psutil: Any,
    raw_addresses: dict[str, list[Any]],
) -> dict[str, int]:
    return {
        key: metadata["index"]
        for key, metadata in _interface_metadata_map(psutil, raw_addresses).items()
    }


def _interface_metadata_map(
    psutil: Any,
    raw_addresses: dict[str, list[Any]],
) -> dict[str, dict[str, Any]]:
    if platform.system().lower() != "windows":
        return {}

    try:
        adapters = _windows_interface_index_map()
    except OSError:
        adapters = {}

    mac_occurrences: dict[str, int] = {}
    for name, addresses in raw_addresses.items():
        mac_address = _mac_address(psutil, addresses)
        if not mac_address:
            continue
        mac_key = _normalize_mac_lookup_key(mac_address)
        mac_occurrences[mac_key] = mac_occurrences.get(mac_key, 0) + 1

    lookup: dict[str, dict[str, Any]] = {}
    for adapter in adapters.values():
        metadata = {"index": adapter["index"]}
        for key in adapter["names"]:
            if key:
                lookup[_normalize_lookup_key(key)] = metadata

        mac_address = adapter.get("mac_address")
        if mac_address:
            mac_key = _normalize_mac_lookup_key(mac_address)
            if mac_occurrences.get(mac_key) == 1:
                lookup[mac_key] = metadata

    return lookup


def _interface_metadata(
    name: str,
    mac_address: str,
    metadata_map: dict[str, Any],
) -> Any:
    metadata = metadata_map.get(_normalize_lookup_key(name))
    if metadata is not None:
        return metadata
    if mac_address:
        return metadata_map.get(_normalize_mac_lookup_key(mac_address))
    return None


def _metadata_index(metadata: Any) -> int | None:
    if isinstance(metadata, int):
        return metadata
    if isinstance(metadata, dict):
        value = metadata.get("index")
        if isinstance(value, int):
            return value
    return None


def _windows_interface_index_map() -> dict[str, dict[str, Any]]:
    import ctypes
    from ctypes import wintypes

    max_adapter_address_length = 8
    af_unspec = 0
    error_buffer_overflow = 111
    no_error = 0

    class IP_ADAPTER_ADDRESSES(ctypes.Structure):
        pass

    IP_ADAPTER_ADDRESSES_POINTER = ctypes.POINTER(IP_ADAPTER_ADDRESSES)
    IP_ADAPTER_ADDRESSES._fields_ = [
        ("Length", wintypes.ULONG),
        ("IfIndex", wintypes.DWORD),
        ("Next", IP_ADAPTER_ADDRESSES_POINTER),
        ("AdapterName", ctypes.c_char_p),
        ("FirstUnicastAddress", ctypes.c_void_p),
        ("FirstAnycastAddress", ctypes.c_void_p),
        ("FirstMulticastAddress", ctypes.c_void_p),
        ("FirstDnsServerAddress", ctypes.c_void_p),
        ("DnsSuffix", wintypes.LPWSTR),
        ("Description", wintypes.LPWSTR),
        ("FriendlyName", wintypes.LPWSTR),
        ("PhysicalAddress", ctypes.c_ubyte * max_adapter_address_length),
        ("PhysicalAddressLength", wintypes.DWORD),
        ("Flags", wintypes.DWORD),
        ("Mtu", wintypes.DWORD),
        ("IfType", wintypes.DWORD),
        ("OperStatus", wintypes.DWORD),
        ("Ipv6IfIndex", wintypes.DWORD),
        ("ZoneIndices", wintypes.DWORD * 16),
        ("FirstPrefix", ctypes.c_void_p),
    ]

    iphlpapi = ctypes.WinDLL("iphlpapi")
    buffer_size = wintypes.ULONG(15_000)
    buffer = ctypes.create_string_buffer(buffer_size.value)

    result = iphlpapi.GetAdaptersAddresses(
        af_unspec,
        0,
        None,
        ctypes.cast(buffer, IP_ADAPTER_ADDRESSES_POINTER),
        ctypes.byref(buffer_size),
    )
    if result == error_buffer_overflow:
        buffer = ctypes.create_string_buffer(buffer_size.value)
        result = iphlpapi.GetAdaptersAddresses(
            af_unspec,
            0,
            None,
            ctypes.cast(buffer, IP_ADAPTER_ADDRESSES_POINTER),
            ctypes.byref(buffer_size),
        )

    if result != no_error:
        raise OSError(f"Windows IP Helper API error {result}")

    adapters: dict[str, dict[str, Any]] = {}
    current = ctypes.cast(buffer, IP_ADAPTER_ADDRESSES_POINTER)
    while current:
        adapter = current.contents
        adapter_name = _decode_adapter_name(adapter.AdapterName)
        names = tuple(
            name
            for name in (
                adapter.FriendlyName,
                adapter_name,
                adapter.Description,
            )
            if name
        )
        mac_address = _format_physical_address(
            adapter.PhysicalAddress,
            adapter.PhysicalAddressLength,
        )
        key = adapter.FriendlyName or adapter_name or adapter.Description or str(adapter.IfIndex)
        adapters[key] = {
            "index": int(adapter.IfIndex),
            "adapter_name": adapter_name,
            "names": names,
            "mac_address": mac_address,
        }
        current = adapter.Next

    return adapters


def _decode_adapter_name(adapter_name: bytes | None) -> str:
    if not adapter_name:
        return ""
    return adapter_name.decode("ascii", errors="ignore")


def _format_physical_address(raw_address, length: int) -> str:
    if not length:
        return ""
    return ":".join(f"{raw_address[index]:02X}" for index in range(int(length)))


def _normalize_lookup_key(value: str) -> str:
    return value.casefold()


def _normalize_mac_lookup_key(value: str) -> str:
    return value.replace("-", ":").casefold()


def _classify_interface(
    name: str,
    mac_address: str,
    addresses: tuple[InterfaceAddress, ...],
) -> InterfaceKind | None:
    if is_loopback_interface(name, addresses):
        return "loopback"

    if is_ethernet_interface(name, mac_address):
        return "ethernet"

    return None
