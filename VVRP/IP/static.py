from __future__ import annotations

import ipaddress
import platform
from dataclasses import dataclass
from typing import Protocol

from VVRP.IFNET.models import InterfaceAddress, NetworkInterface


_UNUSABLE_INTERFACE_NETWORKS = tuple(
    ipaddress.IPv4Network(network)
    for network in (
        "0.0.0.0/8",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
    )
)


@dataclass(frozen=True)
class StaticIpv4Address:
    address: str
    prefix_length: int
    secondary: bool = False

    @property
    def subnet_mask(self) -> str:
        return str(ipaddress.IPv4Network(f"0.0.0.0/{self.prefix_length}").netmask)


@dataclass(frozen=True)
class StaticIpv4Result:
    ok: bool
    message: str = ""


class StaticIpv4Provider(Protocol):
    def set_static_ipv4(
        self,
        interface: NetworkInterface,
        address: StaticIpv4Address,
    ) -> StaticIpv4Result:
        """Configure a static IPv4 address on an interface."""

    def remove_static_ipv4(
        self,
        interface: NetworkInterface,
        address: StaticIpv4Address | None = None,
    ) -> StaticIpv4Result:
        """Remove one or all static IPv4 addresses from an interface."""


class StaticIpv4ValidationError(ValueError):
    pass


class OsStaticIpv4Provider:
    def __init__(self, system: str | None = None) -> None:
        self.system = (system or platform.system()).lower()
        self._ethernet = None
        self._loopback = None

    def set_static_ipv4(
        self,
        interface: NetworkInterface,
        address: StaticIpv4Address,
    ) -> StaticIpv4Result:
        return self._apply(interface, address)

    def remove_static_ipv4(
        self,
        interface: NetworkInterface,
        address: StaticIpv4Address | None = None,
    ) -> StaticIpv4Result:
        return self._apply(interface, address, remove=True)

    def _apply(
        self,
        interface: NetworkInterface,
        address: StaticIpv4Address | None,
        remove: bool = False,
    ) -> StaticIpv4Result:
        if interface.kind == "ethernet":
            provider = self._ethernet_provider()
            if remove:
                return provider.remove_static_ipv4(interface, address)
            assert address is not None
            return provider.set_static_ipv4(interface, address)

        if interface.kind == "loopback":
            provider = self._loopback_provider()
            if remove:
                return provider.remove_static_ipv4(interface, address)
            assert address is not None
            return provider.set_static_ipv4(interface, address)

        return StaticIpv4Result(
            ok=False,
            message=f"% Unsupported interface type for static IPv4: {interface.kind}",
        )

    def _ethernet_provider(self):
        if self._ethernet is None:
            from VVRP.IFNET.Ethernet.static import EthernetStaticIpv4Provider

            self._ethernet = EthernetStaticIpv4Provider(system=self.system)
        return self._ethernet

    def _loopback_provider(self):
        if self._loopback is None:
            from VVRP.IFNET.Loopback.static import LoopbackStaticIpv4Provider

            self._loopback = LoopbackStaticIpv4Provider(system=self.system)
        return self._loopback


def parse_static_ipv4_address(
    address_text: str,
    mask_text: str,
    secondary: bool = False,
) -> StaticIpv4Address:
    address = _parse_ipv4_address(address_text)
    prefix_length = parse_ipv4_mask(mask_text)
    network = ipaddress.IPv4Network(f"{address}/{prefix_length}", strict=False)

    if prefix_length <= 30 and address == network.network_address:
        raise StaticIpv4ValidationError(
            f"% Invalid IPv4 address: {address_text} is the network address for /{prefix_length}"
        )
    if prefix_length <= 30 and address == network.broadcast_address:
        raise StaticIpv4ValidationError(
            f"% Invalid IPv4 address: {address_text} is the broadcast address for /{prefix_length}"
        )

    return StaticIpv4Address(
        address=str(address),
        prefix_length=prefix_length,
        secondary=secondary,
    )


def validate_static_ipv4_address_for_interface(
    address: StaticIpv4Address,
    interface: NetworkInterface,
    interfaces: tuple[NetworkInterface, ...],
) -> None:
    validate_static_ipv4_interface_policy(address, interface)

    current_interface_addresses = static_ipv4_addresses_from_interface(interface)
    for existing in current_interface_addresses:
        if existing.address != address.address:
            continue
        if not address.secondary and existing.prefix_length == address.prefix_length:
            continue
        raise StaticIpv4ValidationError(
            f"% Invalid IPv4 address: duplicate address on interface {interface.name}"
        )

    if address.secondary and _secondary_static_ipv4_count(current_interface_addresses) >= 255:
        raise StaticIpv4ValidationError(
            f"% Too many secondary IPv4 addresses on interface {interface.name}"
        )

    new_entry = _AddressEntry(interface.name, address)
    for other_interface in interfaces:
        if other_interface.name == interface.name:
            continue
        for existing in static_ipv4_addresses_from_interface(other_interface):
            existing_entry = _AddressEntry(other_interface.name, existing)
            _validate_no_cross_interface_conflict(new_entry, existing_entry)


def validate_static_ipv4_interface_policy(
    address: StaticIpv4Address,
    interface: NetworkInterface,
) -> None:
    if interface.kind == "ethernet":
        if address.prefix_length == 32:
            raise StaticIpv4ValidationError(
                "% Invalid IPv4 mask length: /32 is supported only on Loopback interfaces"
            )
    elif interface.kind == "loopback":
        if address.prefix_length != 32:
            raise StaticIpv4ValidationError(
                "% Invalid IPv4 mask length: Loopback interfaces support only /32"
            )
    else:
        raise StaticIpv4ValidationError(
            f"% Unsupported interface type for static IPv4: {interface.kind}"
        )


def primary_static_ipv4_from_interface(
    interface: NetworkInterface,
) -> StaticIpv4Address | None:
    addresses = static_ipv4_addresses_from_interface(interface)
    if not addresses:
        return None
    return addresses[0]


def has_secondary_static_ipv4(interface: NetworkInterface) -> bool:
    return _secondary_static_ipv4_count(static_ipv4_addresses_from_interface(interface)) > 0


def static_ipv4_addresses_from_interface(
    interface: NetworkInterface,
) -> tuple[StaticIpv4Address, ...]:
    addresses: list[StaticIpv4Address] = []
    for item in interface.addresses_by_family("ipv4"):
        address = _static_ipv4_from_interface_address(item)
        if address is not None:
            addresses.append(
                StaticIpv4Address(
                    address=address.address,
                    prefix_length=address.prefix_length,
                    secondary=bool(addresses),
                )
            )
    return tuple(addresses)


@dataclass(frozen=True)
class _AddressEntry:
    interface_name: str
    address: StaticIpv4Address

    @property
    def ip(self) -> ipaddress.IPv4Address:
        return ipaddress.IPv4Address(self.address.address)

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.IPv4Network(
            f"{self.address.address}/{self.address.prefix_length}",
            strict=False,
        )

    @property
    def broadcast(self) -> ipaddress.IPv4Address | None:
        if self.address.prefix_length > 30:
            return None
        return self.network.broadcast_address


def _static_ipv4_from_interface_address(
    address: InterfaceAddress,
) -> StaticIpv4Address | None:
    if address.prefix_length is None:
        return None
    try:
        parsed = parse_static_ipv4_address(address.address, str(address.prefix_length))
    except StaticIpv4ValidationError:
        return None
    return parsed


def _secondary_static_ipv4_count(addresses: tuple[StaticIpv4Address, ...]) -> int:
    if not addresses:
        return 0
    return max(0, len(addresses) - 1)


def _validate_no_cross_interface_conflict(
    new_entry: _AddressEntry,
    existing_entry: _AddressEntry,
) -> None:
    if new_entry.ip == existing_entry.ip:
        raise StaticIpv4ValidationError(
            "% Invalid IPv4 address: duplicate address on another interface "
            f"({existing_entry.interface_name})"
        )

    existing_broadcast = existing_entry.broadcast
    if existing_broadcast is not None and new_entry.ip == existing_broadcast:
        raise StaticIpv4ValidationError(
            "% Invalid IPv4 address: address conflicts with broadcast address on "
            f"{existing_entry.interface_name}"
        )

    new_broadcast = new_entry.broadcast
    if new_broadcast is not None and new_broadcast == existing_entry.ip:
        raise StaticIpv4ValidationError(
            "% Invalid IPv4 address: broadcast address conflicts with address on "
            f"{existing_entry.interface_name}"
        )

    if (
        new_broadcast is not None
        and existing_broadcast is not None
        and new_broadcast == existing_broadcast
    ):
        raise StaticIpv4ValidationError(
            "% Invalid IPv4 address: broadcast address conflicts with interface "
            f"{existing_entry.interface_name}"
        )

    if new_entry.network.overlaps(existing_entry.network):
        raise StaticIpv4ValidationError(
            "% Invalid IPv4 address: subnet overlaps with interface "
            f"{existing_entry.interface_name}"
        )


def parse_ipv4_mask(mask_text: str) -> int:
    if mask_text.isdigit():
        prefix_length = int(mask_text)
        if 0 <= prefix_length <= 32:
            return prefix_length
        raise StaticIpv4ValidationError("% Invalid IPv4 mask length: expected 0-32")

    if not _looks_dotted_decimal(mask_text):
        raise StaticIpv4ValidationError(
            "% Invalid IPv4 mask: expected dotted decimal mask or mask length"
        )

    try:
        mask = ipaddress.IPv4Address(mask_text)
    except ValueError as exc:
        raise StaticIpv4ValidationError("% Invalid IPv4 mask") from exc

    mask_int = int(mask)
    inverted = (~mask_int) & 0xFFFFFFFF
    if inverted & (inverted + 1):
        raise StaticIpv4ValidationError("% Invalid IPv4 mask: mask must be contiguous")

    return int(mask).bit_count()


def _parse_ipv4_address(address_text: str) -> ipaddress.IPv4Address:
    if not _looks_dotted_decimal(address_text):
        raise StaticIpv4ValidationError(
            "% Invalid IPv4 address: expected dotted decimal format"
        )

    try:
        address = ipaddress.IPv4Address(address_text)
    except ValueError as exc:
        raise StaticIpv4ValidationError("% Invalid IPv4 address") from exc

    first_octet = int(address_text.split(".", 1)[0])
    if first_octet < 1 or first_octet > 223:
        raise StaticIpv4ValidationError(
            "% Invalid IPv4 address: expected class A, B, or C unicast address"
        )
    if _is_unusable_interface_address(address):
        raise StaticIpv4ValidationError(
            "% Invalid IPv4 address: address is not usable as an interface unicast address"
        )

    return address


def _is_unusable_interface_address(address: ipaddress.IPv4Address) -> bool:
    if address == ipaddress.IPv4Address("255.255.255.255"):
        return True
    return any(address in network for network in _UNUSABLE_INTERFACE_NETWORKS)


def _looks_dotted_decimal(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        if len(part) > 1 and part.startswith("0"):
            return False
        if not 0 <= int(part) <= 255:
            return False
    return True
