from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Protocol

from src.IFNET.models import InterfaceAddress, NetworkInterface


g_IP_UNUSABLE_INTERFACE_NETWORKS = tuple(
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
class IP_StaticIpv4Address:
    address: str
    prefix_length: int
    secondary: bool = False

    @property
    def subnet_mask(self) -> str:
        return str(ipaddress.IPv4Network(f"0.0.0.0/{self.prefix_length}").netmask)


@dataclass(frozen=True)
class IP_StaticIpv4Result:
    ok: bool
    message: str = ""


class IP_StaticIpv4Provider(Protocol):
    def IP_set_static_ipv4(
        self,
        interface: NetworkInterface,
        address: IP_StaticIpv4Address,
    ) -> IP_StaticIpv4Result:
        """Configure a static IPv4 address on an interface."""

    def IP_remove_static_ipv4(
        self,
        interface: NetworkInterface,
        address: IP_StaticIpv4Address | None = None,
    ) -> IP_StaticIpv4Result:
        """Remove one or all static IPv4 addresses from an interface."""


class IP_StaticIpv4ValidationError(ValueError):
    pass


class IP_OsStaticIpv4Provider:
    def __init__(self, dplane_backend=None) -> None:
        from src.DPlane.ip_config import DPlane_StaticIpv4Provider

        self._provider = DPlane_StaticIpv4Provider(dplane_backend)

    def IP_set_static_ipv4(
        self,
        interface: NetworkInterface,
        address: IP_StaticIpv4Address,
    ) -> IP_StaticIpv4Result:
        return self._provider.IP_set_static_ipv4(interface, address)

    def IP_remove_static_ipv4(
        self,
        interface: NetworkInterface,
        address: IP_StaticIpv4Address | None = None,
    ) -> IP_StaticIpv4Result:
        return self._provider.IP_remove_static_ipv4(interface, address)


def IP_parse_static_ipv4_address(
    address_text: str,
    mask_text: str,
    secondary: bool = False,
) -> IP_StaticIpv4Address:
    address = _IP_parse_ipv4_address(address_text)
    prefix_length = IP_parse_ipv4_mask(mask_text)
    network = ipaddress.IPv4Network(f"{address}/{prefix_length}", strict=False)

    if prefix_length <= 30 and address == network.network_address:
        raise IP_StaticIpv4ValidationError(
            f"% Invalid IPv4 address: {address_text} is the network address for /{prefix_length}"
        )
    if prefix_length <= 30 and address == network.broadcast_address:
        raise IP_StaticIpv4ValidationError(
            f"% Invalid IPv4 address: {address_text} is the broadcast address for /{prefix_length}"
        )

    return IP_StaticIpv4Address(
        address=str(address),
        prefix_length=prefix_length,
        secondary=secondary,
    )


def IP_validate_static_ipv4_address_for_interface(
    address: IP_StaticIpv4Address,
    interface: NetworkInterface,
    interfaces: tuple[NetworkInterface, ...],
) -> None:
    IP_validate_static_ipv4_interface_policy(address, interface)

    current_interface_addresses = IP_static_ipv4_addresses_from_interface(interface)
    for existing in current_interface_addresses:
        if existing.address != address.address:
            continue
        if not address.secondary and existing.prefix_length == address.prefix_length:
            continue
        raise IP_StaticIpv4ValidationError(
            f"% Invalid IPv4 address: duplicate address on interface {interface.name}"
        )

    if address.secondary and _IP_secondary_static_ipv4_count(current_interface_addresses) >= 255:
        raise IP_StaticIpv4ValidationError(
            f"% Too many secondary IPv4 addresses on interface {interface.name}"
        )

    new_entry = _IP_AddressEntry(interface.name, address)
    for other_interface in interfaces:
        if other_interface.name == interface.name:
            continue
        for existing in IP_static_ipv4_addresses_from_interface(other_interface):
            existing_entry = _IP_AddressEntry(other_interface.name, existing)
            _IP_validate_no_cross_interface_conflict(new_entry, existing_entry)


def IP_validate_static_ipv4_interface_policy(
    address: IP_StaticIpv4Address,
    interface: NetworkInterface,
) -> None:
    if interface.kind == "ethernet":
        if address.prefix_length == 32:
            raise IP_StaticIpv4ValidationError(
                "% Invalid IPv4 mask length: /32 is supported only on Loopback interfaces"
            )
    elif interface.kind == "loopback":
        if address.prefix_length != 32:
            raise IP_StaticIpv4ValidationError(
                "% Invalid IPv4 mask length: Loopback interfaces support only /32"
            )
    else:
        raise IP_StaticIpv4ValidationError(
            f"% Unsupported interface type for static IPv4: {interface.kind}"
        )


def IP_primary_static_ipv4_from_interface(
    interface: NetworkInterface,
) -> IP_StaticIpv4Address | None:
    addresses = IP_static_ipv4_addresses_from_interface(interface)
    if not addresses:
        return None
    return addresses[0]


def IP_has_secondary_static_ipv4(interface: NetworkInterface) -> bool:
    return _IP_secondary_static_ipv4_count(IP_static_ipv4_addresses_from_interface(interface)) > 0


def IP_static_ipv4_addresses_from_interface(
    interface: NetworkInterface,
) -> tuple[IP_StaticIpv4Address, ...]:
    addresses: list[IP_StaticIpv4Address] = []
    for item in interface.addresses_by_family("ipv4"):
        address = _IP_static_ipv4_from_interface_address(item)
        if address is not None:
            addresses.append(
                IP_StaticIpv4Address(
                    address=address.address,
                    prefix_length=address.prefix_length,
                    secondary=bool(addresses),
                )
            )
    return tuple(addresses)


@dataclass(frozen=True)
class _IP_AddressEntry:
    interface_name: str
    address: IP_StaticIpv4Address

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


def _IP_static_ipv4_from_interface_address(
    address: InterfaceAddress,
) -> IP_StaticIpv4Address | None:
    if address.prefix_length is None:
        return None
    try:
        parsed = IP_parse_static_ipv4_address(address.address, str(address.prefix_length))
    except IP_StaticIpv4ValidationError:
        return None
    return parsed


def _IP_secondary_static_ipv4_count(addresses: tuple[IP_StaticIpv4Address, ...]) -> int:
    if not addresses:
        return 0
    return max(0, len(addresses) - 1)


def _IP_validate_no_cross_interface_conflict(
    new_entry: _IP_AddressEntry,
    existing_entry: _IP_AddressEntry,
) -> None:
    if new_entry.ip == existing_entry.ip:
        raise IP_StaticIpv4ValidationError(
            "% Invalid IPv4 address: duplicate address on another interface "
            f"({existing_entry.interface_name})"
        )

    existing_broadcast = existing_entry.broadcast
    if existing_broadcast is not None and new_entry.ip == existing_broadcast:
        raise IP_StaticIpv4ValidationError(
            "% Invalid IPv4 address: address conflicts with broadcast address on "
            f"{existing_entry.interface_name}"
        )

    new_broadcast = new_entry.broadcast
    if new_broadcast is not None and new_broadcast == existing_entry.ip:
        raise IP_StaticIpv4ValidationError(
            "% Invalid IPv4 address: broadcast address conflicts with address on "
            f"{existing_entry.interface_name}"
        )

    if (
        new_broadcast is not None
        and existing_broadcast is not None
        and new_broadcast == existing_broadcast
    ):
        raise IP_StaticIpv4ValidationError(
            "% Invalid IPv4 address: broadcast address conflicts with interface "
            f"{existing_entry.interface_name}"
        )

    if new_entry.network.overlaps(existing_entry.network):
        raise IP_StaticIpv4ValidationError(
            "% Invalid IPv4 address: subnet overlaps with interface "
            f"{existing_entry.interface_name}"
        )


def IP_parse_ipv4_mask(mask_text: str) -> int:
    if mask_text.isdigit():
        prefix_length = int(mask_text)
        if 0 <= prefix_length <= 32:
            return prefix_length
        raise IP_StaticIpv4ValidationError("% Invalid IPv4 mask length: expected 0-32")

    if not _IP_looks_dotted_decimal(mask_text):
        raise IP_StaticIpv4ValidationError(
            "% Invalid IPv4 mask: expected dotted decimal mask or mask length"
        )

    try:
        mask = ipaddress.IPv4Address(mask_text)
    except ValueError as exc:
        raise IP_StaticIpv4ValidationError("% Invalid IPv4 mask") from exc

    mask_int = int(mask)
    inverted = (~mask_int) & 0xFFFFFFFF
    if inverted & (inverted + 1):
        raise IP_StaticIpv4ValidationError("% Invalid IPv4 mask: mask must be contiguous")

    return int(mask).bit_count()


def _IP_parse_ipv4_address(address_text: str) -> ipaddress.IPv4Address:
    if not _IP_looks_dotted_decimal(address_text):
        raise IP_StaticIpv4ValidationError(
            "% Invalid IPv4 address: expected dotted decimal format"
        )

    try:
        address = ipaddress.IPv4Address(address_text)
    except ValueError as exc:
        raise IP_StaticIpv4ValidationError("% Invalid IPv4 address") from exc

    first_octet = int(address_text.split(".", 1)[0])
    if first_octet < 1 or first_octet > 223:
        raise IP_StaticIpv4ValidationError(
            "% Invalid IPv4 address: expected class A, B, or C unicast address"
        )
    if _IP_is_unusable_interface_address(address):
        raise IP_StaticIpv4ValidationError(
            "% Invalid IPv4 address: address is not usable as an interface unicast address"
        )

    return address


def _IP_is_unusable_interface_address(address: ipaddress.IPv4Address) -> bool:
    if address == ipaddress.IPv4Address("255.255.255.255"):
        return True
    return any(address in network for network in g_IP_UNUSABLE_INTERFACE_NETWORKS)


def _IP_looks_dotted_decimal(value: str) -> bool:
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


