from __future__ import annotations

import ipaddress
import platform
from dataclasses import dataclass
from typing import Protocol

from VVRP.IFNET.models import NetworkInterface


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

        return StaticIpv4Result(
            ok=False,
            message=f"% Unsupported interface type for static IPv4: {interface.kind}",
        )

    def _ethernet_provider(self):
        if self._ethernet is None:
            from VVRP.IFNET.Ethernet.static import EthernetStaticIpv4Provider

            self._ethernet = EthernetStaticIpv4Provider(system=self.system)
        return self._ethernet


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
