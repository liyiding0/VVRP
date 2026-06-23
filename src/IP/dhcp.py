from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from src.IFNET.models import NetworkInterface


@dataclass(frozen=True)
class IP_DhcpClientResult:
    ok: bool
    message: str = ""


class IP_DhcpClientProvider(Protocol):
    def IP_enable_dhcp(self, interface: NetworkInterface) -> IP_DhcpClientResult:
        """Enable DHCP client address allocation on an interface."""

    def IP_disable_dhcp(self, interface: NetworkInterface) -> IP_DhcpClientResult:
        """Disable DHCP client address allocation on an interface."""


class IP_OsDhcpClientProvider:
    def __init__(self, dplane_backend=None) -> None:
        from src.DPlane.ip_config import DPlane_DhcpClientProvider

        self._provider = DPlane_DhcpClientProvider(dplane_backend)

    def IP_enable_dhcp(self, interface: NetworkInterface) -> IP_DhcpClientResult:
        return self._provider.IP_enable_dhcp(interface)

    def IP_disable_dhcp(self, interface: NetworkInterface) -> IP_DhcpClientResult:
        return self._provider.IP_disable_dhcp(interface)


