from __future__ import annotations

import platform
from dataclasses import dataclass
from typing import Protocol

from VVRP.IFNET.models import NetworkInterface


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
    def __init__(self, system: str | None = None) -> None:
        self.system = (system or platform.system()).lower()
        self._ethernet = None

    def IP_enable_dhcp(self, interface: NetworkInterface) -> IP_DhcpClientResult:
        return self._IP_apply(interface, enable=True)

    def IP_disable_dhcp(self, interface: NetworkInterface) -> IP_DhcpClientResult:
        return self._IP_apply(interface, enable=False)

    def _IP_apply(self, interface: NetworkInterface, enable: bool) -> IP_DhcpClientResult:
        if interface.kind == "ethernet":
            provider = self._IP_ethernet_provider()
            if enable:
                return provider.IP_enable_dhcp(interface)
            return provider.IP_disable_dhcp(interface)

        return IP_DhcpClientResult(
            ok=False,
            message=f"% Unsupported interface type for DHCP client: {interface.kind}",
        )

    def _IP_ethernet_provider(self):
        if self._ethernet is None:
            from VVRP.IFNET.Ethernet.dhcp import EthernetDhcpClientProvider

            self._ethernet = EthernetDhcpClientProvider(system=self.system)
        return self._ethernet


