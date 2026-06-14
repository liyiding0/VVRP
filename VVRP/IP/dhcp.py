from __future__ import annotations

import platform
from dataclasses import dataclass
from typing import Protocol

from VVRP.IFNET.models import NetworkInterface


@dataclass(frozen=True)
class DhcpClientResult:
    ok: bool
    message: str = ""


class DhcpClientProvider(Protocol):
    def enable_dhcp(self, interface: NetworkInterface) -> DhcpClientResult:
        """Enable DHCP client address allocation on an interface."""

    def disable_dhcp(self, interface: NetworkInterface) -> DhcpClientResult:
        """Disable DHCP client address allocation on an interface."""


class OsDhcpClientProvider:
    def __init__(self, system: str | None = None) -> None:
        self.system = (system or platform.system()).lower()
        self._ethernet = None

    def enable_dhcp(self, interface: NetworkInterface) -> DhcpClientResult:
        return self._apply(interface, enable=True)

    def disable_dhcp(self, interface: NetworkInterface) -> DhcpClientResult:
        return self._apply(interface, enable=False)

    def _apply(self, interface: NetworkInterface, enable: bool) -> DhcpClientResult:
        if interface.kind == "ethernet":
            provider = self._ethernet_provider()
            if enable:
                return provider.enable_dhcp(interface)
            return provider.disable_dhcp(interface)

        return DhcpClientResult(
            ok=False,
            message=f"% Unsupported interface type for DHCP client: {interface.kind}",
        )

    def _ethernet_provider(self):
        if self._ethernet is None:
            from VVRP.IFNET.Ethernet.dhcp import EthernetDhcpClientProvider

            self._ethernet = EthernetDhcpClientProvider(system=self.system)
        return self._ethernet
