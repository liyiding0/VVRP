from __future__ import annotations

import platform

from VVRP.IFNET.models import NetworkInterface
from VVRP.IP.dhcp import DhcpClientResult


class EthernetDhcpClientProvider:
    def __init__(self, system: str | None = None) -> None:
        self.system = (system or platform.system()).lower()

    def enable_dhcp(self, interface: NetworkInterface) -> DhcpClientResult:
        return _set_ethernet_dhcp(interface, enabled=True, system=self.system)

    def disable_dhcp(self, interface: NetworkInterface) -> DhcpClientResult:
        return _set_ethernet_dhcp(interface, enabled=False, system=self.system)


def _set_ethernet_dhcp(
    interface: NetworkInterface,
    enabled: bool,
    system: str,
) -> DhcpClientResult:
    try:
        if system == "windows":
            message = _set_windows_ethernet_dhcp(interface, enabled)
        elif system == "linux":
            return DhcpClientResult(
                ok=False,
                message=(
                    "% unsupported OS API backend for DHCP client: linux "
                    "(NetworkManager/systemd-networkd support is not implemented)"
                ),
            )
        else:
            return DhcpClientResult(
                ok=False,
                message=f"% unsupported OS API backend for DHCP client: {system}",
            )
    except PermissionError as exc:
        return DhcpClientResult(ok=False, message=f"% permission denied: {exc}")
    except OSError as exc:
        return DhcpClientResult(ok=False, message=f"% OS interface API failed: {exc}")

    return DhcpClientResult(ok=True, message=message)


def _set_windows_ethernet_dhcp(
    interface: NetworkInterface,
    enabled: bool,
) -> str:
    from .windows import set_windows_network_adapter_dhcp

    return set_windows_network_adapter_dhcp(interface, enabled)
