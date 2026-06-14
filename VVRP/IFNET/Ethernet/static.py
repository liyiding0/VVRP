from __future__ import annotations

import platform

from VVRP.IFNET.models import NetworkInterface
from VVRP.IP.static import StaticIpv4Address, StaticIpv4Result


class EthernetStaticIpv4Provider:
    def __init__(self, system: str | None = None) -> None:
        self.system = (system or platform.system()).lower()

    def set_static_ipv4(
        self,
        interface: NetworkInterface,
        address: StaticIpv4Address,
    ) -> StaticIpv4Result:
        return _set_ethernet_static_ipv4(interface, address, system=self.system)

    def remove_static_ipv4(
        self,
        interface: NetworkInterface,
        address: StaticIpv4Address | None = None,
    ) -> StaticIpv4Result:
        return _remove_ethernet_static_ipv4(interface, address, system=self.system)


def _set_ethernet_static_ipv4(
    interface: NetworkInterface,
    address: StaticIpv4Address,
    system: str,
) -> StaticIpv4Result:
    try:
        if system == "windows":
            message = _set_windows_ethernet_static_ipv4(interface, address)
        elif system == "linux":
            return StaticIpv4Result(
                ok=False,
                message=(
                    "% unsupported OS API backend for static IPv4: linux "
                    "(NetworkManager/systemd-networkd support is not implemented)"
                ),
            )
        else:
            return StaticIpv4Result(
                ok=False,
                message=f"% unsupported OS API backend for static IPv4: {system}",
            )
    except PermissionError as exc:
        return StaticIpv4Result(ok=False, message=f"% permission denied: {exc}")
    except OSError as exc:
        return StaticIpv4Result(ok=False, message=f"% OS interface API failed: {exc}")

    return StaticIpv4Result(ok=True, message=message)


def _remove_ethernet_static_ipv4(
    interface: NetworkInterface,
    address: StaticIpv4Address | None,
    system: str,
) -> StaticIpv4Result:
    try:
        if system == "windows":
            message = _remove_windows_ethernet_static_ipv4(interface, address)
        elif system == "linux":
            return StaticIpv4Result(
                ok=False,
                message=(
                    "% unsupported OS API backend for static IPv4: linux "
                    "(NetworkManager/systemd-networkd support is not implemented)"
                ),
            )
        else:
            return StaticIpv4Result(
                ok=False,
                message=f"% unsupported OS API backend for static IPv4: {system}",
            )
    except PermissionError as exc:
        return StaticIpv4Result(ok=False, message=f"% permission denied: {exc}")
    except OSError as exc:
        return StaticIpv4Result(ok=False, message=f"% OS interface API failed: {exc}")

    return StaticIpv4Result(ok=True, message=message)


def _set_windows_ethernet_static_ipv4(
    interface: NetworkInterface,
    address: StaticIpv4Address,
) -> str:
    from .windows import set_windows_static_ipv4

    return set_windows_static_ipv4(interface, address)


def _remove_windows_ethernet_static_ipv4(
    interface: NetworkInterface,
    address: StaticIpv4Address | None,
) -> str:
    from .windows import remove_windows_static_ipv4

    return remove_windows_static_ipv4(interface, address)
