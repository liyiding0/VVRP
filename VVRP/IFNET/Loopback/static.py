from __future__ import annotations

import platform

from VVRP.IFNET.models import NetworkInterface
from VVRP.IP.static import StaticIpv4Address, StaticIpv4Result


class LoopbackStaticIpv4Provider:
    def __init__(self, system: str | None = None) -> None:
        self.system = (system or platform.system()).lower()

    def set_static_ipv4(
        self,
        interface: NetworkInterface,
        address: StaticIpv4Address,
    ) -> StaticIpv4Result:
        return _set_loopback_static_ipv4(interface, address, system=self.system)

    def remove_static_ipv4(
        self,
        interface: NetworkInterface,
        address: StaticIpv4Address | None = None,
    ) -> StaticIpv4Result:
        return _remove_loopback_static_ipv4(interface, address, system=self.system)


def _set_loopback_static_ipv4(
    interface: NetworkInterface,
    address: StaticIpv4Address,
    system: str,
) -> StaticIpv4Result:
    try:
        if system == "windows":
            message = _set_windows_loopback_static_ipv4(interface, address)
        elif system == "linux":
            return StaticIpv4Result(
                ok=False,
                message=(
                    "% unsupported OS API backend for static IPv4: linux "
                    "(Netlink/pyroute2 support is not implemented)"
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


def _remove_loopback_static_ipv4(
    interface: NetworkInterface,
    address: StaticIpv4Address | None,
    system: str,
) -> StaticIpv4Result:
    try:
        if system == "windows":
            message = _remove_windows_loopback_static_ipv4(interface, address)
        elif system == "linux":
            return StaticIpv4Result(
                ok=False,
                message=(
                    "% unsupported OS API backend for static IPv4: linux "
                    "(Netlink/pyroute2 support is not implemented)"
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


def _set_windows_loopback_static_ipv4(
    interface: NetworkInterface,
    address: StaticIpv4Address,
) -> str:
    from VVRP.IFNET.Ethernet.windows import set_windows_static_ipv4

    return set_windows_static_ipv4(interface, address)


def _remove_windows_loopback_static_ipv4(
    interface: NetworkInterface,
    address: StaticIpv4Address | None,
) -> str:
    from VVRP.IFNET.Ethernet.windows import remove_windows_static_ipv4

    return remove_windows_static_ipv4(interface, address)
