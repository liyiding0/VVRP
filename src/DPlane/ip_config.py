from __future__ import annotations

from src.IFNET.models import NetworkInterface
from src.IP.dhcp import IP_DhcpClientResult
from src.IP.static import IP_StaticIpv4Address, IP_StaticIpv4Result


class DPlane_StaticIpv4Provider:
    def __init__(self, DPlane_backend=None, system: str | None = None) -> None:
        if DPlane_backend is None and system is None:
            from src.DPlane import DPlane_create_backend

            DPlane_backend = DPlane_create_backend()
        self.DPlane_backend = DPlane_backend
        self.DPlane_system = system

    def IP_set_static_ipv4(
        self,
        interface: NetworkInterface,
        address: IP_StaticIpv4Address,
    ) -> IP_StaticIpv4Result:
        return DPlane_set_static_ipv4(interface, address, self._DPlane_platform_kind())

    def IP_remove_static_ipv4(
        self,
        interface: NetworkInterface,
        address: IP_StaticIpv4Address | None = None,
    ) -> IP_StaticIpv4Result:
        return DPlane_remove_static_ipv4(interface, address, self._DPlane_platform_kind())

    def _DPlane_platform_kind(self) -> str:
        if self.DPlane_system is not None:
            return self.DPlane_system.lower()
        return self.DPlane_backend.DPlane_platform.kind


class DPlane_DhcpClientProvider:
    def __init__(self, DPlane_backend=None, system: str | None = None) -> None:
        if DPlane_backend is None and system is None:
            from src.DPlane import DPlane_create_backend

            DPlane_backend = DPlane_create_backend()
        self.DPlane_backend = DPlane_backend
        self.DPlane_system = system

    def IP_enable_dhcp(self, interface: NetworkInterface) -> IP_DhcpClientResult:
        return DPlane_set_dhcp(interface, True, self._DPlane_platform_kind())

    def IP_disable_dhcp(self, interface: NetworkInterface) -> IP_DhcpClientResult:
        return DPlane_set_dhcp(interface, False, self._DPlane_platform_kind())

    def _DPlane_platform_kind(self) -> str:
        if self.DPlane_system is not None:
            return self.DPlane_system.lower()
        return self.DPlane_backend.DPlane_platform.kind


def DPlane_set_static_ipv4(
    DPlane_interface: NetworkInterface,
    DPlane_address: IP_StaticIpv4Address,
    DPlane_platform_kind: str,
) -> IP_StaticIpv4Result:
    if DPlane_interface.kind not in ("ethernet", "loopback"):
        return IP_StaticIpv4Result(
            ok=False,
            message=f"% Unsupported interface type for static IPv4: {DPlane_interface.kind}",
        )
    try:
        if DPlane_platform_kind == "windows":
            from src.DPlane.Windows.interface_windows import set_windows_static_ipv4

            DPlane_message = set_windows_static_ipv4(DPlane_interface, DPlane_address)
        elif DPlane_platform_kind in {"linux", "openwrt"}:
            return IP_StaticIpv4Result(
                ok=False,
                message=(
                    f"% unsupported OS API backend for static IPv4: {DPlane_platform_kind} "
                    "(Netlink/pyroute2 support is not implemented)"
                ),
            )
        else:
            return IP_StaticIpv4Result(
                ok=False,
                message=f"% unsupported OS API backend for static IPv4: {DPlane_platform_kind}",
            )
    except PermissionError as DPlane_exc:
        return IP_StaticIpv4Result(ok=False, message=f"% permission denied: {DPlane_exc}")
    except OSError as DPlane_exc:
        return IP_StaticIpv4Result(ok=False, message=f"% OS interface API failed: {DPlane_exc}")
    return IP_StaticIpv4Result(ok=True, message=DPlane_message)


def DPlane_remove_static_ipv4(
    DPlane_interface: NetworkInterface,
    DPlane_address: IP_StaticIpv4Address | None,
    DPlane_platform_kind: str,
) -> IP_StaticIpv4Result:
    if DPlane_interface.kind not in ("ethernet", "loopback"):
        return IP_StaticIpv4Result(
            ok=False,
            message=f"% Unsupported interface type for static IPv4: {DPlane_interface.kind}",
        )
    try:
        if DPlane_platform_kind == "windows":
            from src.DPlane.Windows.interface_windows import remove_windows_static_ipv4

            DPlane_message = remove_windows_static_ipv4(DPlane_interface, DPlane_address)
        elif DPlane_platform_kind in {"linux", "openwrt"}:
            return IP_StaticIpv4Result(
                ok=False,
                message=(
                    f"% unsupported OS API backend for static IPv4: {DPlane_platform_kind} "
                    "(Netlink/pyroute2 support is not implemented)"
                ),
            )
        else:
            return IP_StaticIpv4Result(
                ok=False,
                message=f"% unsupported OS API backend for static IPv4: {DPlane_platform_kind}",
            )
    except PermissionError as DPlane_exc:
        return IP_StaticIpv4Result(ok=False, message=f"% permission denied: {DPlane_exc}")
    except OSError as DPlane_exc:
        return IP_StaticIpv4Result(ok=False, message=f"% OS interface API failed: {DPlane_exc}")
    return IP_StaticIpv4Result(ok=True, message=DPlane_message)


def DPlane_set_dhcp(
    DPlane_interface: NetworkInterface,
    DPlane_enabled: bool,
    DPlane_platform_kind: str,
) -> IP_DhcpClientResult:
    if DPlane_interface.kind != "ethernet":
        return IP_DhcpClientResult(
            ok=False,
            message=f"% Unsupported interface type for DHCP client: {DPlane_interface.kind}",
        )
    try:
        if DPlane_platform_kind == "windows":
            from src.DPlane.Windows.interface_windows import set_windows_network_adapter_dhcp

            DPlane_message = set_windows_network_adapter_dhcp(DPlane_interface, DPlane_enabled)
        elif DPlane_platform_kind in {"linux", "openwrt"}:
            return IP_DhcpClientResult(
                ok=False,
                message=(
                    f"% unsupported OS API backend for DHCP client: {DPlane_platform_kind} "
                    "(NetworkManager/systemd-networkd support is not implemented)"
                ),
            )
        else:
            return IP_DhcpClientResult(
                ok=False,
                message=f"% unsupported OS API backend for DHCP client: {DPlane_platform_kind}",
            )
    except PermissionError as DPlane_exc:
        return IP_DhcpClientResult(ok=False, message=f"% permission denied: {DPlane_exc}")
    except OSError as DPlane_exc:
        return IP_DhcpClientResult(ok=False, message=f"% OS interface API failed: {DPlane_exc}")
    return IP_DhcpClientResult(ok=True, message=DPlane_message)
