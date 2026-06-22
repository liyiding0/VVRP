from __future__ import annotations

from src.IFNET.admin import InterfaceAdminProvider, OsInterfaceAdminProvider
from src.IFNET.discovery import InterfaceProvider, discover_interfaces
from src.IFNET.models import NetworkInterface

from .models import DPlane_Backend, DPlane_PacketDevice, DPlane_PlatformInfo, DPlane_Result
from .platform import DPlane_detect_platform


class DPlane_UnsupportedBackend:
    def __init__(self, DPlane_platform: DPlane_PlatformInfo | None = None) -> None:
        self._DPlane_platform = DPlane_platform or DPlane_detect_platform()

    @property
    def DPlane_platform(self) -> DPlane_PlatformInfo:
        return self._DPlane_platform

    def DPlane_list_host_interfaces(self) -> tuple[NetworkInterface, ...]:
        raise RuntimeError(f"unsupported DPlane platform: {self.DPlane_platform.kind}")

    def DPlane_list_packet_devices(self) -> tuple[DPlane_PacketDevice, ...]:
        raise RuntimeError(f"unsupported DPlane platform: {self.DPlane_platform.kind}")

    def DPlane_find_packet_device(
        self,
        DPlane_interface: NetworkInterface,
        DPlane_devices: tuple[DPlane_PacketDevice, ...] | None = None,
    ) -> DPlane_PacketDevice | None:
        return None

    def DPlane_open_packet_port(self, DPlane_device: DPlane_PacketDevice):
        raise RuntimeError(f"unsupported DPlane platform: {self.DPlane_platform.kind}")

    def DPlane_set_interface_enabled(
        self,
        DPlane_interface: NetworkInterface,
        DPlane_enabled: bool,
    ) -> DPlane_Result:
        return DPlane_Result(
            ok=False,
            message=f"% unsupported DPlane platform: {self.DPlane_platform.kind}",
        )


class DPlane_InterfaceProviderAdapter:
    def __init__(self, DPlane_backend: DPlane_Backend) -> None:
        self.DPlane_backend = DPlane_backend

    def list_interfaces(self) -> tuple[NetworkInterface, ...]:
        return self.DPlane_backend.DPlane_list_host_interfaces()


class DPlane_AdminProviderAdapter:
    def __init__(self, DPlane_backend: DPlane_Backend) -> None:
        self.DPlane_backend = DPlane_backend

    def shutdown(self, interface: NetworkInterface):
        from src.IFNET.admin import InterfaceAdminResult

        DPlane_result = self.DPlane_backend.DPlane_set_interface_enabled(interface, False)
        return InterfaceAdminResult(ok=DPlane_result.ok, message=DPlane_result.message)

    def no_shutdown(self, interface: NetworkInterface):
        from src.IFNET.admin import InterfaceAdminResult

        DPlane_result = self.DPlane_backend.DPlane_set_interface_enabled(interface, True)
        return InterfaceAdminResult(ok=DPlane_result.ok, message=DPlane_result.message)


class DPlane_LegacyHostBackend:
    def __init__(
        self,
        DPlane_ifnet_provider: InterfaceProvider | None = None,
        DPlane_admin_provider: InterfaceAdminProvider | None = None,
    ) -> None:
        self.DPlane_ifnet_provider = DPlane_ifnet_provider
        self.DPlane_admin_provider = DPlane_admin_provider or OsInterfaceAdminProvider()
        self._DPlane_platform = DPlane_detect_platform()

    @property
    def DPlane_platform(self) -> DPlane_PlatformInfo:
        return self._DPlane_platform

    def DPlane_list_host_interfaces(self) -> tuple[NetworkInterface, ...]:
        return discover_interfaces(self.DPlane_ifnet_provider)

    def DPlane_set_interface_enabled(
        self,
        DPlane_interface: NetworkInterface,
        DPlane_enabled: bool,
    ) -> DPlane_Result:
        if DPlane_enabled:
            DPlane_result = self.DPlane_admin_provider.no_shutdown(DPlane_interface)
        else:
            DPlane_result = self.DPlane_admin_provider.shutdown(DPlane_interface)
        return DPlane_Result(ok=DPlane_result.ok, message=DPlane_result.message)


def DPlane_create_backend(
    DPlane_ifnet_provider: InterfaceProvider | None = None,
    DPlane_admin_provider: InterfaceAdminProvider | None = None,
    DPlane_npcap_library=None,
) -> DPlane_Backend:
    DPlane_platform = DPlane_detect_platform()
    if DPlane_platform.kind == "windows":
        from .Windows.npcap import DPlane_WindowsNpcapBackend

        return DPlane_WindowsNpcapBackend(
            DPlane_ifnet_provider=DPlane_ifnet_provider,
            DPlane_admin_provider=DPlane_admin_provider,
            DPlane_npcap_library=DPlane_npcap_library,
            DPlane_platform=DPlane_platform,
        )
    if DPlane_platform.kind in {"linux", "openwrt"}:
        from .Linux.raw_socket import DPlane_LinuxRawSocketBackend

        return DPlane_LinuxRawSocketBackend(
            DPlane_ifnet_provider=DPlane_ifnet_provider,
            DPlane_admin_provider=DPlane_admin_provider,
            DPlane_platform=DPlane_platform,
        )
    return DPlane_UnsupportedBackend(DPlane_platform)
