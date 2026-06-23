from __future__ import annotations

from src.IFNET.admin import InterfaceAdminResult
from src.IFNET.models import NetworkInterface


class DPlane_InterfaceAdminProvider:
    def __init__(self, DPlane_backend=None, system: str | None = None) -> None:
        if DPlane_backend is None and system is None:
            from src.DPlane import DPlane_create_backend

            DPlane_backend = DPlane_create_backend()
        self.DPlane_backend = DPlane_backend
        self.DPlane_system = system

    def shutdown(self, interface: NetworkInterface) -> InterfaceAdminResult:
        if interface.kind != "ethernet":
            return InterfaceAdminResult(
                ok=False,
                message=f"% Unsupported interface type for shutdown: {interface.kind}",
            )
        DPlane_result = self._DPlane_set_interface_enabled(interface, False)
        return InterfaceAdminResult(ok=DPlane_result.ok, message=DPlane_result.message)

    def no_shutdown(self, interface: NetworkInterface) -> InterfaceAdminResult:
        if interface.kind != "ethernet":
            return InterfaceAdminResult(
                ok=False,
                message=f"% Unsupported interface type for no shutdown: {interface.kind}",
            )
        DPlane_result = self._DPlane_set_interface_enabled(interface, True)
        return InterfaceAdminResult(ok=DPlane_result.ok, message=DPlane_result.message)

    def _DPlane_set_interface_enabled(
        self,
        DPlane_interface: NetworkInterface,
        DPlane_enabled: bool,
    ):
        if self.DPlane_system is None:
            return self.DPlane_backend.DPlane_set_interface_enabled(DPlane_interface, DPlane_enabled)
        return DPlane_set_interface_enabled(
            DPlane_interface,
            DPlane_enabled,
            self.DPlane_system.lower(),
        )


def DPlane_set_interface_enabled(
    DPlane_interface: NetworkInterface,
    DPlane_enabled: bool,
    DPlane_platform_kind: str,
):
    from src.DPlane.models import DPlane_Result

    try:
        if DPlane_platform_kind == "windows":
            from src.DPlane.Windows.interface_windows import set_windows_network_adapter_enabled

            set_windows_network_adapter_enabled(DPlane_interface, DPlane_enabled)
        elif DPlane_platform_kind in {"linux", "openwrt"}:
            from src.DPlane.Linux.raw_socket import DPlane_set_linux_interface_enabled

            DPlane_set_linux_interface_enabled(DPlane_interface, DPlane_enabled)
        else:
            return DPlane_Result(
                ok=False,
                message=f"% unsupported OS API backend: {DPlane_platform_kind}",
            )
    except PermissionError as DPlane_exc:
        return DPlane_Result(ok=False, message=f"% permission denied: {DPlane_exc}")
    except OSError as DPlane_exc:
        return DPlane_Result(ok=False, message=f"% OS interface API failed: {DPlane_exc}")
    return DPlane_Result(ok=True)
