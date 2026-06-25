from __future__ import annotations

import threading
from collections.abc import Callable

from src.CCmd.models import CliContext
from src.DPlane.backend import DPlane_create_backend
from src.DPlane.models import DPlane_Backend, DPlane_PacketDevice
from src.IFNET.admin import InterfaceAdminProvider
from src.IFNET.discovery import InterfaceDiscoveryError, InterfaceProvider
from src.IFNET.imports import imported_interfaces
from src.IFNET.inventory import get_ifnet_manager
from src.IFNET.models import NetworkInterface
from src.IFNET.state import is_admin_down


g_DPLANE_PACKET_INPUT_FILTER = "ether proto 0x0806 or ether proto 0x0800"
g_DPLANE_PACKET_INPUT_STOP_JOIN_TIMEOUT_SECONDS = 1.0


class DPlane_PacketInputService:
    def __init__(
        self,
        DPlane_ifnet_provider: InterfaceProvider | None = None,
        DPlane_ifnet_admin_provider: InterfaceAdminProvider | None = None,
        DPlane_backend: DPlane_Backend | None = None,
        DPlane_port_factory=None,
        DPlane_frame_handler_factory: Callable[[CliContext, object], object] | None = None,
    ) -> None:
        self.DPlane_ifnet_provider = DPlane_ifnet_provider
        self.DPlane_ifnet_admin_provider = DPlane_ifnet_admin_provider
        self.DPlane_backend = DPlane_backend or DPlane_create_backend(
            DPlane_ifnet_provider=DPlane_ifnet_provider,
            DPlane_admin_provider=DPlane_ifnet_admin_provider,
        )
        self.DPlane_port_factory = DPlane_port_factory or self._DPlane_default_port_factory
        self.DPlane_frame_handler_factory = (
            DPlane_frame_handler_factory or self._DPlane_default_frame_handler_factory
        )
        self.DPlane_sessions: dict[str, _DPlane_PacketInputSession] = {}

    def DPlane_refresh(self, DPlane_ctx: CliContext) -> str:
        self.DPlane_stop()
        try:
            DPlane_bindings = self._DPlane_bindings(DPlane_ctx)
        except (InterfaceDiscoveryError, RuntimeError) as DPlane_exc:
            return f"DPlane packet input refresh failed: {DPlane_exc}"

        for DPlane_interface, DPlane_device in DPlane_bindings:
            DPlane_port = self.DPlane_port_factory(DPlane_device)
            DPlane_frame_handler = self.DPlane_frame_handler_factory(DPlane_ctx, DPlane_port)
            DPlane_session = _DPlane_PacketInputSession(
                DPlane_ctx,
                DPlane_interface,
                DPlane_port,
                DPlane_frame_handler,
            )
            DPlane_session.DPlane_start()
            self.DPlane_sessions[DPlane_interface.name] = DPlane_session
        if not DPlane_bindings:
            return "no imported IPv4 Ethernet interfaces"
        return f"{len(DPlane_bindings)} listener(s) running"

    def DPlane_stop(self) -> None:
        for DPlane_session in tuple(self.DPlane_sessions.values()):
            DPlane_session.DPlane_stop()
        self.DPlane_sessions.clear()

    def _DPlane_bindings(
        self,
        DPlane_ctx: CliContext,
    ) -> tuple[tuple[NetworkInterface, DPlane_PacketDevice], ...]:
        DPlane_interfaces = get_ifnet_manager(
            DPlane_ctx.state,
            provider=self.DPlane_ifnet_provider,
            admin_provider=self.DPlane_ifnet_admin_provider,
        ).list_interfaces()
        DPlane_devices = self.DPlane_backend.DPlane_list_packet_devices()
        DPlane_output: list[tuple[NetworkInterface, DPlane_PacketDevice]] = []
        for DPlane_interface in imported_interfaces(DPlane_ctx.state, DPlane_interfaces):
            if (
                DPlane_interface.kind != "ethernet"
                or not DPlane_interface.is_up
                or is_admin_down(DPlane_ctx.state, DPlane_interface.name)
                or not DPlane_interface.addresses_by_family("ipv4")
            ):
                continue
            DPlane_device = self.DPlane_backend.DPlane_find_packet_device(DPlane_interface, DPlane_devices)
            if DPlane_device is not None:
                DPlane_output.append((DPlane_interface, DPlane_device))
        return tuple(DPlane_output)

    def _DPlane_default_port_factory(self, DPlane_device: DPlane_PacketDevice):
        return self.DPlane_backend.DPlane_open_packet_port(DPlane_device)

    def _DPlane_default_frame_handler_factory(self, DPlane_ctx: CliContext, DPlane_port):
        from src.FWD import FWD_default_input_dispatcher

        return FWD_default_input_dispatcher(
            DPlane_ctx,
            FWD_ethernet_send_frame=DPlane_port.send_frame,
        )


class _DPlane_PacketInputSession:
    def __init__(
        self,
        DPlane_ctx: CliContext,
        DPlane_interface: NetworkInterface,
        DPlane_port,
        DPlane_frame_handler,
    ) -> None:
        self.DPlane_ctx = DPlane_ctx
        self.DPlane_interface = DPlane_interface
        self.DPlane_port = DPlane_port
        self.DPlane_frame_handler = DPlane_frame_handler
        self.DPlane_stop_event = threading.Event()
        self.DPlane_thread = threading.Thread(
            target=self._DPlane_run,
            name=f"vvrp-dplane-input-{DPlane_interface.name}",
            daemon=True,
        )

    def DPlane_start(self) -> None:
        self.DPlane_thread.start()

    def DPlane_stop(self) -> None:
        self.DPlane_stop_event.set()
        try:
            self.DPlane_port.close()
        except Exception:
            pass
        if threading.current_thread() is not self.DPlane_thread:
            self.DPlane_thread.join(g_DPLANE_PACKET_INPUT_STOP_JOIN_TIMEOUT_SECONDS)

    def _DPlane_run(self) -> None:
        try:
            self.DPlane_port.open()
            self.DPlane_port.set_filter(g_DPLANE_PACKET_INPUT_FILTER)
            while not self.DPlane_stop_event.is_set():
                DPlane_raw = self.DPlane_port.recv_frame()
                if DPlane_raw is None:
                    continue
                self.DPlane_frame_handler.FWD_handle_frame(
                    self.DPlane_interface,
                    DPlane_raw,
                )
        except Exception as DPlane_exc:
            if not self.DPlane_stop_event.is_set():
                self.DPlane_ctx.write(
                    f"% DPlane packet input stopped on {self.DPlane_interface.name}: {DPlane_exc}"
                )
        finally:
            try:
                self.DPlane_port.close()
            except Exception:
                pass

