from __future__ import annotations

import threading
from dataclasses import dataclass

from VVRP.CCmd.models import CliContext
from VVRP.ETHERNET import debug_ethernet_frame, parse_ethernet_ii_frame
from VVRP.ETHERNET.frame import EthernetFrameError
from VVRP.IFNET.admin import InterfaceAdminProvider
from VVRP.IFNET.discovery import InterfaceDiscoveryError, InterfaceProvider
from VVRP.IFNET.imports import imported_interfaces
from VVRP.IFNET.inventory import get_ifnet_manager
from VVRP.IFNET.models import NetworkInterface

from .Windows.npcap import NpcapDevice, NpcapError, NpcapLibrary, NpcapPacketPort, find_npcap_device_for_interface


DEFAULT_FRAME_DEBUG_FILTER = "ether proto 0x0800 or ether proto 0x0806 or ether proto 0x86dd"


@dataclass(frozen=True)
class FrameDebugPortBinding:
    interface: NetworkInterface
    device: NpcapDevice


class DplaneEthernetFrameDebugService:
    def __init__(
        self,
        ifnet_provider: InterfaceProvider | None = None,
        ifnet_admin_provider: InterfaceAdminProvider | None = None,
        npcap_library: NpcapLibrary | None = None,
        port_factory=None,
        packet_filter: str = DEFAULT_FRAME_DEBUG_FILTER,
    ) -> None:
        self.ifnet_provider = ifnet_provider
        self.ifnet_admin_provider = ifnet_admin_provider
        self.npcap_library = npcap_library
        self.port_factory = port_factory or self._default_port_factory
        self.packet_filter = packet_filter
        self._sessions: dict[str, _FrameDebugSession] = {}

    def start(self, ctx: CliContext) -> str:
        bindings = self._bindings(ctx)
        active_names = {binding.interface.name for binding in bindings}
        for name in tuple(self._sessions):
            if name not in active_names:
                self._sessions.pop(name).stop()

        started = 0
        for binding in bindings:
            if binding.interface.name in self._sessions:
                continue
            port = self.port_factory(binding.device.name)
            session = _FrameDebugSession(ctx, binding.interface.name, port, self.packet_filter)
            session.start()
            self._sessions[binding.interface.name] = session
            started += 1

        if not bindings:
            return "no imported Npcap interfaces"
        if started == 0:
            return f"{len(self._sessions)} listener(s) already running"
        return f"{len(self._sessions)} listener(s) running"

    def stop(self) -> str:
        count = len(self._sessions)
        for session in tuple(self._sessions.values()):
            session.stop()
        self._sessions.clear()
        if count == 0:
            return "no listeners were running"
        return f"{count} listener(s) stopped"

    def status(self) -> str:
        if not self._sessions:
            return "no listeners running"
        names = ", ".join(sorted(self._sessions))
        return f"listeners running on {names}"

    def _bindings(self, ctx: CliContext) -> tuple[FrameDebugPortBinding, ...]:
        try:
            interfaces = get_ifnet_manager(
                ctx.state,
                provider=self.ifnet_provider,
                admin_provider=self.ifnet_admin_provider,
            ).list_interfaces()
            devices = (self.npcap_library or NpcapLibrary()).list_devices()
        except (InterfaceDiscoveryError, NpcapError) as exc:
            raise RuntimeError(str(exc)) from exc

        output: list[FrameDebugPortBinding] = []
        for interface in imported_interfaces(ctx.state, interfaces):
            device = find_npcap_device_for_interface(interface, devices)
            if device is not None:
                output.append(FrameDebugPortBinding(interface=interface, device=device))
        return tuple(output)

    def _default_port_factory(self, device_name: str):
        return NpcapPacketPort(device_name, library=self.npcap_library)


class _FrameDebugSession:
    def __init__(self, ctx: CliContext, interface_name: str, port, packet_filter: str) -> None:
        self.ctx = ctx
        self.interface_name = interface_name
        self.port = port
        self.packet_filter = packet_filter
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, name=f"vvrp-eth-debug-{interface_name}", daemon=True)

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        try:
            self.port.close()
        except Exception:
            pass

    def _run(self) -> None:
        try:
            self.port.open()
            if self.packet_filter:
                self.port.set_filter(self.packet_filter)
            while not self.stop_event.is_set():
                raw = self.port.recv_frame()
                if raw is None:
                    continue
                try:
                    frame = parse_ethernet_ii_frame(raw)
                except EthernetFrameError:
                    continue
                debug_ethernet_frame(self.ctx, self.interface_name, "rx", frame)
        except Exception as exc:
            self.ctx.write(f"% Ethernet frame debug stopped on {self.interface_name}: {exc}")
        finally:
            try:
                self.port.close()
            except Exception:
                pass
