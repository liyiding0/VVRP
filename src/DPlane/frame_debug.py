from __future__ import annotations

import threading
from dataclasses import dataclass

from src.ARP import ArpPacketError, ArpProtocol, get_arp_table
from src.CCmd.models import CliContext
from src.DPlane.backend import DPlane_create_backend
from src.DPlane.models import DPlane_Backend, DPlane_PacketDevice
from src.ETHERNET import ETHERTYPE_ARP, debug_ethernet_frame, parse_ethernet_ii_frame
from src.ETHERNET.frame import EthernetFrameError
from src.IFNET.admin import InterfaceAdminProvider
from src.IFNET.discovery import InterfaceDiscoveryError, InterfaceProvider
from src.IFNET.imports import imported_interfaces
from src.IFNET.inventory import get_ifnet_manager
from src.IFNET.models import NetworkInterface


DEFAULT_FRAME_DEBUG_FILTER = "ether proto 0x0800 or ether proto 0x0806 or ether proto 0x86dd"


@dataclass(frozen=True)
class FrameDebugPortBinding:
    interface: NetworkInterface
    device: DPlane_PacketDevice
    host_mac_address: str


class DplaneEthernetFrameDebugService:
    def __init__(
        self,
        ifnet_provider: InterfaceProvider | None = None,
        ifnet_admin_provider: InterfaceAdminProvider | None = None,
        dplane_backend: DPlane_Backend | None = None,
        port_factory=None,
        packet_filter: str = DEFAULT_FRAME_DEBUG_FILTER,
    ) -> None:
        self.ifnet_provider = ifnet_provider
        self.ifnet_admin_provider = ifnet_admin_provider
        self.dplane_backend = dplane_backend or DPlane_create_backend(
            DPlane_ifnet_provider=ifnet_provider,
            DPlane_admin_provider=ifnet_admin_provider,
        )
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
            port = self.port_factory(binding.device)
            session = _FrameDebugSession(
                ctx,
                binding.interface,
                binding.host_mac_address,
                port,
                self.packet_filter,
            )
            session.start()
            self._sessions[binding.interface.name] = session
            started += 1

        if not bindings:
            return "no imported DPlane packet interfaces"
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
            devices = self.dplane_backend.DPlane_list_packet_devices()
        except (InterfaceDiscoveryError, RuntimeError) as exc:
            raise RuntimeError(str(exc)) from exc

        output: list[FrameDebugPortBinding] = []
        host_mac_by_name = {interface.name: interface.mac_address for interface in interfaces}
        for interface in imported_interfaces(ctx.state, interfaces):
            device = self.dplane_backend.DPlane_find_packet_device(interface, devices)
            if device is not None:
                output.append(
                    FrameDebugPortBinding(
                        interface=interface,
                        device=device,
                        host_mac_address=host_mac_by_name.get(interface.name, interface.mac_address),
                    )
                )
        return tuple(output)

    def _default_port_factory(self, device: DPlane_PacketDevice):
        return self.dplane_backend.DPlane_open_packet_port(device)


class _FrameDebugSession:
    def __init__(
        self,
        ctx: CliContext,
        interface: NetworkInterface,
        host_mac_address: str,
        port,
        packet_filter: str,
    ) -> None:
        self.ctx = ctx
        self.interface = interface
        self.interface_name = interface.name
        self.host_mac_address = host_mac_address.lower()
        self.port = port
        self.packet_filter = packet_filter
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, name=f"vvrp-eth-debug-{self.interface_name}", daemon=True)

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
                if not _frame_belongs_to_vvrp_interface(frame, self.interface, self.host_mac_address):
                    continue
                _learn_arp_from_frame(self.ctx, self.interface, frame)
                debug_ethernet_frame(self.ctx, self.interface_name, "rx", frame)
        except Exception as exc:
            self.ctx.write(f"% Ethernet frame debug stopped on {self.interface_name}: {exc}")
        finally:
            try:
                self.port.close()
            except Exception:
                pass


def _learn_arp_from_frame(ctx: CliContext, interface: NetworkInterface, frame) -> None:
    if frame.ethertype != ETHERTYPE_ARP:
        return
    try:
        ArpProtocol(get_arp_table(ctx.state)).handle_frame(interface, frame)
    except (ArpPacketError, ValueError):
        return


def _frame_belongs_to_vvrp_interface(frame, interface: NetworkInterface, host_mac_address: str) -> bool:
    vvrp_mac = interface.mac_address.lower()
    host_mac = host_mac_address.lower()
    source = frame.source.lower()
    destination = frame.destination.lower()

    if vvrp_mac == host_mac:
        return True
    if source == host_mac or destination == host_mac:
        return False
    if source == vvrp_mac or destination == vvrp_mac:
        return True
    return _is_group_address(destination)


def _is_group_address(mac_address: str) -> bool:
    try:
        first_octet = int(mac_address.split(":", 1)[0], 16)
    except (ValueError, IndexError):
        return False
    return bool(first_octet & 1)
