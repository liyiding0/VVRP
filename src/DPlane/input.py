from __future__ import annotations

import threading

from src.ARP import ArpPacketError, ArpProtocol, get_arp_table
from src.CCmd.models import CliContext
from src.DPlane.Windows.npcap import (
    NpcapDevice,
    NpcapError,
    NpcapLibrary,
    NpcapPacketPort,
    find_npcap_device_for_interface,
)
from src.ETHERNET import (
    ETHERTYPE_ARP,
    ETHERTYPE_IPV4,
    EthernetFrame,
    debug_ethernet_frame,
    parse_ethernet_ii_frame,
)
from src.ETHERNET.frame import EthernetFrameError
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
        DPlane_npcap_library: NpcapLibrary | None = None,
        DPlane_port_factory=None,
    ) -> None:
        self.DPlane_ifnet_provider = DPlane_ifnet_provider
        self.DPlane_ifnet_admin_provider = DPlane_ifnet_admin_provider
        self.DPlane_npcap_library = DPlane_npcap_library
        self.DPlane_port_factory = DPlane_port_factory or self._DPlane_default_port_factory
        self.DPlane_sessions: dict[str, _DPlane_PacketInputSession] = {}

    def DPlane_refresh(self, DPlane_ctx: CliContext) -> str:
        self.DPlane_stop()
        try:
            DPlane_bindings = self._DPlane_bindings(DPlane_ctx)
        except (InterfaceDiscoveryError, NpcapError) as DPlane_exc:
            return f"DPlane packet input refresh failed: {DPlane_exc}"

        for DPlane_interface, DPlane_device in DPlane_bindings:
            DPlane_port = self.DPlane_port_factory(DPlane_device.name)
            DPlane_session = _DPlane_PacketInputSession(DPlane_ctx, DPlane_interface, DPlane_port)
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
    ) -> tuple[tuple[NetworkInterface, NpcapDevice], ...]:
        DPlane_interfaces = get_ifnet_manager(
            DPlane_ctx.state,
            provider=self.DPlane_ifnet_provider,
            admin_provider=self.DPlane_ifnet_admin_provider,
        ).list_interfaces()
        DPlane_devices = (self.DPlane_npcap_library or NpcapLibrary()).list_devices()
        DPlane_output: list[tuple[NetworkInterface, NpcapDevice]] = []
        for DPlane_interface in imported_interfaces(DPlane_ctx.state, DPlane_interfaces):
            if (
                DPlane_interface.kind != "ethernet"
                or not DPlane_interface.is_up
                or is_admin_down(DPlane_ctx.state, DPlane_interface.name)
                or not DPlane_interface.addresses_by_family("ipv4")
            ):
                continue
            DPlane_device = find_npcap_device_for_interface(DPlane_interface, DPlane_devices)
            if DPlane_device is not None:
                DPlane_output.append((DPlane_interface, DPlane_device))
        return tuple(DPlane_output)

    def _DPlane_default_port_factory(self, DPlane_device_name: str):
        return NpcapPacketPort(DPlane_device_name, library=self.DPlane_npcap_library)


class _DPlane_PacketInputSession:
    def __init__(self, DPlane_ctx: CliContext, DPlane_interface: NetworkInterface, DPlane_port) -> None:
        self.DPlane_ctx = DPlane_ctx
        self.DPlane_interface = DPlane_interface
        self.DPlane_port = DPlane_port
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
                try:
                    DPlane_frame = parse_ethernet_ii_frame(DPlane_raw)
                except EthernetFrameError:
                    continue
                if not _DPlane_frame_belongs_to_interface(DPlane_frame, self.DPlane_interface):
                    continue
                if DPlane_frame.ethertype == ETHERTYPE_ARP:
                    self._DPlane_handle_arp(DPlane_frame)
                elif DPlane_frame.ethertype == ETHERTYPE_IPV4:
                    self._DPlane_handle_ipv4(DPlane_frame)
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

    def _DPlane_handle_arp(self, DPlane_frame: EthernetFrame) -> None:
        try:
            DPlane_reply = ArpProtocol(get_arp_table(self.DPlane_ctx.state)).handle_frame(
                self.DPlane_interface,
                DPlane_frame,
            )
        except (ArpPacketError, ValueError):
            return
        if DPlane_reply is None:
            return
        debug_ethernet_frame(self.DPlane_ctx, self.DPlane_interface.name, "tx", DPlane_reply)
        self.DPlane_port.send_frame(DPlane_reply.to_bytes(pad=True))

    def _DPlane_handle_ipv4(self, DPlane_frame: EthernetFrame) -> None:
        from src.IP.ICMP.input import ICMP_handle_ipv4_packet

        DPlane_reply_packet = ICMP_handle_ipv4_packet(self.DPlane_interface, DPlane_frame.payload)
        if DPlane_reply_packet is None:
            return
        DPlane_reply_frame = EthernetFrame(
            destination=DPlane_frame.source,
            source=self.DPlane_interface.mac_address,
            ethertype=ETHERTYPE_IPV4,
            payload=DPlane_reply_packet,
        )
        debug_ethernet_frame(self.DPlane_ctx, self.DPlane_interface.name, "tx", DPlane_reply_frame)
        self.DPlane_port.send_frame(DPlane_reply_frame.to_bytes(pad=True))


def _DPlane_frame_belongs_to_interface(
    DPlane_frame: EthernetFrame,
    DPlane_interface: NetworkInterface,
) -> bool:
    DPlane_mac = DPlane_interface.mac_address.lower()
    DPlane_source = DPlane_frame.source.lower()
    DPlane_destination = DPlane_frame.destination.lower()
    return DPlane_source != DPlane_mac and (
        DPlane_destination == DPlane_mac or _DPlane_is_group_address(DPlane_destination)
    )


def _DPlane_is_group_address(DPlane_mac_address: str) -> bool:
    try:
        DPlane_first_octet = int(DPlane_mac_address.split(":", 1)[0], 16)
    except (ValueError, IndexError):
        return False
    return bool(DPlane_first_octet & 1)
