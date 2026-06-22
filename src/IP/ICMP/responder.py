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

from .packet import ICMP_build_echo_reply, ICMP_parse_echo
from .ping import g_ICMP_IPV4_PROTOCOL_ICMP, ICMP_build_ipv4_packet, ICMP_parse_ipv4_packet


g_ICMP_RESPONDER_FILTER = "ether proto 0x0806 or ether proto 0x0800"


class ICMP_ResponderService:
    def __init__(
        self,
        ICMP_ifnet_provider: InterfaceProvider | None = None,
        ICMP_ifnet_admin_provider: InterfaceAdminProvider | None = None,
        ICMP_npcap_library: NpcapLibrary | None = None,
        ICMP_port_factory=None,
    ) -> None:
        self.ICMP_ifnet_provider = ICMP_ifnet_provider
        self.ICMP_ifnet_admin_provider = ICMP_ifnet_admin_provider
        self.ICMP_npcap_library = ICMP_npcap_library
        self.ICMP_port_factory = ICMP_port_factory or self._ICMP_default_port_factory
        self.ICMP_sessions: dict[str, _ICMP_ResponderSession] = {}

    def ICMP_refresh(self, ICMP_ctx: CliContext) -> str:
        self.ICMP_stop()
        try:
            ICMP_bindings = self._ICMP_bindings(ICMP_ctx)
        except (InterfaceDiscoveryError, NpcapError) as ICMP_exc:
            return f"ICMP responder refresh failed: {ICMP_exc}"

        for ICMP_interface, ICMP_device in ICMP_bindings:
            ICMP_port = self.ICMP_port_factory(ICMP_device.name)
            ICMP_session = _ICMP_ResponderSession(ICMP_ctx, ICMP_interface, ICMP_port)
            ICMP_session.ICMP_start()
            self.ICMP_sessions[ICMP_interface.name] = ICMP_session
        if not ICMP_bindings:
            return "no imported IPv4 Ethernet interfaces"
        return f"{len(ICMP_bindings)} listener(s) running"

    def ICMP_stop(self) -> None:
        for ICMP_session in tuple(self.ICMP_sessions.values()):
            ICMP_session.ICMP_stop()
        self.ICMP_sessions.clear()

    def _ICMP_bindings(
        self,
        ICMP_ctx: CliContext,
    ) -> tuple[tuple[NetworkInterface, NpcapDevice], ...]:
        ICMP_interfaces = get_ifnet_manager(
            ICMP_ctx.state,
            provider=self.ICMP_ifnet_provider,
            admin_provider=self.ICMP_ifnet_admin_provider,
        ).list_interfaces()
        ICMP_devices = (self.ICMP_npcap_library or NpcapLibrary()).list_devices()
        ICMP_output: list[tuple[NetworkInterface, NpcapDevice]] = []
        for ICMP_interface in imported_interfaces(ICMP_ctx.state, ICMP_interfaces):
            if (
                ICMP_interface.kind != "ethernet"
                or not ICMP_interface.is_up
                or is_admin_down(ICMP_ctx.state, ICMP_interface.name)
                or not ICMP_interface.addresses_by_family("ipv4")
            ):
                continue
            ICMP_device = find_npcap_device_for_interface(ICMP_interface, ICMP_devices)
            if ICMP_device is not None:
                ICMP_output.append((ICMP_interface, ICMP_device))
        return tuple(ICMP_output)

    def _ICMP_default_port_factory(self, ICMP_device_name: str):
        return NpcapPacketPort(ICMP_device_name, library=self.ICMP_npcap_library)


class _ICMP_ResponderSession:
    def __init__(self, ICMP_ctx: CliContext, ICMP_interface: NetworkInterface, ICMP_port) -> None:
        self.ICMP_ctx = ICMP_ctx
        self.ICMP_interface = ICMP_interface
        self.ICMP_port = ICMP_port
        self.ICMP_stop_event = threading.Event()
        self.ICMP_thread = threading.Thread(
            target=self._ICMP_run,
            name=f"vvrp-icmp-responder-{ICMP_interface.name}",
            daemon=True,
        )

    def ICMP_start(self) -> None:
        self.ICMP_thread.start()

    def ICMP_stop(self) -> None:
        self.ICMP_stop_event.set()
        try:
            self.ICMP_port.close()
        except Exception:
            pass

    def _ICMP_run(self) -> None:
        try:
            self.ICMP_port.open()
            self.ICMP_port.set_filter(g_ICMP_RESPONDER_FILTER)
            while not self.ICMP_stop_event.is_set():
                ICMP_raw = self.ICMP_port.recv_frame()
                if ICMP_raw is None:
                    continue
                try:
                    ICMP_frame = parse_ethernet_ii_frame(ICMP_raw)
                except EthernetFrameError:
                    continue
                if not _ICMP_frame_belongs_to_interface(ICMP_frame, self.ICMP_interface):
                    continue
                if ICMP_frame.ethertype == ETHERTYPE_ARP:
                    self._ICMP_handle_arp(ICMP_frame)
                elif ICMP_frame.ethertype == ETHERTYPE_IPV4:
                    self._ICMP_handle_ipv4(ICMP_frame)
        except Exception as ICMP_exc:
            self.ICMP_ctx.write(f"% ICMP responder stopped on {self.ICMP_interface.name}: {ICMP_exc}")
        finally:
            try:
                self.ICMP_port.close()
            except Exception:
                pass

    def _ICMP_handle_arp(self, ICMP_frame: EthernetFrame) -> None:
        try:
            ICMP_reply = ArpProtocol(get_arp_table(self.ICMP_ctx.state)).handle_frame(
                self.ICMP_interface,
                ICMP_frame,
            )
        except (ArpPacketError, ValueError):
            return
        if ICMP_reply is None:
            return
        debug_ethernet_frame(self.ICMP_ctx, self.ICMP_interface.name, "tx", ICMP_reply)
        self.ICMP_port.send_frame(ICMP_reply.to_bytes(pad=True))

    def _ICMP_handle_ipv4(self, ICMP_frame: EthernetFrame) -> None:
        try:
            ICMP_packet = ICMP_parse_ipv4_packet(ICMP_frame.payload)
        except ValueError:
            return
        if ICMP_packet.ICMP_protocol != g_ICMP_IPV4_PROTOCOL_ICMP:
            return
        if ICMP_packet.ICMP_destination not in _ICMP_interface_ipv4_addresses(self.ICMP_interface):
            return
        ICMP_echo = ICMP_parse_echo(ICMP_packet.ICMP_payload)
        if ICMP_echo is None or not ICMP_echo.ICMP_is_echo_request:
            return
        ICMP_payload = ICMP_build_echo_reply(
            ICMP_echo.ICMP_identifier,
            ICMP_echo.ICMP_sequence,
            ICMP_echo.ICMP_payload,
        )
        ICMP_reply_packet = ICMP_build_ipv4_packet(
            ICMP_packet.ICMP_destination,
            ICMP_packet.ICMP_source,
            g_ICMP_IPV4_PROTOCOL_ICMP,
            ICMP_payload,
            ICMP_ttl=255,
        )
        ICMP_reply_frame = EthernetFrame(
            destination=ICMP_frame.source,
            source=self.ICMP_interface.mac_address,
            ethertype=ETHERTYPE_IPV4,
            payload=ICMP_reply_packet,
        )
        debug_ethernet_frame(self.ICMP_ctx, self.ICMP_interface.name, "tx", ICMP_reply_frame)
        self.ICMP_port.send_frame(ICMP_reply_frame.to_bytes(pad=True))


def _ICMP_interface_ipv4_addresses(ICMP_interface: NetworkInterface) -> frozenset[str]:
    return frozenset(
        ICMP_address.address
        for ICMP_address in ICMP_interface.addresses_by_family("ipv4")
    )


def _ICMP_frame_belongs_to_interface(
    ICMP_frame: EthernetFrame,
    ICMP_interface: NetworkInterface,
) -> bool:
    ICMP_mac = ICMP_interface.mac_address.lower()
    ICMP_source = ICMP_frame.source.lower()
    ICMP_destination = ICMP_frame.destination.lower()
    return ICMP_source != ICMP_mac and (
        ICMP_destination == ICMP_mac or _ICMP_is_group_address(ICMP_destination)
    )


def _ICMP_is_group_address(ICMP_mac_address: str) -> bool:
    try:
        ICMP_first_octet = int(ICMP_mac_address.split(":", 1)[0], 16)
    except (ValueError, IndexError):
        return False
    return bool(ICMP_first_octet & 1)
