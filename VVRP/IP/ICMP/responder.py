from __future__ import annotations

import threading

from VVRP.ARP import ArpPacketError, ArpProtocol, get_arp_table
from VVRP.CCmd.models import CliContext
from VVRP.DPlane.Windows.npcap import (
    NpcapDevice,
    NpcapError,
    NpcapLibrary,
    NpcapPacketPort,
    find_npcap_device_for_interface,
)
from VVRP.ETHERNET import ETHERTYPE_ARP, ETHERTYPE_IPV4, EthernetFrame, debug_ethernet_frame, parse_ethernet_ii_frame
from VVRP.ETHERNET.frame import EthernetFrameError
from VVRP.IFNET.admin import InterfaceAdminProvider
from VVRP.IFNET.discovery import InterfaceDiscoveryError, InterfaceProvider
from VVRP.IFNET.imports import imported_interfaces
from VVRP.IFNET.inventory import get_ifnet_manager
from VVRP.IFNET.models import NetworkInterface
from VVRP.IFNET.state import is_admin_down
from .ping import IPV4_PROTOCOL_ICMP, build_ipv4_packet, parse_ipv4_packet

from .packet import build_icmp_echo_reply, parse_icmp_echo


ICMP_RESPONDER_FILTER = "ether proto 0x0806 or ether proto 0x0800"


class IcmpResponderService:
    def __init__(
        self,
        ifnet_provider: InterfaceProvider | None = None,
        ifnet_admin_provider: InterfaceAdminProvider | None = None,
        npcap_library: NpcapLibrary | None = None,
        port_factory=None,
    ) -> None:
        self.ifnet_provider = ifnet_provider
        self.ifnet_admin_provider = ifnet_admin_provider
        self.npcap_library = npcap_library
        self.port_factory = port_factory or self._default_port_factory
        self._sessions: dict[str, _IcmpResponderSession] = {}

    def refresh(self, ctx: CliContext) -> str:
        self.stop()
        try:
            bindings = self._bindings(ctx)
        except (InterfaceDiscoveryError, NpcapError) as exc:
            return f"ICMP responder refresh failed: {exc}"

        for interface, device in bindings:
            port = self.port_factory(device.name)
            session = _IcmpResponderSession(ctx, interface, port)
            session.start()
            self._sessions[interface.name] = session
        if not bindings:
            return "no imported IPv4 Ethernet interfaces"
        return f"{len(bindings)} listener(s) running"

    def stop(self) -> None:
        for session in tuple(self._sessions.values()):
            session.stop()
        self._sessions.clear()

    def _bindings(self, ctx: CliContext) -> tuple[tuple[NetworkInterface, NpcapDevice], ...]:
        interfaces = get_ifnet_manager(
            ctx.state,
            provider=self.ifnet_provider,
            admin_provider=self.ifnet_admin_provider,
        ).list_interfaces()
        devices = (self.npcap_library or NpcapLibrary()).list_devices()
        output: list[tuple[NetworkInterface, NpcapDevice]] = []
        for interface in imported_interfaces(ctx.state, interfaces):
            if (
                interface.kind != "ethernet"
                or not interface.is_up
                or is_admin_down(ctx.state, interface.name)
                or not interface.addresses_by_family("ipv4")
            ):
                continue
            device = find_npcap_device_for_interface(interface, devices)
            if device is not None:
                output.append((interface, device))
        return tuple(output)

    def _default_port_factory(self, device_name: str):
        return NpcapPacketPort(device_name, library=self.npcap_library)


class _IcmpResponderSession:
    def __init__(self, ctx: CliContext, interface: NetworkInterface, port) -> None:
        self.ctx = ctx
        self.interface = interface
        self.port = port
        self.stop_event = threading.Event()
        self.thread = threading.Thread(
            target=self._run,
            name=f"vvrp-icmp-responder-{interface.name}",
            daemon=True,
        )

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
            self.port.set_filter(ICMP_RESPONDER_FILTER)
            while not self.stop_event.is_set():
                raw = self.port.recv_frame()
                if raw is None:
                    continue
                try:
                    frame = parse_ethernet_ii_frame(raw)
                except EthernetFrameError:
                    continue
                if not _frame_belongs_to_interface(frame, self.interface):
                    continue
                if frame.ethertype == ETHERTYPE_ARP:
                    self._handle_arp(frame)
                elif frame.ethertype == ETHERTYPE_IPV4:
                    self._handle_ipv4(frame)
        except Exception as exc:
            self.ctx.write(f"% ICMP responder stopped on {self.interface.name}: {exc}")
        finally:
            try:
                self.port.close()
            except Exception:
                pass

    def _handle_arp(self, frame: EthernetFrame) -> None:
        try:
            reply = ArpProtocol(get_arp_table(self.ctx.state)).handle_frame(self.interface, frame)
        except (ArpPacketError, ValueError):
            return
        if reply is None:
            return
        debug_ethernet_frame(self.ctx, self.interface.name, "tx", reply)
        self.port.send_frame(reply.to_bytes(pad=True))

    def _handle_ipv4(self, frame: EthernetFrame) -> None:
        try:
            packet = parse_ipv4_packet(frame.payload)
        except ValueError:
            return
        if packet.protocol != IPV4_PROTOCOL_ICMP:
            return
        if packet.destination not in _interface_ipv4_addresses(self.interface):
            return
        echo = parse_icmp_echo(packet.payload)
        if echo is None or not echo.is_echo_request:
            return
        payload = build_icmp_echo_reply(echo.identifier, echo.sequence, echo.payload)
        reply_packet = build_ipv4_packet(
            packet.destination,
            packet.source,
            IPV4_PROTOCOL_ICMP,
            payload,
            ttl=255,
        )
        reply_frame = EthernetFrame(
            destination=frame.source,
            source=self.interface.mac_address,
            ethertype=ETHERTYPE_IPV4,
            payload=reply_packet,
        )
        debug_ethernet_frame(self.ctx, self.interface.name, "tx", reply_frame)
        self.port.send_frame(reply_frame.to_bytes(pad=True))


def _interface_ipv4_addresses(interface: NetworkInterface) -> frozenset[str]:
    return frozenset(address.address for address in interface.addresses_by_family("ipv4"))


def _frame_belongs_to_interface(frame: EthernetFrame, interface: NetworkInterface) -> bool:
    mac = interface.mac_address.lower()
    source = frame.source.lower()
    destination = frame.destination.lower()
    return source != mac and (destination == mac or _is_group_address(destination))


def _is_group_address(mac_address: str) -> bool:
    try:
        first_octet = int(mac_address.split(":", 1)[0], 16)
    except (ValueError, IndexError):
        return False
    return bool(first_octet & 1)
