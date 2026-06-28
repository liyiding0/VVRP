from __future__ import annotations

import threading
import time
from collections.abc import Callable

from src.ARP import ARP_EntryLearned, ArpProtocol, ArpTable, get_arp_table
from src.ARP.packet import ArpPacketError
from src.CCmd.models import CliContext
from src.ETHERNET.debug import debug_ethernet_frame
from src.ETHERNET.frame import (
    ETHERTYPE_ARP,
    ETHERTYPE_IPV4,
    EthernetFrame,
    EthernetFrameError,
    parse_ethernet_ii_frame,
)
from src.FIB import FIBEntry
from src.IFNET.models import NetworkInterface
from src.events import VVRP_event_bus


g_ETHERNET_ARP_RESOLVE_TIMEOUT_SECONDS = 2.0


class ETHERNET_OutputHandler:
    def __init__(
        self,
        ETHERNET_state: dict,
        *,
        ETHERNET_port_provider: Callable[[NetworkInterface], object] | None = None,
        ETHERNET_arp_table: ArpTable | None = None,
        ETHERNET_arp_timeout_seconds: float = g_ETHERNET_ARP_RESOLVE_TIMEOUT_SECONDS,
        ETHERNET_debug_ctx: CliContext | None = None,
    ) -> None:
        self.ETHERNET_state = ETHERNET_state
        self.ETHERNET_port_provider = ETHERNET_port_provider
        self.ETHERNET_arp_table = ETHERNET_arp_table
        self.ETHERNET_arp_timeout_seconds = ETHERNET_arp_timeout_seconds
        self.ETHERNET_debug_ctx = ETHERNET_debug_ctx

    def ETHERNET_send_packet(
        self,
        ETHERNET_packet: bytes,
        ETHERNET_route: FIBEntry,
        ETHERNET_interface: NetworkInterface,
        *,
        ETHERNET_target_ip: str,
    ):
        if self.ETHERNET_port_provider is None:
            return None, "% Ethernet output port is not available"
        ETHERNET_port = self.ETHERNET_port_provider(ETHERNET_interface)
        ETHERNET_arp_entry = self._ETHERNET_resolve_arp(
            ETHERNET_target_ip,
            ETHERNET_interface,
            ETHERNET_port,
            ETHERNET_route.source_ip,
        )
        if ETHERNET_arp_entry is None:
            return None, f"% Ethernet adjacency unresolved: {ETHERNET_target_ip} via {ETHERNET_interface.name}"
        ETHERNET_frame = EthernetFrame(
            destination=ETHERNET_arp_entry.mac_address,
            source=ETHERNET_interface.mac_address,
            ethertype=ETHERTYPE_IPV4,
            payload=ETHERNET_packet,
        )
        ETHERNET_raw_frame = ETHERNET_frame.to_bytes(pad=True)
        debug_ethernet_frame(
            self.ETHERNET_debug_ctx or CliContext(state=self.ETHERNET_state),
            ETHERNET_interface.name,
            "tx",
            ETHERNET_frame,
        )
        ETHERNET_port.send_frame(ETHERNET_raw_frame)
        return ETHERNET_raw_frame, ""

    def _ETHERNET_arp_table(self) -> ArpTable:
        return get_arp_table(self.ETHERNET_state, self.ETHERNET_arp_table)

    def _ETHERNET_resolve_arp(
        self,
        ETHERNET_destination_ip: str,
        ETHERNET_interface: NetworkInterface,
        ETHERNET_port,
        ETHERNET_source_ip: str,
    ):
        ETHERNET_table = self._ETHERNET_arp_table()
        ETHERNET_entry = ETHERNET_table.lookup(ETHERNET_destination_ip, ETHERNET_interface.name)
        if ETHERNET_entry is not None:
            return ETHERNET_entry

        try:
            ETHERNET_request = ArpProtocol(ETHERNET_table).build_request(
                ETHERNET_interface,
                ETHERNET_destination_ip,
                sender_ip=ETHERNET_source_ip,
            )
        except ValueError:
            return None
        ETHERNET_waiter = self._ETHERNET_arp_entry_waiter(
            ETHERNET_destination_ip,
            ETHERNET_interface.name,
        )
        debug_ethernet_frame(
            self.ETHERNET_debug_ctx or CliContext(state=self.ETHERNET_state),
            ETHERNET_interface.name,
            "tx",
            ETHERNET_request,
        )
        ETHERNET_port.send_frame(ETHERNET_request.to_bytes(pad=True))

        self._ETHERNET_wait_for_arp_resolution(
            ETHERNET_destination_ip,
            ETHERNET_interface,
            ETHERNET_port,
            ETHERNET_waiter,
        )
        return ETHERNET_table.lookup(ETHERNET_destination_ip, ETHERNET_interface.name)

    def _ETHERNET_wait_for_arp_resolution(
        self,
        ETHERNET_destination_ip: str,
        ETHERNET_interface: NetworkInterface,
        ETHERNET_port,
        ETHERNET_waiter,
    ) -> None:
        ETHERNET_deadline = time.monotonic() + self.ETHERNET_arp_timeout_seconds
        while time.monotonic() < ETHERNET_deadline:
            if self._ETHERNET_arp_table().lookup(ETHERNET_destination_ip, ETHERNET_interface.name) is not None:
                ETHERNET_waiter(0)
                return
            ETHERNET_remaining = ETHERNET_deadline - time.monotonic()
            if ETHERNET_remaining <= 0:
                break
            if ETHERNET_waiter(min(0.05, ETHERNET_remaining)):
                return
            self._ETHERNET_drain_arp_frame(ETHERNET_port, ETHERNET_interface)
        ETHERNET_waiter(0)

    def _ETHERNET_drain_arp_frame(self, ETHERNET_port, ETHERNET_interface: NetworkInterface) -> None:
        ETHERNET_recv_frame = getattr(ETHERNET_port, "recv_frame", None)
        if ETHERNET_recv_frame is None:
            return
        ETHERNET_raw = ETHERNET_recv_frame()
        if ETHERNET_raw is None:
            return
        try:
            ETHERNET_frame = parse_ethernet_ii_frame(ETHERNET_raw)
        except EthernetFrameError:
            return
        if ETHERNET_frame.ethertype != ETHERTYPE_ARP or not ETHERNET_frame_belongs_to_interface(
            ETHERNET_frame,
            ETHERNET_interface,
        ):
            return
        debug_ethernet_frame(
            self.ETHERNET_debug_ctx or CliContext(state=self.ETHERNET_state),
            ETHERNET_interface.name,
            "rx",
            ETHERNET_frame,
        )
        try:
            ETHERNET_reply = ArpProtocol(self._ETHERNET_arp_table()).handle_frame(
                ETHERNET_interface,
                ETHERNET_frame,
            )
        except (ArpPacketError, ValueError):
            return
        if ETHERNET_reply is not None:
            debug_ethernet_frame(
                self.ETHERNET_debug_ctx or CliContext(state=self.ETHERNET_state),
                ETHERNET_interface.name,
                "tx",
                ETHERNET_reply,
            )
            ETHERNET_port.send_frame(ETHERNET_reply.to_bytes(pad=True))

    def _ETHERNET_arp_entry_waiter(self, ETHERNET_destination_ip: str, ETHERNET_interface_name: str):
        ETHERNET_ready = threading.Event()

        def ETHERNET_handle_entry_learned(ETHERNET_event: ARP_EntryLearned) -> None:
            if (
                ETHERNET_event.entry.ip_address == ETHERNET_destination_ip
                and ETHERNET_event.entry.interface_name == ETHERNET_interface_name
            ):
                ETHERNET_ready.set()

        ETHERNET_bus = VVRP_event_bus(self.ETHERNET_state)
        ETHERNET_bus.VVRP_subscribe(ARP_EntryLearned, ETHERNET_handle_entry_learned)

        def ETHERNET_wait(ETHERNET_timeout_seconds: float | None = None) -> bool:
            if self._ETHERNET_arp_table().lookup(ETHERNET_destination_ip, ETHERNET_interface_name) is not None:
                ETHERNET_bus.VVRP_unsubscribe(ARP_EntryLearned, ETHERNET_handle_entry_learned)
                return True
            try:
                return ETHERNET_ready.wait(
                    self.ETHERNET_arp_timeout_seconds
                    if ETHERNET_timeout_seconds is None
                    else max(0.0, ETHERNET_timeout_seconds)
                )
            finally:
                if ETHERNET_ready.is_set() or ETHERNET_timeout_seconds is None or ETHERNET_timeout_seconds == 0:
                    ETHERNET_bus.VVRP_unsubscribe(ARP_EntryLearned, ETHERNET_handle_entry_learned)

        return ETHERNET_wait


def ETHERNET_frame_belongs_to_interface(
    ETHERNET_frame: EthernetFrame,
    ETHERNET_interface: NetworkInterface,
) -> bool:
    ETHERNET_mac = ETHERNET_interface.mac_address.lower()
    ETHERNET_source = ETHERNET_frame.source.lower()
    ETHERNET_destination = ETHERNET_frame.destination.lower()
    return ETHERNET_source != ETHERNET_mac and (
        ETHERNET_destination == ETHERNET_mac
        or ETHERNET_is_group_address(ETHERNET_destination)
    )


def ETHERNET_is_group_address(ETHERNET_mac_address: str) -> bool:
    try:
        ETHERNET_first_octet = int(ETHERNET_mac_address.split(":", 1)[0], 16)
    except (ValueError, IndexError):
        return False
    return bool(ETHERNET_first_octet & 1)
