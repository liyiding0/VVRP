from __future__ import annotations

from collections.abc import Callable

from src.ARP import ArpPacketError, ArpProtocol, get_arp_table
from src.CCmd.models import CliContext
from src.IFNET.models import NetworkInterface
from src.IP.ICMP.input import ICMP_handle_ipv4_packet

from .debug import debug_ethernet_frame
from .frame import (
    ETHERTYPE_ARP,
    ETHERTYPE_IPV4,
    EthernetFrame,
    EthernetFrameError,
    parse_ethernet_ii_frame,
)


class ETHERNET_InputHandler:
    def __init__(
        self,
        ETHERNET_ctx: CliContext,
        ETHERNET_send_frame: Callable[[bytes], None],
    ) -> None:
        self.ETHERNET_ctx = ETHERNET_ctx
        self.ETHERNET_send_frame = ETHERNET_send_frame

    def ETHERNET_handle_frame(
        self,
        ETHERNET_interface: NetworkInterface,
        ETHERNET_raw_frame: bytes,
    ) -> None:
        try:
            ETHERNET_frame = parse_ethernet_ii_frame(ETHERNET_raw_frame)
        except EthernetFrameError:
            return
        if not ETHERNET_frame_belongs_to_interface(ETHERNET_frame, ETHERNET_interface):
            return
        debug_ethernet_frame(
            self.ETHERNET_ctx,
            ETHERNET_interface.name,
            "rx",
            ETHERNET_frame,
        )
        if ETHERNET_frame.ethertype == ETHERTYPE_ARP:
            self._ETHERNET_handle_arp(ETHERNET_interface, ETHERNET_frame)
        elif ETHERNET_frame.ethertype == ETHERTYPE_IPV4:
            self._ETHERNET_handle_ipv4(ETHERNET_interface, ETHERNET_frame)

    def _ETHERNET_handle_arp(
        self,
        ETHERNET_interface: NetworkInterface,
        ETHERNET_frame: EthernetFrame,
    ) -> None:
        try:
            ETHERNET_reply = ArpProtocol(get_arp_table(self.ETHERNET_ctx.state)).handle_frame(
                ETHERNET_interface,
                ETHERNET_frame,
            )
        except (ArpPacketError, ValueError):
            return
        if ETHERNET_reply is None:
            return
        debug_ethernet_frame(
            self.ETHERNET_ctx,
            ETHERNET_interface.name,
            "tx",
            ETHERNET_reply,
        )
        self.ETHERNET_send_frame(ETHERNET_reply.to_bytes(pad=True))

    def _ETHERNET_handle_ipv4(
        self,
        ETHERNET_interface: NetworkInterface,
        ETHERNET_frame: EthernetFrame,
    ) -> None:
        ETHERNET_reply_packet = ICMP_handle_ipv4_packet(
            ETHERNET_interface,
            ETHERNET_frame.payload,
            self.ETHERNET_ctx.state,
        )
        if ETHERNET_reply_packet is None:
            return
        ETHERNET_reply_frame = EthernetFrame(
            destination=ETHERNET_frame.source,
            source=ETHERNET_interface.mac_address,
            ethertype=ETHERTYPE_IPV4,
            payload=ETHERNET_reply_packet,
        )
        debug_ethernet_frame(
            self.ETHERNET_ctx,
            ETHERNET_interface.name,
            "tx",
            ETHERNET_reply_frame,
        )
        self.ETHERNET_send_frame(ETHERNET_reply_frame.to_bytes(pad=True))


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

