from __future__ import annotations

from collections.abc import Callable

from src.ARP import ArpTable, get_arp_table
from src.ETHERNET import ETHERTYPE_IPV4, EthernetFrame
from src.FIB import FIBEntry
from src.IFNET.models import NetworkInterface
from src.IP.ipv4 import IP_parse_ipv4_packet

from .models import FWD_RawFramePort, FWD_Result


class FWD_EthernetOutputHandler:
    def __init__(
        self,
        FWD_state: dict,
        *,
        FWD_port_provider: Callable[[NetworkInterface], FWD_RawFramePort] | None = None,
        FWD_arp_table: ArpTable | None = None,
    ) -> None:
        self.FWD_state = FWD_state
        self.FWD_port_provider = FWD_port_provider
        self.FWD_arp_table = FWD_arp_table

    def FWD_send_packet(
        self,
        FWD_packet: bytes,
        FWD_route: FIBEntry,
        FWD_interface: NetworkInterface,
    ) -> FWD_Result:
        if self.FWD_port_provider is None:
            return FWD_Result(
                FWD_ok=False,
                FWD_message="% FWD Ethernet output port is not available",
                FWD_route=FWD_route,
            )
        try:
            FWD_destination_ip = FWD_next_hop_ip(FWD_packet, FWD_route)
        except ValueError as FWD_exc:
            return FWD_Result(
                FWD_ok=False,
                FWD_message=f"% FWD invalid IPv4 packet: {FWD_exc}",
                FWD_route=FWD_route,
            )
        FWD_arp_entry = self._FWD_arp_table().lookup(FWD_destination_ip, FWD_interface.name)
        if FWD_arp_entry is None:
            return FWD_Result(
                FWD_ok=False,
                FWD_message=(
                    f"% FWD adjacency unresolved: {FWD_destination_ip} "
                    f"via {FWD_interface.name}"
                ),
                FWD_route=FWD_route,
            )
        FWD_frame = EthernetFrame(
            destination=FWD_arp_entry.mac_address,
            source=FWD_interface.mac_address,
            ethertype=ETHERTYPE_IPV4,
            payload=FWD_packet,
        )
        FWD_raw_frame = FWD_frame.to_bytes(pad=True)
        self.FWD_port_provider(FWD_interface).send_frame(FWD_raw_frame)
        return FWD_Result(
            FWD_ok=True,
            FWD_message="",
            FWD_frame=FWD_raw_frame,
            FWD_route=FWD_route,
        )

    def _FWD_arp_table(self) -> ArpTable:
        return get_arp_table(self.FWD_state, self.FWD_arp_table)


def FWD_next_hop_ip(FWD_packet: bytes, FWD_route: FIBEntry) -> str:
    if FWD_route.next_hop_ip:
        return FWD_route.next_hop_ip
    return IP_parse_ipv4_packet(FWD_packet).IP_destination
