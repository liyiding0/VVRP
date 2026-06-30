from __future__ import annotations

from src.ETHERNET import BROADCAST_MAC, ETHERTYPE_ARP, EthernetFrame
from src.IFNET.models import NetworkInterface

from .packet import ARP_REPLY, ARP_REQUEST, ZERO_MAC, ArpPacket, arp_packet_from_ethernet
from .table import ArpEntry, ArpTable


class ArpProtocol:
    def __init__(self, table: ArpTable | None = None) -> None:
        self.table = table or ArpTable()

    def build_request(
        self,
        interface: NetworkInterface,
        target_ip: str,
        sender_ip: str | None = None,
    ) -> EthernetFrame:
        source_ip = sender_ip or _primary_ipv4_address(interface)
        packet = ArpPacket(
            operation=ARP_REQUEST,
            sender_mac=interface.mac_address,
            sender_ip=source_ip,
            target_mac=ZERO_MAC,
            target_ip=target_ip,
        )
        return EthernetFrame(
            destination=BROADCAST_MAC,
            source=interface.mac_address,
            ethertype=ETHERTYPE_ARP,
            payload=packet.to_bytes(),
        )

    def build_reply(
        self,
        interface: NetworkInterface,
        request: ArpPacket,
        sender_ip: str | None = None,
    ) -> EthernetFrame:
        source_ip = sender_ip or _primary_ipv4_address(interface)
        packet = ArpPacket(
            operation=ARP_REPLY,
            sender_mac=interface.mac_address,
            sender_ip=source_ip,
            target_mac=request.sender_mac,
            target_ip=request.sender_ip,
        )
        return EthernetFrame(
            destination=request.sender_mac,
            source=interface.mac_address,
            ethertype=ETHERTYPE_ARP,
            payload=packet.to_bytes(),
        )

    def handle_frame(
        self,
        interface: NetworkInterface,
        frame: EthernetFrame,
        now: float | None = None,
    ) -> EthernetFrame | None:
        packet = arp_packet_from_ethernet(frame)
        self.learn(interface, packet, now=now)
        if packet.is_request and packet.target_ip in _interface_ipv4_addresses(interface):
            return self.build_reply(interface, packet, sender_ip=packet.target_ip)
        return None

    def learn(
        self,
        interface: NetworkInterface,
        packet: ArpPacket,
        now: float | None = None,
    ) -> ArpEntry | None:
        return self.table.learn(
            packet.sender_ip,
            packet.sender_mac,
            interface.name,
            now=now,
            local_ip_addresses=_interface_ipv4_addresses(interface),
        )

    def age(self, now: float | None = None) -> tuple[ArpEntry, ...]:
        return self.table.age(now=now)


def _primary_ipv4_address(interface: NetworkInterface) -> str:
    addresses = _interface_ipv4_addresses(interface)
    if not addresses:
        raise ValueError(f"interface has no IPv4 address: {interface.name}")
    return addresses[0]


def _interface_ipv4_addresses(interface: NetworkInterface) -> tuple[str, ...]:
    return tuple(address.address for address in interface.addresses_by_family("ipv4"))
