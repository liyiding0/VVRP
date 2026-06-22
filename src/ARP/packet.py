from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from src.ETHERNET import (
    ETHERTYPE_ARP,
    ETHERTYPE_IPV4,
    EthernetFrame,
    EthernetFrameError,
    format_mac_address,
    parse_mac_address,
)


ARP_ETHERNET_HARDWARE_TYPE = 1
ARP_IPV4_PROTOCOL_LENGTH = 4
ARP_ETHERNET_HARDWARE_LENGTH = 6
ARP_REQUEST = 1
ARP_REPLY = 2
ARP_PACKET_LENGTH = 28
ZERO_MAC = "00:00:00:00:00:00"


class ArpPacketError(ValueError):
    pass


@dataclass(frozen=True)
class ArpPacket:
    operation: int
    sender_mac: str
    sender_ip: str
    target_mac: str
    target_ip: str
    hardware_type: int = ARP_ETHERNET_HARDWARE_TYPE
    protocol_type: int = ETHERTYPE_IPV4

    def to_bytes(self) -> bytes:
        if self.operation not in (ARP_REQUEST, ARP_REPLY):
            raise ArpPacketError(f"unsupported ARP operation: {self.operation}")
        return b"".join(
            (
                self.hardware_type.to_bytes(2, "big"),
                self.protocol_type.to_bytes(2, "big"),
                bytes((ARP_ETHERNET_HARDWARE_LENGTH, ARP_IPV4_PROTOCOL_LENGTH)),
                self.operation.to_bytes(2, "big"),
                parse_mac_address(self.sender_mac),
                _parse_ipv4_address(self.sender_ip),
                parse_mac_address(self.target_mac),
                _parse_ipv4_address(self.target_ip),
            )
        )

    @property
    def is_request(self) -> bool:
        return self.operation == ARP_REQUEST

    @property
    def is_reply(self) -> bool:
        return self.operation == ARP_REPLY


def parse_arp_packet(data: bytes) -> ArpPacket:
    raw = bytes(data)
    if len(raw) < ARP_PACKET_LENGTH:
        raise ArpPacketError("ARP packet is shorter than 28 bytes")

    hardware_type = int.from_bytes(raw[0:2], "big")
    protocol_type = int.from_bytes(raw[2:4], "big")
    hardware_length = raw[4]
    protocol_length = raw[5]
    operation = int.from_bytes(raw[6:8], "big")

    if hardware_type != ARP_ETHERNET_HARDWARE_TYPE:
        raise ArpPacketError(f"unsupported ARP hardware type: {hardware_type}")
    if protocol_type != ETHERTYPE_IPV4:
        raise ArpPacketError(f"unsupported ARP protocol type: 0x{protocol_type:04x}")
    if hardware_length != ARP_ETHERNET_HARDWARE_LENGTH:
        raise ArpPacketError(f"unsupported ARP hardware length: {hardware_length}")
    if protocol_length != ARP_IPV4_PROTOCOL_LENGTH:
        raise ArpPacketError(f"unsupported ARP protocol length: {protocol_length}")
    if operation not in (ARP_REQUEST, ARP_REPLY):
        raise ArpPacketError(f"unsupported ARP operation: {operation}")

    return ArpPacket(
        operation=operation,
        sender_mac=format_mac_address(raw[8:14]),
        sender_ip=str(ipaddress.IPv4Address(raw[14:18])),
        target_mac=format_mac_address(raw[18:24]),
        target_ip=str(ipaddress.IPv4Address(raw[24:28])),
        hardware_type=hardware_type,
        protocol_type=protocol_type,
    )


def arp_packet_from_ethernet(frame: EthernetFrame) -> ArpPacket:
    if frame.ethertype != ETHERTYPE_ARP:
        raise EthernetFrameError(f"Ethernet frame is not ARP: 0x{frame.ethertype:04x}")
    return parse_arp_packet(frame.payload)


def _parse_ipv4_address(value: str) -> bytes:
    try:
        return ipaddress.IPv4Address(value).packed
    except ipaddress.AddressValueError as exc:
        raise ArpPacketError(f"invalid IPv4 address: {value}") from exc
