from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass


g_IP_DEFAULT_TTL = 255
g_IP_IPV4_HEADER_LENGTH = 20


@dataclass(frozen=True)
class IP_IPv4Packet:
    IP_source: str
    IP_destination: str
    IP_protocol: int
    IP_ttl: int
    IP_payload: bytes
    IP_raw: bytes


def IP_build_ipv4_packet(
    IP_source: str,
    IP_destination: str,
    IP_protocol: int,
    IP_payload: bytes,
    *,
    IP_ttl: int = g_IP_DEFAULT_TTL,
    IP_identification: int = 0,
) -> bytes:
    IP_source_bytes = ipaddress.IPv4Address(IP_source).packed
    IP_destination_bytes = ipaddress.IPv4Address(IP_destination).packed
    IP_total_length = g_IP_IPV4_HEADER_LENGTH + len(IP_payload)
    IP_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        IP_total_length,
        IP_identification & 0xFFFF,
        0x4000,
        IP_ttl,
        IP_protocol,
        0,
        IP_source_bytes,
        IP_destination_bytes,
    )
    IP_check = IP_checksum(IP_header)
    IP_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        IP_total_length,
        IP_identification & 0xFFFF,
        0x4000,
        IP_ttl,
        IP_protocol,
        IP_check,
        IP_source_bytes,
        IP_destination_bytes,
    )
    return IP_header + bytes(IP_payload)


def IP_parse_ipv4_packet(IP_data: bytes) -> IP_IPv4Packet:
    IP_raw = bytes(IP_data)
    if len(IP_raw) < g_IP_IPV4_HEADER_LENGTH:
        raise ValueError("IPv4 packet is shorter than 20 bytes")
    IP_version = IP_raw[0] >> 4
    if IP_version != 4:
        raise ValueError("packet is not IPv4")
    IP_header_length = (IP_raw[0] & 0x0F) * 4
    if IP_header_length < g_IP_IPV4_HEADER_LENGTH or len(IP_raw) < IP_header_length:
        raise ValueError("invalid IPv4 header length")
    IP_total_length = int.from_bytes(IP_raw[2:4], "big")
    if IP_total_length < IP_header_length or len(IP_raw) < IP_total_length:
        raise ValueError("invalid IPv4 total length")
    return IP_IPv4Packet(
        IP_source=str(ipaddress.IPv4Address(IP_raw[12:16])),
        IP_destination=str(ipaddress.IPv4Address(IP_raw[16:20])),
        IP_protocol=IP_raw[9],
        IP_ttl=IP_raw[8],
        IP_payload=IP_raw[IP_header_length:IP_total_length],
        IP_raw=IP_raw[:IP_total_length],
    )


def IP_checksum(IP_data: bytes) -> int:
    IP_payload = bytes(IP_data)
    if len(IP_payload) % 2:
        IP_payload += b"\x00"
    IP_total = 0
    for IP_index in range(0, len(IP_payload), 2):
        IP_total += (IP_payload[IP_index] << 8) + IP_payload[IP_index + 1]
        IP_total = (IP_total & 0xFFFF) + (IP_total >> 16)
    return (~IP_total) & 0xFFFF
