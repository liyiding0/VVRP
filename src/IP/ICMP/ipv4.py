from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass

from .packet import ICMP_checksum


g_ICMP_DEFAULT_TTL = 255
g_ICMP_IPV4_HEADER_LENGTH = 20
g_ICMP_IPV4_PROTOCOL_ICMP = 1


@dataclass(frozen=True)
class ICMP_IPv4Packet:
    ICMP_source: str
    ICMP_destination: str
    ICMP_protocol: int
    ICMP_ttl: int
    ICMP_payload: bytes
    ICMP_raw: bytes


def ICMP_build_ipv4_packet(
    ICMP_source: str,
    ICMP_destination: str,
    ICMP_protocol: int,
    ICMP_payload: bytes,
    *,
    ICMP_ttl: int = g_ICMP_DEFAULT_TTL,
    ICMP_identification: int = 0,
) -> bytes:
    ICMP_source_bytes = ipaddress.IPv4Address(ICMP_source).packed
    ICMP_destination_bytes = ipaddress.IPv4Address(ICMP_destination).packed
    ICMP_total_length = g_ICMP_IPV4_HEADER_LENGTH + len(ICMP_payload)
    ICMP_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        ICMP_total_length,
        ICMP_identification & 0xFFFF,
        0x4000,
        ICMP_ttl,
        ICMP_protocol,
        0,
        ICMP_source_bytes,
        ICMP_destination_bytes,
    )
    ICMP_check = ICMP_checksum(ICMP_header)
    ICMP_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        ICMP_total_length,
        ICMP_identification & 0xFFFF,
        0x4000,
        ICMP_ttl,
        ICMP_protocol,
        ICMP_check,
        ICMP_source_bytes,
        ICMP_destination_bytes,
    )
    return ICMP_header + bytes(ICMP_payload)


def ICMP_parse_ipv4_packet(ICMP_data: bytes) -> ICMP_IPv4Packet:
    ICMP_raw = bytes(ICMP_data)
    if len(ICMP_raw) < g_ICMP_IPV4_HEADER_LENGTH:
        raise ValueError("IPv4 packet is shorter than 20 bytes")
    ICMP_version = ICMP_raw[0] >> 4
    if ICMP_version != 4:
        raise ValueError("packet is not IPv4")
    ICMP_header_length = (ICMP_raw[0] & 0x0F) * 4
    if ICMP_header_length < g_ICMP_IPV4_HEADER_LENGTH or len(ICMP_raw) < ICMP_header_length:
        raise ValueError("invalid IPv4 header length")
    ICMP_total_length = int.from_bytes(ICMP_raw[2:4], "big")
    if ICMP_total_length < ICMP_header_length or len(ICMP_raw) < ICMP_total_length:
        raise ValueError("invalid IPv4 total length")
    return ICMP_IPv4Packet(
        ICMP_source=str(ipaddress.IPv4Address(ICMP_raw[12:16])),
        ICMP_destination=str(ipaddress.IPv4Address(ICMP_raw[16:20])),
        ICMP_protocol=ICMP_raw[9],
        ICMP_ttl=ICMP_raw[8],
        ICMP_payload=ICMP_raw[ICMP_header_length:ICMP_total_length],
        ICMP_raw=ICMP_raw[:ICMP_total_length],
    )
