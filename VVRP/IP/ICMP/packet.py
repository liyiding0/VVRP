from __future__ import annotations

import struct
from dataclasses import dataclass


ICMP_ECHO_REPLY = 0
ICMP_ECHO_REQUEST = 8
ICMP_CODE = 0


@dataclass(frozen=True)
class IcmpEcho:
    icmp_type: int
    identifier: int
    sequence: int
    payload: bytes

    @property
    def is_echo_request(self) -> bool:
        return self.icmp_type == ICMP_ECHO_REQUEST

    @property
    def is_echo_reply(self) -> bool:
        return self.icmp_type == ICMP_ECHO_REPLY


def build_icmp_echo_request(identifier: int, sequence: int, payload: bytes) -> bytes:
    return _build_icmp_echo(ICMP_ECHO_REQUEST, identifier, sequence, payload)


def build_icmp_echo_reply(identifier: int, sequence: int, payload: bytes) -> bytes:
    return _build_icmp_echo(ICMP_ECHO_REPLY, identifier, sequence, payload)


def parse_icmp_echo(data: bytes) -> IcmpEcho | None:
    raw = bytes(data)
    if len(raw) < 8:
        return None
    icmp_type, code, _, identifier, sequence = struct.unpack("!BBHHH", raw[:8])
    if code != ICMP_CODE or icmp_type not in (ICMP_ECHO_REQUEST, ICMP_ECHO_REPLY):
        return None
    return IcmpEcho(
        icmp_type=icmp_type,
        identifier=identifier,
        sequence=sequence,
        payload=raw[8:],
    )


def icmp_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for index in range(0, len(data), 2):
        total += (data[index] << 8) + data[index + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _build_icmp_echo(icmp_type: int, identifier: int, sequence: int, payload: bytes) -> bytes:
    header = struct.pack("!BBHHH", icmp_type, ICMP_CODE, 0, identifier, sequence)
    checksum = icmp_checksum(header + payload)
    header = struct.pack("!BBHHH", icmp_type, ICMP_CODE, checksum, identifier, sequence)
    return header + bytes(payload)
