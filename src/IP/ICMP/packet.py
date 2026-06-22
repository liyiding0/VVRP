from __future__ import annotations

import struct
from dataclasses import dataclass


g_ICMP_ECHO_REPLY = 0
g_ICMP_ECHO_REQUEST = 8
g_ICMP_CODE = 0


@dataclass(frozen=True)
class ICMP_Echo:
    ICMP_type: int
    ICMP_identifier: int
    ICMP_sequence: int
    ICMP_payload: bytes

    @property
    def ICMP_is_echo_request(self) -> bool:
        return self.ICMP_type == g_ICMP_ECHO_REQUEST

    @property
    def ICMP_is_echo_reply(self) -> bool:
        return self.ICMP_type == g_ICMP_ECHO_REPLY


def ICMP_build_echo_request(
    ICMP_identifier: int,
    ICMP_sequence: int,
    ICMP_payload: bytes,
) -> bytes:
    return _ICMP_build_echo(
        g_ICMP_ECHO_REQUEST,
        ICMP_identifier,
        ICMP_sequence,
        ICMP_payload,
    )


def ICMP_build_echo_reply(
    ICMP_identifier: int,
    ICMP_sequence: int,
    ICMP_payload: bytes,
) -> bytes:
    return _ICMP_build_echo(
        g_ICMP_ECHO_REPLY,
        ICMP_identifier,
        ICMP_sequence,
        ICMP_payload,
    )


def ICMP_parse_echo(ICMP_data: bytes) -> ICMP_Echo | None:
    ICMP_raw = bytes(ICMP_data)
    if len(ICMP_raw) < 8:
        return None
    ICMP_type, ICMP_code, _, ICMP_identifier, ICMP_sequence = struct.unpack(
        "!BBHHH",
        ICMP_raw[:8],
    )
    if ICMP_code != g_ICMP_CODE or ICMP_type not in (
        g_ICMP_ECHO_REQUEST,
        g_ICMP_ECHO_REPLY,
    ):
        return None
    return ICMP_Echo(
        ICMP_type=ICMP_type,
        ICMP_identifier=ICMP_identifier,
        ICMP_sequence=ICMP_sequence,
        ICMP_payload=ICMP_raw[8:],
    )


def ICMP_checksum(ICMP_data: bytes) -> int:
    ICMP_payload = bytes(ICMP_data)
    if len(ICMP_payload) % 2:
        ICMP_payload += b"\x00"
    ICMP_total = 0
    for ICMP_index in range(0, len(ICMP_payload), 2):
        ICMP_total += (ICMP_payload[ICMP_index] << 8) + ICMP_payload[ICMP_index + 1]
        ICMP_total = (ICMP_total & 0xFFFF) + (ICMP_total >> 16)
    return (~ICMP_total) & 0xFFFF


def _ICMP_build_echo(
    ICMP_type: int,
    ICMP_identifier: int,
    ICMP_sequence: int,
    ICMP_payload: bytes,
) -> bytes:
    ICMP_header = struct.pack(
        "!BBHHH",
        ICMP_type,
        g_ICMP_CODE,
        0,
        ICMP_identifier,
        ICMP_sequence,
    )
    ICMP_check = ICMP_checksum(ICMP_header + ICMP_payload)
    ICMP_header = struct.pack(
        "!BBHHH",
        ICMP_type,
        g_ICMP_CODE,
        ICMP_check,
        ICMP_identifier,
        ICMP_sequence,
    )
    return ICMP_header + bytes(ICMP_payload)
