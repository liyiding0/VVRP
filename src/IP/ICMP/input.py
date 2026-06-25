from __future__ import annotations

from src.IFNET.models import NetworkInterface

from .packet import ICMP_build_echo_reply, ICMP_parse_echo
from .ipv4 import g_ICMP_IPV4_PROTOCOL_ICMP, ICMP_build_ipv4_packet, ICMP_parse_ipv4_packet
from .replies import ICMP_record_echo_reply


def ICMP_handle_ipv4_packet(
    ICMP_interface: NetworkInterface,
    ICMP_ipv4_payload: bytes,
    ICMP_state: dict | None = None,
) -> bytes | None:
    try:
        ICMP_packet = ICMP_parse_ipv4_packet(ICMP_ipv4_payload)
    except ValueError:
        return None
    if ICMP_packet.ICMP_protocol != g_ICMP_IPV4_PROTOCOL_ICMP:
        return None
    if ICMP_packet.ICMP_destination not in _ICMP_interface_ipv4_addresses(ICMP_interface):
        return None
    ICMP_echo = ICMP_parse_echo(ICMP_packet.ICMP_payload)
    if ICMP_echo is None:
        return None
    if ICMP_echo.ICMP_is_echo_reply:
        if ICMP_state is not None:
            ICMP_record_echo_reply(
                ICMP_state,
                ICMP_source=ICMP_packet.ICMP_source,
                ICMP_destination=ICMP_packet.ICMP_destination,
                ICMP_identifier=ICMP_echo.ICMP_identifier,
                ICMP_sequence=ICMP_echo.ICMP_sequence,
                ICMP_ttl=ICMP_packet.ICMP_ttl,
                ICMP_payload=ICMP_echo.ICMP_payload,
            )
        return None
    if not ICMP_echo.ICMP_is_echo_request:
        return None

    ICMP_payload = ICMP_build_echo_reply(
        ICMP_echo.ICMP_identifier,
        ICMP_echo.ICMP_sequence,
        ICMP_echo.ICMP_payload,
    )
    return ICMP_build_ipv4_packet(
        ICMP_packet.ICMP_destination,
        ICMP_packet.ICMP_source,
        g_ICMP_IPV4_PROTOCOL_ICMP,
        ICMP_payload,
        ICMP_ttl=255,
    )


def _ICMP_interface_ipv4_addresses(ICMP_interface: NetworkInterface) -> frozenset[str]:
    return frozenset(
        ICMP_address.address
        for ICMP_address in ICMP_interface.addresses_by_family("ipv4")
    )
