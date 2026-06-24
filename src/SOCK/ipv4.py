from __future__ import annotations

import ipaddress

from src.FIB import FIB_resolve_forwarding
from src.IP.ipv4 import IP_build_ipv4_packet

from .models import (
    SOCK_AF_INET,
    SOCK_IPPROTO_IP,
    SOCK_Forwarder,
    SOCK_NoopForwarder,
    SOCK_SOCK_RAW,
    SOCK_SendResult,
    SOCK_SockaddrIn,
)


class SOCK_Error(ValueError):
    pass


class SOCK_Socket:
    def __init__(
        self,
        SOCK_state: dict,
        *,
        SOCK_protocol: int = SOCK_IPPROTO_IP,
        SOCK_forwarder: SOCK_Forwarder | None = None,
    ) -> None:
        self.SOCK_state = SOCK_state
        self.SOCK_protocol = SOCK_protocol
        self.SOCK_forwarder = SOCK_forwarder or SOCK_NoopForwarder()
        self.SOCK_local_address: SOCK_SockaddrIn | None = None
        self.SOCK_peer_address: SOCK_SockaddrIn | None = None
        self.SOCK_closed = False

    def SOCK_bind(self, SOCK_address: SOCK_SockaddrIn | tuple[str, int] | str) -> None:
        self._SOCK_require_open()
        self.SOCK_local_address = SOCK_normalize_sockaddr_in(SOCK_address)

    def SOCK_connect(self, SOCK_address: SOCK_SockaddrIn | tuple[str, int] | str) -> None:
        self._SOCK_require_open()
        self.SOCK_peer_address = SOCK_normalize_sockaddr_in(SOCK_address)

    def SOCK_send(
        self,
        SOCK_payload: bytes,
        *,
        SOCK_ttl: int = 255,
        SOCK_identification: int = 0,
    ) -> SOCK_SendResult:
        self._SOCK_require_open()
        if self.SOCK_peer_address is None:
            return SOCK_SendResult(
                SOCK_ok=False,
                SOCK_message="% Socket is not connected",
            )
        return self.SOCK_sendto(
            SOCK_payload,
            self.SOCK_peer_address,
            SOCK_ttl=SOCK_ttl,
            SOCK_identification=SOCK_identification,
        )

    def SOCK_sendto(
        self,
        SOCK_payload: bytes,
        SOCK_destination: SOCK_SockaddrIn | tuple[str, int] | str,
        *,
        SOCK_source: str | None = None,
        SOCK_ttl: int = 255,
        SOCK_identification: int = 0,
    ) -> SOCK_SendResult:
        self._SOCK_require_open()
        SOCK_sockaddr = SOCK_normalize_sockaddr_in(SOCK_destination)
        SOCK_destination_ip = str(ipaddress.IPv4Address(SOCK_sockaddr.SOCK_addr))
        SOCK_route = FIB_resolve_forwarding(
            self.SOCK_state,
            (),
            (),
            SOCK_destination_ip,
        )
        if SOCK_route is None:
            return SOCK_SendResult(
                SOCK_ok=False,
                SOCK_message=f"% No VVRP route to host: {SOCK_destination_ip}",
            )

        SOCK_source_ip = SOCK_source or self._SOCK_bound_source() or SOCK_route.source_ip
        SOCK_packet = IP_build_ipv4_packet(
            SOCK_source_ip,
            SOCK_destination_ip,
            self.SOCK_protocol,
            SOCK_payload,
            IP_ttl=SOCK_ttl,
            IP_identification=SOCK_identification,
        )
        if SOCK_route.mtu is not None and len(SOCK_packet) > SOCK_route.mtu:
            return SOCK_SendResult(
                SOCK_ok=False,
                SOCK_message=f"% Packet size exceeds interface MTU: {SOCK_route.out_if_name}",
                SOCK_packet=SOCK_packet,
                SOCK_route=SOCK_route,
            )
        FWD_result = self.SOCK_forwarder.FWD_send_packet(SOCK_packet, SOCK_route)
        if isinstance(FWD_result, SOCK_SendResult):
            return FWD_result
        return SOCK_SendResult(
            SOCK_ok=FWD_result.FWD_ok,
            SOCK_message=FWD_result.FWD_message,
            SOCK_packet=SOCK_packet,
            SOCK_route=SOCK_route,
        )

    def SOCK_close(self) -> None:
        self.SOCK_closed = True

    def _SOCK_bound_source(self) -> str | None:
        if self.SOCK_local_address is None:
            return None
        if self.SOCK_local_address.SOCK_addr == "0.0.0.0":
            return None
        return self.SOCK_local_address.SOCK_addr

    def _SOCK_require_open(self) -> None:
        if self.SOCK_closed:
            raise SOCK_Error("socket is closed")


def SOCK_socket(
    SOCK_state: dict,
    SOCK_domain: int,
    SOCK_type: int,
    SOCK_protocol: int = SOCK_IPPROTO_IP,
    *,
    SOCK_forwarder: SOCK_Forwarder | None = None,
) -> SOCK_Socket:
    if SOCK_domain != SOCK_AF_INET:
        raise SOCK_Error("% Unsupported socket domain")
    if SOCK_type != SOCK_SOCK_RAW:
        raise SOCK_Error("% Unsupported socket type")
    return SOCK_Socket(
        SOCK_state,
        SOCK_protocol=SOCK_protocol,
        SOCK_forwarder=SOCK_forwarder,
    )


def SOCK_bind(SOCK_socket_obj: SOCK_Socket, SOCK_address: SOCK_SockaddrIn | tuple[str, int] | str) -> None:
    SOCK_socket_obj.SOCK_bind(SOCK_address)


def SOCK_connect(SOCK_socket_obj: SOCK_Socket, SOCK_address: SOCK_SockaddrIn | tuple[str, int] | str) -> None:
    SOCK_socket_obj.SOCK_connect(SOCK_address)


def SOCK_send(
    SOCK_socket_obj: SOCK_Socket,
    SOCK_payload: bytes,
    *,
    SOCK_ttl: int = 255,
    SOCK_identification: int = 0,
) -> SOCK_SendResult:
    return SOCK_socket_obj.SOCK_send(
        SOCK_payload,
        SOCK_ttl=SOCK_ttl,
        SOCK_identification=SOCK_identification,
    )


def SOCK_sendto(
    SOCK_socket_obj: SOCK_Socket,
    SOCK_payload: bytes,
    SOCK_destination: SOCK_SockaddrIn | tuple[str, int] | str,
    *,
    SOCK_ttl: int = 255,
    SOCK_identification: int = 0,
) -> SOCK_SendResult:
    return SOCK_socket_obj.SOCK_sendto(
        SOCK_payload,
        SOCK_destination,
        SOCK_ttl=SOCK_ttl,
        SOCK_identification=SOCK_identification,
    )


def SOCK_close(SOCK_socket_obj: SOCK_Socket) -> None:
    SOCK_socket_obj.SOCK_close()


def SOCK_normalize_sockaddr_in(
    SOCK_address: SOCK_SockaddrIn | tuple[str, int] | str,
) -> SOCK_SockaddrIn:
    if isinstance(SOCK_address, SOCK_SockaddrIn):
        if SOCK_address.SOCK_family != SOCK_AF_INET:
            raise SOCK_Error("% Address family mismatch")
        return SOCK_address
    if isinstance(SOCK_address, tuple):
        return SOCK_SockaddrIn(str(ipaddress.IPv4Address(SOCK_address[0])), int(SOCK_address[1]))
    return SOCK_SockaddrIn(str(ipaddress.IPv4Address(SOCK_address)))
