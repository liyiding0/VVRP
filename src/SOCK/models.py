from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from src.FIB import FIBEntry


SOCK_AF_INET = 2
SOCK_AF_INET6 = 10
SOCK_SOCK_STREAM = 1
SOCK_SOCK_DGRAM = 2
SOCK_SOCK_RAW = 3
SOCK_IPPROTO_IP = 0
SOCK_IPPROTO_ICMP = 1
SOCK_IPPROTO_TCP = 6
SOCK_IPPROTO_UDP = 17
SOCK_IPPROTO_OSPF = 89


@dataclass(frozen=True)
class SOCK_SockaddrIn:
    SOCK_addr: str
    SOCK_port: int = 0
    SOCK_family: int = SOCK_AF_INET


@dataclass(frozen=True)
class SOCK_SendResult:
    SOCK_ok: bool
    SOCK_message: str = ""
    SOCK_packet: bytes = b""
    SOCK_route: FIBEntry | None = None


class SOCK_Forwarder(Protocol):
    def FWD_send_packet(self, SOCK_packet: bytes, SOCK_route: FIBEntry):
        """Forward a fully assembled network-layer packet according to a FIB entry."""


class SOCK_NoopForwarder:
    def FWD_send_packet(self, SOCK_packet: bytes, SOCK_route: FIBEntry) -> SOCK_SendResult:
        return SOCK_SendResult(
            SOCK_ok=False,
            SOCK_message="% VVRP forwarder is not available until FWD is installed",
            SOCK_packet=SOCK_packet,
            SOCK_route=SOCK_route,
        )
