from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from src.FIB import FIBEntry
from src.IFNET.models import NetworkInterface
from src.IP.ipv4 import IP_parse_ipv4_packet


@dataclass(frozen=True)
class FWD_Adjacency:
    FWD_target_ip: str


class FWD_AdjacencyHandler(Protocol):
    def FWD_resolve_adjacency(
        self,
        FWD_packet: bytes,
        FWD_route: FIBEntry,
        FWD_interface: NetworkInterface,
    ) -> FWD_Adjacency:
        """Resolve the media-specific forwarding adjacency for one packet."""


class FWD_AdjacencyRegistry:
    def __init__(
        self,
        FWD_handlers: dict[str, FWD_AdjacencyHandler] | None = None,
    ) -> None:
        self.FWD_handlers = dict(FWD_handlers or {})

    def FWD_register_handler(
        self,
        FWD_interface_kind: str,
        FWD_handler: FWD_AdjacencyHandler,
    ) -> None:
        self.FWD_handlers[FWD_interface_kind] = FWD_handler

    def FWD_resolve_adjacency(
        self,
        FWD_packet: bytes,
        FWD_route: FIBEntry,
        FWD_interface: NetworkInterface,
    ) -> FWD_Adjacency:
        FWD_handler = self.FWD_handlers.get(FWD_interface.kind)
        if FWD_handler is None:
            raise FWD_AdjacencyError(f"unsupported adjacency media: {FWD_interface.kind}")
        return FWD_handler.FWD_resolve_adjacency(FWD_packet, FWD_route, FWD_interface)


class FWD_AdjacencyError(ValueError):
    pass


class FWD_EthernetAdjacencyHandler:
    def FWD_resolve_adjacency(
        self,
        FWD_packet: bytes,
        FWD_route: FIBEntry,
        FWD_interface: NetworkInterface,
    ) -> FWD_Adjacency:
        if FWD_route.next_hop_ip:
            return FWD_Adjacency(FWD_target_ip=FWD_route.next_hop_ip)
        return FWD_Adjacency(
            FWD_target_ip=IP_parse_ipv4_packet(FWD_packet).IP_destination,
        )


def FWD_default_adjacency_registry() -> FWD_AdjacencyRegistry:
    FWD_registry = FWD_AdjacencyRegistry()
    FWD_registry.FWD_register_handler("ethernet", FWD_EthernetAdjacencyHandler())
    return FWD_registry
