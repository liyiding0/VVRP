from __future__ import annotations

import time
from collections.abc import Callable

from src.ARP import ArpProtocol, ArpTable, get_arp_table
from src.ETHERNET import ETHERTYPE_IPV4, EthernetFrame
from src.FIB import FIBEntry
from src.IFNET.models import NetworkInterface

from .adjacency import FWD_AdjacencyError, FWD_AdjacencyRegistry, FWD_default_adjacency_registry
from .models import FWD_RawFramePort, FWD_Result


g_FWD_ARP_RESOLVE_TIMEOUT_SECONDS = 1.0
g_FWD_ARP_RESOLVE_INTERVAL_SECONDS = 0.05


class FWD_EthernetOutputHandler:
    def __init__(
        self,
        FWD_state: dict,
        *,
        FWD_port_provider: Callable[[NetworkInterface], FWD_RawFramePort] | None = None,
        FWD_arp_table: ArpTable | None = None,
        FWD_arp_timeout_seconds: float = g_FWD_ARP_RESOLVE_TIMEOUT_SECONDS,
        FWD_arp_poll_interval_seconds: float = g_FWD_ARP_RESOLVE_INTERVAL_SECONDS,
        FWD_monotonic: Callable[[], float] = time.monotonic,
        FWD_sleep: Callable[[float], None] = time.sleep,
        FWD_adjacency_registry: FWD_AdjacencyRegistry | None = None,
    ) -> None:
        self.FWD_state = FWD_state
        self.FWD_port_provider = FWD_port_provider
        self.FWD_arp_table = FWD_arp_table
        self.FWD_arp_timeout_seconds = FWD_arp_timeout_seconds
        self.FWD_arp_poll_interval_seconds = FWD_arp_poll_interval_seconds
        self.FWD_monotonic = FWD_monotonic
        self.FWD_sleep = FWD_sleep
        self.FWD_adjacency_registry = FWD_adjacency_registry or FWD_default_adjacency_registry()

    def FWD_send_packet(
        self,
        FWD_packet: bytes,
        FWD_route: FIBEntry,
        FWD_interface: NetworkInterface,
    ) -> FWD_Result:
        if self.FWD_port_provider is None:
            return FWD_Result(
                FWD_ok=False,
                FWD_message="% FWD Ethernet output port is not available",
                FWD_route=FWD_route,
            )
        try:
            FWD_adjacency = self.FWD_adjacency_registry.FWD_resolve_adjacency(
                FWD_packet,
                FWD_route,
                FWD_interface,
            )
        except (FWD_AdjacencyError, ValueError) as FWD_exc:
            return FWD_Result(
                FWD_ok=False,
                FWD_message=f"% FWD adjacency resolution failed: {FWD_exc}",
                FWD_route=FWD_route,
            )
        FWD_port = self.FWD_port_provider(FWD_interface)
        FWD_arp_entry = self._FWD_resolve_arp(
            FWD_adjacency.FWD_target_ip,
            FWD_interface,
            FWD_port,
            FWD_route.source_ip,
        )
        if FWD_arp_entry is None:
            return FWD_Result(
                FWD_ok=False,
                FWD_message=(
                    f"% FWD adjacency unresolved: {FWD_adjacency.FWD_target_ip} "
                    f"via {FWD_interface.name}"
                ),
                FWD_route=FWD_route,
            )
        FWD_frame = EthernetFrame(
            destination=FWD_arp_entry.mac_address,
            source=FWD_interface.mac_address,
            ethertype=ETHERTYPE_IPV4,
            payload=FWD_packet,
        )
        FWD_raw_frame = FWD_frame.to_bytes(pad=True)
        FWD_port.send_frame(FWD_raw_frame)
        return FWD_Result(
            FWD_ok=True,
            FWD_message="",
            FWD_frame=FWD_raw_frame,
            FWD_route=FWD_route,
        )

    def _FWD_arp_table(self) -> ArpTable:
        return get_arp_table(self.FWD_state, self.FWD_arp_table)

    def _FWD_resolve_arp(
        self,
        FWD_destination_ip: str,
        FWD_interface: NetworkInterface,
        FWD_port: FWD_RawFramePort,
        FWD_source_ip: str,
    ):
        FWD_table = self._FWD_arp_table()
        FWD_entry = FWD_table.lookup(FWD_destination_ip, FWD_interface.name)
        if FWD_entry is not None:
            return FWD_entry

        try:
            FWD_request = ArpProtocol(FWD_table).build_request(
                FWD_interface,
                FWD_destination_ip,
                sender_ip=FWD_source_ip,
            )
        except ValueError:
            return None
        FWD_port.send_frame(FWD_request.to_bytes(pad=True))

        FWD_deadline = self.FWD_monotonic() + self.FWD_arp_timeout_seconds
        while self.FWD_monotonic() < FWD_deadline:
            FWD_entry = FWD_table.lookup(FWD_destination_ip, FWD_interface.name)
            if FWD_entry is not None:
                return FWD_entry
            FWD_remaining = FWD_deadline - self.FWD_monotonic()
            if FWD_remaining <= 0:
                break
            self.FWD_sleep(min(self.FWD_arp_poll_interval_seconds, FWD_remaining))
        return FWD_table.lookup(FWD_destination_ip, FWD_interface.name)
