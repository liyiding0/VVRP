from __future__ import annotations

from collections.abc import Callable

from src.ETHERNET.output import ETHERNET_OutputHandler
from src.FIB import FIBEntry
from src.IFNET.models import NetworkInterface

from .adjacency import FWD_AdjacencyError, FWD_AdjacencyRegistry, FWD_default_adjacency_registry
from .models import FWD_RawFramePort, FWD_Result


class FWD_EthernetOutputHandler:
    def __init__(
        self,
        FWD_state: dict,
        *,
        FWD_port_provider: Callable[[NetworkInterface], FWD_RawFramePort] | None = None,
        FWD_arp_table=None,
        FWD_arp_timeout_seconds: float = 2.0,
        FWD_adjacency_registry: FWD_AdjacencyRegistry | None = None,
        FWD_debug_ctx=None,
    ) -> None:
        self.FWD_adjacency_registry = FWD_adjacency_registry or FWD_default_adjacency_registry()
        self.FWD_ethernet_output = ETHERNET_OutputHandler(
            FWD_state,
            ETHERNET_port_provider=FWD_port_provider,
            ETHERNET_arp_table=FWD_arp_table,
            ETHERNET_arp_timeout_seconds=FWD_arp_timeout_seconds,
            ETHERNET_debug_ctx=FWD_debug_ctx,
        )

    def FWD_send_packet(
        self,
        FWD_packet: bytes,
        FWD_route: FIBEntry,
        FWD_interface: NetworkInterface,
    ) -> FWD_Result:
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
        FWD_frame, FWD_error = self.FWD_ethernet_output.ETHERNET_send_packet(
            FWD_packet,
            FWD_route,
            FWD_interface,
            ETHERNET_target_ip=FWD_adjacency.FWD_target_ip,
        )
        if FWD_frame is None:
            return FWD_Result(
                FWD_ok=False,
                FWD_message=FWD_error.replace("% Ethernet", "% FWD"),
                FWD_route=FWD_route,
            )
        return FWD_Result(
            FWD_ok=True,
            FWD_message="",
            FWD_frame=FWD_frame,
            FWD_route=FWD_route,
        )
