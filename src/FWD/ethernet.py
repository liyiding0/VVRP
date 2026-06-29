from __future__ import annotations

from collections.abc import Callable

from src.ETHERNET.output import ETHERNET_OutputHandler
from src.FIB import FIBEntry
from src.IFNET.models import NetworkInterface

from .models import FWD_RawFramePort, FWD_Result


class FWD_EthernetOutputHandler:
    def __init__(
        self,
        FWD_state: dict,
        *,
        FWD_port_provider: Callable[[NetworkInterface], FWD_RawFramePort] | None = None,
        FWD_arp_table=None,
        FWD_arp_timeout_seconds: float = 2.0,
        FWD_debug_ctx=None,
    ) -> None:
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
        FWD_frame, FWD_error = self.FWD_ethernet_output.ETHERNET_send_packet(
            FWD_packet,
            FWD_route,
            FWD_interface,
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
