from __future__ import annotations

from collections.abc import Callable

from src.FIB import FIBEntry
from src.IFNET.models import NetworkInterface

from .models import FWD_Result


class FWD_LoopbackOutputHandler:
    def __init__(
        self,
        FWD_local_ipv4_input: Callable[[bytes], bytes | None],
    ) -> None:
        self.FWD_local_ipv4_input = FWD_local_ipv4_input

    def FWD_send_packet(
        self,
        FWD_packet: bytes,
        FWD_route: FIBEntry,
        FWD_interface: NetworkInterface,
    ) -> FWD_Result:
        FWD_reply = self.FWD_local_ipv4_input(FWD_packet)
        if FWD_reply is not None:
            self.FWD_local_ipv4_input(FWD_reply)
        return FWD_Result(
            FWD_ok=True,
            FWD_frame=FWD_packet,
            FWD_route=FWD_route,
        )
