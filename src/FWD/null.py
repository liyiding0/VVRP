from __future__ import annotations

from src.FIB import FIBEntry
from src.IFNET.models import NetworkInterface

from .models import FWD_Result


class FWD_NullOutputHandler:
    def FWD_send_packet(
        self,
        FWD_packet: bytes,
        FWD_route: FIBEntry,
        FWD_interface: NetworkInterface,
    ) -> FWD_Result:
        return FWD_Result(
            FWD_ok=True,
            FWD_route=FWD_route,
        )
