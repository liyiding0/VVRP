from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from src.FIB import FIBEntry
from src.IFNET.models import NetworkInterface


@dataclass(frozen=True)
class FWD_Result:
    FWD_ok: bool
    FWD_message: str = ""
    FWD_frame: bytes = b""
    FWD_route: FIBEntry | None = None


class FWD_OutputHandler(Protocol):
    def FWD_send_packet(
        self,
        FWD_packet: bytes,
        FWD_route: FIBEntry,
        FWD_interface: NetworkInterface,
    ) -> FWD_Result:
        """Send one network-layer packet through a concrete interface type."""


class FWD_InputHandler(Protocol):
    def FWD_handle_frame(
        self,
        FWD_interface: NetworkInterface,
        FWD_frame: bytes,
    ) -> None:
        """Receive one raw link-layer frame from a concrete interface type."""


class FWD_RawFramePort(Protocol):
    def send_frame(self, FWD_frame: bytes) -> None:
        """Send one raw link-layer frame."""

    def recv_frame(self) -> bytes | None:
        """Receive one raw link-layer frame, or None when no frame is available."""
