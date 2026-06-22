from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class CapturedFrame:
    data: bytes
    captured_length: int
    original_length: int
    timestamp_seconds: int = 0
    timestamp_microseconds: int = 0


class PacketPort(Protocol):
    def open(self) -> None:
        """Open the packet I/O port."""

    def close(self) -> None:
        """Close the packet I/O port."""

    def recv_frame(self) -> bytes | None:
        """Return one Ethernet frame, or None when no frame is available."""

    def send_frame(self, frame: bytes) -> None:
        """Transmit one Ethernet frame."""

    def set_filter(self, expression: str) -> None:
        """Install a backend-specific packet filter."""
