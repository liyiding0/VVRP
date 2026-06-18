from __future__ import annotations

from typing import Protocol

from .frame import EthernetFrame, parse_ethernet_ii_frame


class RawEthernetPort(Protocol):
    def open(self) -> None:
        """Open the raw Ethernet frame I/O port."""

    def close(self) -> None:
        """Close the raw Ethernet frame I/O port."""

    def recv_frame(self) -> bytes | None:
        """Return one raw Ethernet frame, or None when no frame is available."""

    def send_frame(self, frame: bytes) -> None:
        """Transmit one raw Ethernet frame."""

    def set_filter(self, expression: str) -> None:
        """Install a backend-specific packet filter."""


class EthernetPort:
    def __init__(self, packet_port: RawEthernetPort) -> None:
        self.packet_port = packet_port

    def open(self) -> None:
        self.packet_port.open()

    def close(self) -> None:
        self.packet_port.close()

    def recv_frame(self) -> EthernetFrame | None:
        raw = self.packet_port.recv_frame()
        if raw is None:
            return None
        return parse_ethernet_ii_frame(raw)

    def send_frame(self, frame: EthernetFrame, pad: bool = True) -> None:
        self.packet_port.send_frame(frame.to_bytes(pad=pad))

    def set_filter(self, expression: str) -> None:
        self.packet_port.set_filter(expression)

    def __enter__(self) -> EthernetPort:
        self.open()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()
