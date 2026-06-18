from __future__ import annotations

from dataclasses import dataclass


ETHERNET_ADDRESS_LENGTH = 6
ETHERNET_HEADER_LENGTH = 14
ETHERNET_MIN_FRAME_LENGTH = 60
ETHERNET_MAX_PAYLOAD_LENGTH = 1500
ETHERNET_II_MIN_ETHERTYPE = 0x0600

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_8021Q = 0x8100
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_MPLS_UNICAST = 0x8847
ETHERTYPE_MPLS_MULTICAST = 0x8848

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


class EthernetFrameError(ValueError):
    pass


class UnsupportedEthernetFrame(EthernetFrameError):
    pass


@dataclass(frozen=True)
class EthernetFrame:
    destination: str
    source: str
    ethertype: int
    payload: bytes

    def to_bytes(self, pad: bool = False) -> bytes:
        frame = (
            parse_mac_address(self.destination)
            + parse_mac_address(self.source)
            + encode_ethertype(self.ethertype)
            + bytes(self.payload)
        )
        if pad and len(frame) < ETHERNET_MIN_FRAME_LENGTH:
            frame += b"\x00" * (ETHERNET_MIN_FRAME_LENGTH - len(frame))
        return frame


def parse_ethernet_ii_frame(data: bytes) -> EthernetFrame:
    raw = bytes(data)
    if len(raw) < ETHERNET_HEADER_LENGTH:
        raise EthernetFrameError("Ethernet frame is shorter than 14 bytes")

    type_or_length = int.from_bytes(raw[12:14], "big")
    if type_or_length < ETHERNET_II_MIN_ETHERTYPE:
        raise UnsupportedEthernetFrame("IEEE 802.3 LLC/SNAP frame is not supported")

    return EthernetFrame(
        destination=format_mac_address(raw[0:6]),
        source=format_mac_address(raw[6:12]),
        ethertype=type_or_length,
        payload=raw[14:],
    )


def build_ethernet_ii_frame(
    destination: str,
    source: str,
    ethertype: int,
    payload: bytes = b"",
    pad: bool = False,
) -> bytes:
    return EthernetFrame(
        destination=destination,
        source=source,
        ethertype=ethertype,
        payload=bytes(payload),
    ).to_bytes(pad=pad)


def parse_mac_address(value: str | bytes | bytearray | memoryview) -> bytes:
    if isinstance(value, str):
        normalized = value.strip().replace("-", ":").lower()
        parts = normalized.split(":")
        if len(parts) != ETHERNET_ADDRESS_LENGTH:
            raise EthernetFrameError(f"invalid MAC address: {value}")
        try:
            output = bytes(int(part, 16) for part in parts)
        except ValueError as exc:
            raise EthernetFrameError(f"invalid MAC address: {value}") from exc
    else:
        output = bytes(value)

    if len(output) != ETHERNET_ADDRESS_LENGTH:
        raise EthernetFrameError(f"invalid MAC address length: {len(output)}")
    return output


def format_mac_address(value: bytes | bytearray | memoryview) -> str:
    raw = parse_mac_address(value)
    return ":".join(f"{octet:02x}" for octet in raw)


def encode_ethertype(value: int) -> bytes:
    if not 0 <= int(value) <= 0xFFFF:
        raise EthernetFrameError(f"invalid EtherType: {value}")
    if int(value) < ETHERNET_II_MIN_ETHERTYPE:
        raise EthernetFrameError(f"EtherType value is in IEEE 802.3 length range: {value}")
    return int(value).to_bytes(2, "big")
