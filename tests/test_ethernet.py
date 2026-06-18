from __future__ import annotations

import unittest

from VVRP.ETHERNET import (
    ETHERNET_MIN_FRAME_LENGTH,
    ETHERTYPE_ARP,
    ETHERTYPE_IPV4,
    EthernetFrame,
    EthernetFrameError,
    EthernetPort,
    UnsupportedEthernetFrame,
    build_ethernet_ii_frame,
    encode_ethertype,
    format_mac_address,
    parse_ethernet_ii_frame,
    parse_mac_address,
)


class FakePacketPort:
    def __init__(self, frames=()) -> None:
        self.frames = list(frames)
        self.sent = []
        self.filters = []
        self.opened = False
        self.closed = False

    def open(self) -> None:
        self.opened = True

    def close(self) -> None:
        self.closed = True

    def recv_frame(self) -> bytes | None:
        if not self.frames:
            return None
        return self.frames.pop(0)

    def send_frame(self, frame: bytes) -> None:
        self.sent.append(frame)

    def set_filter(self, expression: str) -> None:
        self.filters.append(expression)


class EthernetFrameTests(unittest.TestCase):
    def test_parse_and_build_ethernet_ii_frame(self):
        raw = build_ethernet_ii_frame(
            destination="ff:ff:ff:ff:ff:ff",
            source="00:11:22:33:44:55",
            ethertype=ETHERTYPE_IPV4,
            payload=b"hello",
        )

        frame = parse_ethernet_ii_frame(raw)

        self.assertEqual("ff:ff:ff:ff:ff:ff", frame.destination)
        self.assertEqual("00:11:22:33:44:55", frame.source)
        self.assertEqual(ETHERTYPE_IPV4, frame.ethertype)
        self.assertEqual(b"hello", frame.payload)
        self.assertEqual(raw, frame.to_bytes())

    def test_build_can_pad_to_minimum_ethernet_frame_length(self):
        frame = EthernetFrame(
            destination="ff:ff:ff:ff:ff:ff",
            source="00:11:22:33:44:55",
            ethertype=ETHERTYPE_ARP,
            payload=b"",
        )

        raw = frame.to_bytes(pad=True)

        self.assertEqual(ETHERNET_MIN_FRAME_LENGTH, len(raw))
        self.assertTrue(raw.startswith(bytes.fromhex("ffffffffffff0011223344550806")))

    def test_rejects_ieee_802_3_length_frame(self):
        raw = (
            bytes.fromhex("ffffffffffff001122334455")
            + (46).to_bytes(2, "big")
            + (b"\x00" * 46)
        )

        with self.assertRaisesRegex(UnsupportedEthernetFrame, "802.3"):
            parse_ethernet_ii_frame(raw)

        with self.assertRaisesRegex(EthernetFrameError, "802.3 length range"):
            encode_ethertype(46)

    def test_rejects_short_frame_and_bad_mac(self):
        with self.assertRaisesRegex(EthernetFrameError, "shorter than 14 bytes"):
            parse_ethernet_ii_frame(b"\x00" * 13)

        with self.assertRaisesRegex(EthernetFrameError, "invalid MAC address"):
            parse_mac_address("00:11:22:33:44")

    def test_mac_helpers_accept_bytes_and_hyphen_text(self):
        self.assertEqual(bytes.fromhex("001122334455"), parse_mac_address("00-11-22-33-44-55"))
        self.assertEqual("00:11:22:33:44:55", format_mac_address(bytes.fromhex("001122334455")))


class EthernetPortTests(unittest.TestCase):
    def test_wraps_packet_port_with_ethernet_frame_semantics(self):
        raw = build_ethernet_ii_frame(
            destination="ff:ff:ff:ff:ff:ff",
            source="00:11:22:33:44:55",
            ethertype=ETHERTYPE_ARP,
            payload=b"arp",
        )
        packet_port = FakePacketPort(frames=(raw, None))
        port = EthernetPort(packet_port)

        with port:
            frame = port.recv_frame()
            self.assertIsNotNone(frame)
            self.assertEqual(ETHERTYPE_ARP, frame.ethertype)
            self.assertIsNone(port.recv_frame())
            port.send_frame(
                EthernetFrame(
                    destination="ff:ff:ff:ff:ff:ff",
                    source="00:11:22:33:44:55",
                    ethertype=ETHERTYPE_IPV4,
                    payload=b"ip",
                )
            )
            port.set_filter("ether proto 0x0800")

        self.assertTrue(packet_port.opened)
        self.assertTrue(packet_port.closed)
        self.assertEqual(ETHERNET_MIN_FRAME_LENGTH, len(packet_port.sent[0]))
        self.assertEqual(["ether proto 0x0800"], packet_port.filters)


if __name__ == "__main__":
    unittest.main()
