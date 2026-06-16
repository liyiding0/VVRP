from __future__ import annotations

import ctypes
import unittest

from VVRP.DPlane import CapturedFrame
from VVRP.DPlane.Windows.npcap import (
    NpcapDevice,
    NpcapError,
    NpcapLibrary,
    NpcapPacketPort,
    _PcapIf,
    _PcapIfPointer,
    find_npcap_device_for_interface,
)
from VVRP.IFNET import NetworkInterface


def fake_interface() -> NetworkInterface:
    return NetworkInterface(
        name="eth1",
        ifnet_index=2,
        index=12,
        kind="ethernet",
        is_up=True,
        mac_address="00:11:22:33:44:55",
        mtu=1500,
        speed_mbps=1000,
        os_id="{12345678-1234-1234-1234-1234567890AB}",
        os_aliases=("Ethernet 1", r"\DEVICE\TCPIP_{12345678-1234-1234-1234-1234567890AB}"),
    )


class FakePacketLibrary:
    def __init__(self) -> None:
        self.open_args = None
        self.closed = []
        self.sent = []
        self.filters = []
        self.frames = [
            CapturedFrame(
                data=b"\x00\x01\x02",
                captured_length=3,
                original_length=3,
                timestamp_seconds=10,
                timestamp_microseconds=20,
            ),
            None,
        ]

    def open_live(self, device_name, snaplen, promiscuous, read_timeout_ms):
        self.open_args = (device_name, snaplen, promiscuous, read_timeout_ms)
        return object()

    def close(self, handle):
        self.closed.append(handle)

    def next_frame(self, handle):
        return self.frames.pop(0)

    def send_packet(self, handle, frame):
        self.sent.append(frame)

    def set_filter(self, handle, expression):
        self.filters.append(expression)


class FakePcapDll:
    def __init__(self) -> None:
        self.second = _PcapIf()
        self.second.next = _PcapIfPointer()
        self.second.name = b"\\Device\\NPF_{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}"
        self.second.description = b"Ethernet B"
        self.second.addresses = None
        self.second.flags = 0

        self.first = _PcapIf()
        self.first.next = ctypes.pointer(self.second)
        self.first.name = b"\\Device\\NPF_{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}"
        self.first.description = b"Ethernet A"
        self.first.addresses = None
        self.first.flags = 0

        self.first_pointer = ctypes.pointer(self.first)
        self.freed = False

    def pcap_findalldevs(self, alldevsp, errbuf):
        output = ctypes.cast(alldevsp, ctypes.POINTER(_PcapIfPointer))
        output[0] = self.first_pointer
        return 0

    def pcap_freealldevs(self, devices):
        self.freed = True


class NpcapTests(unittest.TestCase):
    def test_find_npcap_device_for_interface_matches_guid_and_alias(self):
        devices = (
            NpcapDevice(
                name=r"\Device\NPF_{12345678-1234-1234-1234-1234567890AB}",
                description="Some adapter",
            ),
            NpcapDevice(name=r"\Device\NPF_{99999999-9999-9999-9999-999999999999}"),
        )

        self.assertEqual(devices[0], find_npcap_device_for_interface(fake_interface(), devices))

        alias_only = (
            NpcapDevice(
                name=r"\Device\NPF_{99999999-9999-9999-9999-999999999999}",
                description="Ethernet 1",
            ),
        )
        self.assertEqual(alias_only[0], find_npcap_device_for_interface(fake_interface(), alias_only))

    def test_npcap_packet_port_lifecycle_recv_send_and_filter(self):
        library = FakePacketLibrary()
        port = NpcapPacketPort(
            r"\Device\NPF_{12345678-1234-1234-1234-1234567890AB}",
            library=library,
            snaplen=2048,
            promiscuous=True,
            read_timeout_ms=50,
        )

        with self.assertRaises(NpcapError):
            port.recv_frame()

        with port:
            self.assertTrue(port.is_open)
            self.assertEqual(
                (r"\Device\NPF_{12345678-1234-1234-1234-1234567890AB}", 2048, True, 50),
                library.open_args,
            )
            self.assertEqual(b"\x00\x01\x02", port.recv_frame())
            self.assertIsNone(port.recv_frame())
            port.send_frame(b"\xff" * 14)
            port.set_filter("arp or ip")

        self.assertFalse(port.is_open)
        self.assertEqual([b"\xff" * 14], library.sent)
        self.assertEqual(["arp or ip"], library.filters)
        self.assertEqual(1, len(library.closed))

    def test_npcap_packet_port_rejects_empty_frame(self):
        port = NpcapPacketPort("dev", library=FakePacketLibrary())
        port.open()

        with self.assertRaisesRegex(NpcapError, "empty Ethernet frame"):
            port.send_frame(b"")

    def test_npcap_library_lists_devices_and_frees_list(self):
        dll = FakePcapDll()
        library = NpcapLibrary(dll=dll)

        devices = library.list_devices()

        self.assertEqual(
            (
                NpcapDevice(
                    name=r"\Device\NPF_{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}",
                    description="Ethernet A",
                ),
                NpcapDevice(
                    name=r"\Device\NPF_{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}",
                    description="Ethernet B",
                ),
            ),
            devices,
        )
        self.assertTrue(dll.freed)


if __name__ == "__main__":
    unittest.main()
