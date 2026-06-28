from __future__ import annotations

import io
import time
import unittest
from dataclasses import replace

from src.ARP import ARP_REQUEST, ArpPacket
from src.CMD import CliContext
from src.DPlane import DPlane_PlatformInfo, DPlane_Result
from src.DPlane.input import DPlane_PacketInputService
from src.DPlane.Windows.npcap import NpcapDevice
from src.ETHERNET import ETHERTYPE_ARP, ETHERTYPE_IPV4, build_ethernet_ii_frame, parse_ethernet_ii_frame
from src.IFNET import InterfaceAddress, NetworkInterface
from src.ETHERNET.device import ETHERNET_commit_device_changes, ETHERNET_stage_device_install
from src.IFNET.state import set_interface_mac_address
from src.IP.state import IP_set_interface_addresses
from src.IP.ICMP.packet import ICMP_build_echo_request, ICMP_parse_echo
from src.IP.ICMP.ping import g_ICMP_IPV4_PROTOCOL_ICMP, ICMP_build_ipv4_packet, ICMP_parse_ipv4_packet


class FakeInterfaceProvider:
    def __init__(self, interfaces: tuple[NetworkInterface, ...]) -> None:
        self.interfaces = interfaces

    def list_interfaces(self) -> tuple[NetworkInterface, ...]:
        return self.interfaces


class FakeNpcapLibrary:
    def list_devices(self) -> tuple[NpcapDevice, ...]:
        return (NpcapDevice(name=r"\Device\NPF_eth4", description="eth4"),)


class FakeDPlaneBackend:
    def DPlane_list_packet_devices(self) -> tuple[NpcapDevice, ...]:
        return (NpcapDevice(name=r"\Device\NPF_eth4", description="eth4"),)

    @property
    def DPlane_platform(self):
        return DPlane_PlatformInfo(kind="windows", system="Windows")

    def DPlane_list_host_interfaces(self):
        return ()

    def DPlane_find_packet_device(self, DPlane_interface, DPlane_devices=None):
        for DPlane_device in tuple(DPlane_devices or self.DPlane_list_packet_devices()):
            if DPlane_interface.name in (DPlane_device.name, DPlane_device.description):
                return DPlane_device
        return None

    def DPlane_open_packet_port(self, DPlane_device):
        raise RuntimeError("FakeDPlaneBackend does not provide packet ports")

    def DPlane_set_interface_enabled(self, DPlane_interface, DPlane_enabled):
        return DPlane_Result(ok=True)

    def DPlane_install_forwarding_entry(self, DPlane_entry):
        return DPlane_Result(ok=True)

    def DPlane_delete_forwarding_entry(self, DPlane_entry):
        return DPlane_Result(ok=True)


class FakeDPlaneInputPort:
    def __init__(self, frames: tuple[bytes | None, ...]) -> None:
        self.frames = list(frames)
        self.sent: list[bytes] = []
        self.filters: list[str] = []
        self.opened = False
        self.closed = False

    def open(self) -> None:
        self.opened = True

    def close(self) -> None:
        self.closed = True

    def recv_frame(self) -> bytes | None:
        if not self.frames:
            time.sleep(0.01)
            return None
        return self.frames.pop(0)

    def send_frame(self, frame: bytes) -> None:
        self.sent.append(frame)

    def set_filter(self, expression: str) -> None:
        self.filters.append(expression)


class StopErrorDPlaneInputPort:
    def __init__(self) -> None:
        self.stop_requested = False
        self.opened = False
        self.closed = False

    def open(self) -> None:
        self.opened = True

    def close(self) -> None:
        self.closed = True
        self.stop_requested = True

    def recv_frame(self) -> bytes | None:
        while not self.stop_requested:
            time.sleep(0.01)
        raise RuntimeError("read error: PacketReceivePacket failed")

    def send_frame(self, frame: bytes) -> None:
        raise AssertionError("send_frame should not be called")

    def set_filter(self, expression: str) -> None:
        return None


class DPlanePacketInputTests(unittest.TestCase):
    def test_packet_input_replies_to_arp_and_icmp_echo_for_vvrp_ip(self):
        ctx = CliContext(output=io.StringIO())
        ETHERNET_stage_device_install(ctx.state, "eth4")
        ETHERNET_commit_device_changes(ctx.state)
        IP_set_interface_addresses(
            ctx.state,
            "eth4",
            (InterfaceAddress(family="ipv4", address="192.168.211.100", prefix_length=24),),
        )
        set_interface_mac_address(ctx.state, "eth4", "00:E0:4C:11:22:33")
        remote_mac = "5a:9f:62:39:a3:66"
        remote_ip = "192.168.211.1"

        arp_request = ArpPacket(
            operation=ARP_REQUEST,
            sender_mac=remote_mac,
            sender_ip=remote_ip,
            target_mac="00:00:00:00:00:00",
            target_ip="192.168.211.100",
        )
        arp_frame = build_ethernet_ii_frame(
            destination="ff:ff:ff:ff:ff:ff",
            source=remote_mac,
            ethertype=ETHERTYPE_ARP,
            payload=arp_request.to_bytes(),
        )
        echo_request = ICMP_build_echo_request(0x1234, 7, b"hello")
        ip_request = ICMP_build_ipv4_packet(
            remote_ip,
            "192.168.211.100",
            g_ICMP_IPV4_PROTOCOL_ICMP,
            echo_request,
            ICMP_ttl=64,
            ICMP_identification=0x4567,
        )
        icmp_frame = build_ethernet_ii_frame(
            destination="00:E0:4C:11:22:33",
            source=remote_mac,
            ethertype=ETHERTYPE_IPV4,
            payload=ip_request,
        )
        port = FakeDPlaneInputPort((arp_frame, icmp_frame))
        service = DPlane_PacketInputService(
            DPlane_ifnet_provider=FakeInterfaceProvider((fake_ethernet("eth4"),)),
            DPlane_backend=FakeDPlaneBackend(),
            DPlane_port_factory=lambda device: port,
        )

        self.assertIn("1 listener", service.DPlane_refresh(ctx))
        deadline = time.time() + 1
        while len(port.sent) < 2 and time.time() < deadline:
            time.sleep(0.01)
        service.DPlane_stop()

        self.assertEqual(["ether proto 0x0806 or ether proto 0x0800"], port.filters)
        self.assertEqual(2, len(port.sent))
        arp_reply = parse_ethernet_ii_frame(port.sent[0])
        self.assertEqual(ETHERTYPE_ARP, arp_reply.ethertype)
        self.assertEqual("00:e0:4c:11:22:33", arp_reply.source)
        self.assertEqual(remote_mac, arp_reply.destination)

        echo_reply = parse_ethernet_ii_frame(port.sent[1])
        self.assertEqual(ETHERTYPE_IPV4, echo_reply.ethertype)
        self.assertEqual("00:e0:4c:11:22:33", echo_reply.source)
        self.assertEqual(remote_mac, echo_reply.destination)
        ip_reply = ICMP_parse_ipv4_packet(echo_reply.payload)
        self.assertEqual("192.168.211.100", ip_reply.ICMP_source)
        self.assertEqual(remote_ip, ip_reply.ICMP_destination)
        echo = ICMP_parse_echo(ip_reply.ICMP_payload)
        self.assertIsNotNone(echo)
        self.assertTrue(echo.ICMP_is_echo_reply)
        self.assertEqual(0x1234, echo.ICMP_identifier)
        self.assertEqual(7, echo.ICMP_sequence)
        self.assertEqual(b"hello", echo.ICMP_payload)

    def test_packet_input_stop_suppresses_expected_read_error(self):
        output = io.StringIO()
        ctx = CliContext(output=output)
        ETHERNET_stage_device_install(ctx.state, "eth4")
        ETHERNET_commit_device_changes(ctx.state)
        IP_set_interface_addresses(
            ctx.state,
            "eth4",
            (InterfaceAddress(family="ipv4", address="192.168.211.100", prefix_length=24),),
        )
        port = StopErrorDPlaneInputPort()
        service = DPlane_PacketInputService(
            DPlane_ifnet_provider=FakeInterfaceProvider((fake_ethernet("eth4"),)),
            DPlane_backend=FakeDPlaneBackend(),
            DPlane_port_factory=lambda device: port,
        )

        self.assertIn("1 listener", service.DPlane_refresh(ctx))
        deadline = time.time() + 1
        while not port.opened and time.time() < deadline:
            time.sleep(0.01)

        service.DPlane_stop()

        self.assertTrue(port.closed)
        self.assertEqual("", output.getvalue())


def fake_ethernet(name: str) -> NetworkInterface:
    return replace(
        NetworkInterface(
            name=name,
            ifnet_index=0,
            index=7,
            kind="ethernet",
            is_up=True,
            mac_address="00:E0:4C:68:00:BE",
            mtu=1500,
            speed_mbps=1000,
        ),
        addresses=(),
    )


if __name__ == "__main__":
    unittest.main()

