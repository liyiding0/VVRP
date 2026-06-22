from __future__ import annotations

import io
import time
import unittest
from dataclasses import replace

from VVRP.ARP import ARP_REQUEST, ArpPacket
from VVRP.CCmd import CliContext
from VVRP.DPlane.Windows.npcap import NpcapDevice
from VVRP.ETHERNET import ETHERTYPE_ARP, ETHERTYPE_IPV4, build_ethernet_ii_frame, parse_ethernet_ii_frame
from VVRP.IFNET import InterfaceAddress, NetworkInterface
from VVRP.IFNET.imports import commit_imports, stage_import_interface
from VVRP.IFNET.state import set_interface_addresses, set_interface_mac_address
from VVRP.IP.ICMP.packet import build_icmp_echo_request, parse_icmp_echo
from VVRP.IP.ICMP.responder import IcmpResponderService
from VVRP.IP.ICMP.ping import IPV4_PROTOCOL_ICMP, build_ipv4_packet, parse_ipv4_packet


class FakeInterfaceProvider:
    def __init__(self, interfaces: tuple[NetworkInterface, ...]) -> None:
        self.interfaces = interfaces

    def list_interfaces(self) -> tuple[NetworkInterface, ...]:
        return self.interfaces


class FakeNpcapLibrary:
    def list_devices(self) -> tuple[NpcapDevice, ...]:
        return (NpcapDevice(name=r"\Device\NPF_eth4", description="eth4"),)


class FakeResponderPort:
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


class IcmpResponderTests(unittest.TestCase):
    def test_responder_replies_to_arp_and_icmp_echo_for_vvrp_ip(self):
        ctx = CliContext(output=io.StringIO())
        stage_import_interface(ctx.state, "eth4")
        commit_imports(ctx.state)
        set_interface_addresses(
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
        echo_request = build_icmp_echo_request(0x1234, 7, b"hello")
        ip_request = build_ipv4_packet(
            remote_ip,
            "192.168.211.100",
            IPV4_PROTOCOL_ICMP,
            echo_request,
            ttl=64,
            identification=0x4567,
        )
        icmp_frame = build_ethernet_ii_frame(
            destination="00:E0:4C:11:22:33",
            source=remote_mac,
            ethertype=ETHERTYPE_IPV4,
            payload=ip_request,
        )
        port = FakeResponderPort((arp_frame, icmp_frame))
        service = IcmpResponderService(
            ifnet_provider=FakeInterfaceProvider((fake_ethernet("eth4"),)),
            npcap_library=FakeNpcapLibrary(),
            port_factory=lambda device_name: port,
        )

        self.assertIn("1 listener", service.refresh(ctx))
        deadline = time.time() + 1
        while len(port.sent) < 2 and time.time() < deadline:
            time.sleep(0.01)
        service.stop()

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
        ip_reply = parse_ipv4_packet(echo_reply.payload)
        self.assertEqual("192.168.211.100", ip_reply.source)
        self.assertEqual(remote_ip, ip_reply.destination)
        echo = parse_icmp_echo(ip_reply.payload)
        self.assertIsNotNone(echo)
        self.assertTrue(echo.is_echo_reply)
        self.assertEqual(0x1234, echo.identifier)
        self.assertEqual(7, echo.sequence)
        self.assertEqual(b"hello", echo.payload)


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
            os_id=name,
        ),
        addresses=(),
    )


if __name__ == "__main__":
    unittest.main()
