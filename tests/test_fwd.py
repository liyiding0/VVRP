from __future__ import annotations

import unittest
from ipaddress import IPv4Network

from src.ARP import ArpTable
from src.ETHERNET import ETHERTYPE_IPV4, parse_ethernet_ii_frame
from src.FIB import FIBEntry, FIB_table
from src.FWD import FWD_EthernetOutputHandler, FWD_Forwarder, FWD_default_forwarder
from src.IFNET import NetworkInterface
from src.IP.ipv4 import IP_build_ipv4_packet
from src.RM import RMRoute
from src.SOCK import SOCK_AF_INET, SOCK_IPPROTO_ICMP, SOCK_SOCK_RAW, SOCK_sendto, SOCK_socket


class FakeRawFramePort:
    def __init__(self):
        self.frames = []

    def send_frame(self, frame: bytes) -> None:
        self.frames.append(bytes(frame))


class FwdTests(unittest.TestCase):
    def test_fwd_dispatches_ipv4_packet_to_ethernet_handler(self):
        state = {}
        interface = fwd_interface("eth4")
        route = fwd_route(interface, "192.0.2.0/24", "192.0.2.10")
        packet = IP_build_ipv4_packet("192.0.2.10", "192.0.2.1", 1, b"hello")
        arp = ArpTable()
        arp.learn("192.0.2.1", "66:77:88:99:aa:bb", "eth4")
        port = FakeRawFramePort()
        forwarder = FWD_default_forwarder(
            state,
            FWD_interfaces_provider=lambda: (interface,),
            FWD_ethernet_port_provider=lambda current_interface: port,
            FWD_arp_table=arp,
        )

        result = forwarder.FWD_send_packet(packet, route)

        self.assertTrue(result.FWD_ok)
        self.assertEqual(1, len(port.frames))
        frame = parse_ethernet_ii_frame(port.frames[0])
        self.assertEqual("66:77:88:99:aa:bb", frame.destination)
        self.assertEqual("02:00:00:00:00:01", frame.source)
        self.assertEqual(ETHERTYPE_IPV4, frame.ethertype)
        self.assertEqual(packet, frame.payload[: len(packet)])

    def test_fwd_reports_unresolved_ethernet_adjacency(self):
        state = {}
        interface = fwd_interface("eth4")
        route = fwd_route(interface, "192.0.2.0/24", "192.0.2.10")
        packet = IP_build_ipv4_packet("192.0.2.10", "192.0.2.1", 1, b"hello")
        port = FakeRawFramePort()
        handler = FWD_EthernetOutputHandler(
            state,
            FWD_port_provider=lambda current_interface: port,
            FWD_arp_table=ArpTable(),
        )

        result = handler.FWD_send_packet(packet, route, interface)

        self.assertFalse(result.FWD_ok)
        self.assertIn("adjacency unresolved", result.FWD_message)
        self.assertEqual([], port.frames)

    def test_fwd_uses_route_next_hop_for_ethernet_adjacency(self):
        state = {}
        interface = fwd_interface("eth4")
        route = fwd_route(
            interface,
            "0.0.0.0/0",
            "192.0.2.10",
            next_hop="192.0.2.254",
        )
        packet = IP_build_ipv4_packet("192.0.2.10", "198.51.100.1", 1, b"hello")
        arp = ArpTable()
        arp.learn("192.0.2.254", "66:77:88:99:aa:bb", "eth4")
        port = FakeRawFramePort()

        result = FWD_EthernetOutputHandler(
            state,
            FWD_port_provider=lambda current_interface: port,
            FWD_arp_table=arp,
        ).FWD_send_packet(packet, route, interface)

        self.assertTrue(result.FWD_ok)
        frame = parse_ethernet_ii_frame(port.frames[0])
        self.assertEqual("66:77:88:99:aa:bb", frame.destination)

    def test_fwd_reports_unsupported_future_interface_type(self):
        state = {}
        interface = fwd_interface("ppp0", kind="ppp")
        route = fwd_route(interface, "192.0.2.0/24", "192.0.2.10")
        packet = IP_build_ipv4_packet("192.0.2.10", "192.0.2.1", 1, b"hello")
        forwarder = FWD_Forwarder(state, FWD_interfaces_provider=lambda: (interface,))

        result = forwarder.FWD_send_packet(packet, route)

        self.assertFalse(result.FWD_ok)
        self.assertIn("unsupported interface type: ppp", result.FWD_message)

    def test_sock_can_use_fwd_forwarder(self):
        state = {}
        interface = fwd_interface("eth4")
        FIB_table(state).FIB_install(fwd_route(interface, "192.0.2.0/24", "192.0.2.10"))
        arp = ArpTable()
        arp.learn("192.0.2.1", "66:77:88:99:aa:bb", "eth4")
        port = FakeRawFramePort()
        sock = SOCK_socket(
            state,
            SOCK_AF_INET,
            SOCK_SOCK_RAW,
            SOCK_IPPROTO_ICMP,
            SOCK_forwarder=FWD_default_forwarder(
                state,
                FWD_interfaces_provider=lambda: (interface,),
                FWD_ethernet_port_provider=lambda current_interface: port,
                FWD_arp_table=arp,
            ),
        )

        result = SOCK_sendto(sock, b"hello", "192.0.2.1")

        self.assertTrue(result.SOCK_ok)
        self.assertEqual(1, len(port.frames))
        self.assertEqual("eth4", FIB_table(state).FIB_lookup("192.0.2.1").out_if_name)


def fwd_interface(name: str, kind: str = "ethernet") -> NetworkInterface:
    return NetworkInterface(
        name=name,
        kind=kind,
        index=1,
        is_up=True,
        mac_address="02:00:00:00:00:01",
        speed_mbps=1000,
        ifnet_index=1,
        mtu=1500,
    )


def fwd_route(
    interface: NetworkInterface,
    destination: str,
    source_ip: str,
    next_hop: str = "",
) -> FIBEntry:
    return FIBEntry(
        destination=IPv4Network(destination),
        out_if_name=interface.name,
        out_if_index=interface.ifnet_index,
        source_ip=source_ip,
        source_mac=interface.mac_address,
        next_hop_ip=next_hop,
        mtu=interface.mtu,
    )
