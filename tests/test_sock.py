from __future__ import annotations

import unittest
from ipaddress import IPv4Network

from src.FIB import FIB_sync_active_routes
from src.IFNET import NetworkInterface
from src.IP.ipv4 import IP_parse_ipv4_packet
from src.RM import RMRoute
from src.SOCK import (
    SOCK_AF_INET,
    SOCK_AF_INET6,
    SOCK_IPPROTO_ICMP,
    SOCK_IPPROTO_OSPF,
    SOCK_SOCK_DGRAM,
    SOCK_SOCK_RAW,
    SOCK_Error,
    SOCK_SendResult,
    SOCK_SockaddrIn,
    SOCK_bind,
    SOCK_close,
    SOCK_connect,
    SOCK_send,
    SOCK_sendto,
    SOCK_socket,
)


class FakeForwarder:
    def __init__(self):
        self.calls = []

    def FWD_send_packet(self, SOCK_packet, SOCK_route):
        self.calls.append((SOCK_packet, SOCK_route))
        return SOCK_SendResult(
            SOCK_ok=True,
            SOCK_message="sent",
            SOCK_packet=SOCK_packet,
            SOCK_route=SOCK_route,
        )


class SockTests(unittest.TestCase):
    def test_sock_socket_sendto_uses_fib_source_and_forwarder(self):
        state = {}
        FIB_sync_active_routes(
            state,
            (
                sock_route(
                    "eth4",
                    "192.0.2.0/24",
                    "192.0.2.10",
                    mtu=1500,
                ),
            ),
        )
        forwarder = FakeForwarder()
        sock = SOCK_socket(
            state,
            SOCK_AF_INET,
            SOCK_SOCK_RAW,
            SOCK_IPPROTO_OSPF,
            SOCK_forwarder=forwarder,
        )

        result = SOCK_sendto(
            sock,
            b"hello",
            SOCK_SockaddrIn("192.0.2.1"),
            SOCK_ttl=64,
            SOCK_identification=0x1234,
        )

        self.assertTrue(result.SOCK_ok)
        self.assertEqual("sent", result.SOCK_message)
        self.assertEqual(1, len(forwarder.calls))
        packet = IP_parse_ipv4_packet(forwarder.calls[0][0])
        self.assertEqual("192.0.2.10", packet.IP_source)
        self.assertEqual("192.0.2.1", packet.IP_destination)
        self.assertEqual(89, packet.IP_protocol)
        self.assertEqual(64, packet.IP_ttl)
        self.assertEqual(b"hello", packet.IP_payload)
        self.assertEqual("eth4", forwarder.calls[0][1].out_if_name)

    def test_sock_bind_overrides_source_address(self):
        state = {}
        FIB_sync_active_routes(
            state,
            (sock_route("eth4", "192.0.2.0/24", "192.0.2.10"),),
        )
        forwarder = FakeForwarder()
        sock = SOCK_socket(
            state,
            SOCK_AF_INET,
            SOCK_SOCK_RAW,
            SOCK_IPPROTO_ICMP,
            SOCK_forwarder=forwarder,
        )
        SOCK_bind(sock, ("192.0.2.99", 0))

        result = SOCK_sendto(sock, b"hello", ("192.0.2.1", 0))

        self.assertTrue(result.SOCK_ok)
        packet = IP_parse_ipv4_packet(forwarder.calls[0][0])
        self.assertEqual("192.0.2.99", packet.IP_source)

    def test_sock_connect_and_send_use_default_peer(self):
        state = {}
        FIB_sync_active_routes(
            state,
            (sock_route("eth4", "192.0.2.0/24", "192.0.2.10"),),
        )
        forwarder = FakeForwarder()
        sock = SOCK_socket(
            state,
            SOCK_AF_INET,
            SOCK_SOCK_RAW,
            SOCK_IPPROTO_ICMP,
            SOCK_forwarder=forwarder,
        )
        SOCK_connect(sock, "192.0.2.1")

        result = SOCK_send(sock, b"hello")

        self.assertTrue(result.SOCK_ok)
        packet = IP_parse_ipv4_packet(forwarder.calls[0][0])
        self.assertEqual("192.0.2.1", packet.IP_destination)

    def test_sock_sendto_reports_missing_route(self):
        sock = SOCK_socket({}, SOCK_AF_INET, SOCK_SOCK_RAW, SOCK_IPPROTO_ICMP)

        result = SOCK_sendto(sock, b"hello", "198.51.100.1")

        self.assertFalse(result.SOCK_ok)
        self.assertIn("No VVRP route to host", result.SOCK_message)

    def test_sock_sendto_checks_mtu_before_forwarding(self):
        state = {}
        FIB_sync_active_routes(
            state,
            (sock_route("eth4", "192.0.2.0/24", "192.0.2.10", mtu=24),),
        )
        forwarder = FakeForwarder()

        sock = SOCK_socket(
            state,
            SOCK_AF_INET,
            SOCK_SOCK_RAW,
            SOCK_IPPROTO_ICMP,
            SOCK_forwarder=forwarder,
        )

        result = SOCK_sendto(
            sock,
            b"hello",
            "192.0.2.1",
        )

        self.assertFalse(result.SOCK_ok)
        self.assertIn("Packet size exceeds interface MTU", result.SOCK_message)
        self.assertEqual([], forwarder.calls)

    def test_sock_without_forwarder_keeps_packet_and_route_for_future_fwd(self):
        state = {}
        FIB_sync_active_routes(
            state,
            (sock_route("eth4", "192.0.2.0/24", "192.0.2.10"),),
        )

        sock = SOCK_socket(state, SOCK_AF_INET, SOCK_SOCK_RAW, SOCK_IPPROTO_ICMP)

        result = SOCK_sendto(sock, b"hello", "192.0.2.1")

        self.assertFalse(result.SOCK_ok)
        self.assertIn("FWD", result.SOCK_message)
        self.assertTrue(result.SOCK_packet)
        self.assertIsNotNone(result.SOCK_route)
        self.assertEqual("eth4", result.SOCK_route.out_if_name)

    def test_sock_rejects_unsupported_domain_and_type(self):
        with self.assertRaises(SOCK_Error):
            SOCK_socket({}, SOCK_AF_INET6, SOCK_SOCK_RAW, SOCK_IPPROTO_ICMP)
        with self.assertRaises(SOCK_Error):
            SOCK_socket({}, SOCK_AF_INET, SOCK_SOCK_DGRAM, SOCK_IPPROTO_ICMP)

    def test_sock_close_rejects_later_send(self):
        sock = SOCK_socket({}, SOCK_AF_INET, SOCK_SOCK_RAW, SOCK_IPPROTO_ICMP)

        SOCK_close(sock)

        with self.assertRaises(SOCK_Error):
            SOCK_sendto(sock, b"hello", "192.0.2.1")


def sock_route(name: str, destination: str, source_ip: str, mtu: int | None = 1500):
    return RMRoute(
        destination=IPv4Network(destination),
        source="connected",
        interface=NetworkInterface(
            name=name,
            kind="ethernet",
            index=1,
            is_up=True,
            mac_address="02:00:00:00:00:01",
            speed_mbps=1000,
            ifnet_index=1,
            mtu=mtu,
        ),
        source_ip=source_ip,
    )
