from __future__ import annotations

import unittest
import io
from ipaddress import IPv4Network

from src.ARP import (
    ARP_EntryLearned,
    ARP_REPLY,
    ARP_REQUEST,
    ZERO_MAC,
    ArpPacket,
    ArpTable,
    get_arp_table,
    parse_arp_packet,
)
from src.ETHERNET import BROADCAST_MAC, ETHERTYPE_ARP, ETHERTYPE_IPV4, EthernetFrame, parse_ethernet_ii_frame
from src.ETHERNET.debug import set_ethernet_frame_brief_debug
from src.FIB import FIBEntry, FIB_table
from src.FWD import (
    FWD_Adjacency,
    FWD_AdjacencyError,
    FWD_AdjacencyRegistry,
    FWD_EthernetAdjacencyHandler,
    FWD_EthernetOutputHandler,
    FWD_Forwarder,
    FWD_InputDispatcher,
    FWD_default_forwarder,
    FWD_default_input_dispatcher,
)
from src.IFNET import InterfaceAddress, NetworkInterface
from src.CCmd import CliContext
from src.IP.ipv4 import IP_build_ipv4_packet
from src.RM import RMRoute
from src.SOCK import SOCK_AF_INET, SOCK_IPPROTO_ICMP, SOCK_SOCK_RAW, SOCK_sendto, SOCK_socket
from src.events import VVRP_event_bus


class FakeRawFramePort:
    def __init__(self, received_frames=()):
        self.frames = []
        self.received_frames = list(received_frames)

    def send_frame(self, frame: bytes) -> None:
        self.frames.append(bytes(frame))

    def recv_frame(self) -> bytes | None:
        if not self.received_frames:
            return None
        return self.received_frames.pop(0)


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
        self.assertEqual(1, len(port.frames))
        frame = parse_ethernet_ii_frame(port.frames[0])
        self.assertEqual(ETHERTYPE_ARP, frame.ethertype)

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

    def test_ethernet_adjacency_handler_resolves_gateway_or_direct_target(self):
        interface = fwd_interface("eth4")
        gateway_route = fwd_route(
            interface,
            "0.0.0.0/0",
            "192.0.2.10",
            next_hop="192.0.2.254",
        )
        direct_route = fwd_route(interface, "192.0.2.0/24", "192.0.2.10")
        packet = IP_build_ipv4_packet("192.0.2.10", "198.51.100.1", 1, b"hello")
        handler = FWD_EthernetAdjacencyHandler()

        gateway = handler.FWD_resolve_adjacency(packet, gateway_route, interface)
        direct = handler.FWD_resolve_adjacency(packet, direct_route, interface)

        self.assertEqual("192.0.2.254", gateway.FWD_target_ip)
        self.assertEqual("198.51.100.1", direct.FWD_target_ip)

    def test_adjacency_registry_dispatches_by_interface_type(self):
        class PppAdjacencyHandler:
            def FWD_resolve_adjacency(self, FWD_packet, FWD_route, FWD_interface):
                return FWD_Adjacency(FWD_target_ip="0.0.0.0")

        registry = FWD_AdjacencyRegistry({"ppp": PppAdjacencyHandler()})
        interface = fwd_interface("ppp0", kind="ppp")

        adjacency = registry.FWD_resolve_adjacency(
            b"packet",
            fwd_route(interface, "192.0.2.0/24", "192.0.2.10"),
            interface,
        )

        self.assertEqual("0.0.0.0", adjacency.FWD_target_ip)

    def test_adjacency_registry_reports_unregistered_media(self):
        registry = FWD_AdjacencyRegistry()
        interface = fwd_interface("tun0", kind="tunnel")

        with self.assertRaisesRegex(FWD_AdjacencyError, "unsupported adjacency media: tunnel"):
            registry.FWD_resolve_adjacency(
                b"packet",
                fwd_route(interface, "192.0.2.0/24", "192.0.2.10"),
                interface,
            )

    def test_fwd_sends_arp_request_then_ipv4_after_adjacency_is_learned(self):
        state = {}
        interface = fwd_interface("eth4")
        route = fwd_route(interface, "192.0.2.0/24", "192.0.2.10")
        packet = IP_build_ipv4_packet("192.0.2.10", "192.0.2.1", 1, b"hello")
        arp = ArpTable(event_publisher=VVRP_event_bus(state).VVRP_publish)

        class ResolvingPort(FakeRawFramePort):
            def send_frame(self, frame: bytes) -> None:
                super().send_frame(frame)
                parsed = parse_ethernet_ii_frame(frame)
                if parsed.ethertype == ETHERTYPE_ARP:
                    request = parse_arp_packet(parsed.payload)
                    if request.operation == ARP_REQUEST:
                        arp.learn(request.target_ip, "66:77:88:99:aa:bb", "eth4")

        port = ResolvingPort()
        result = FWD_EthernetOutputHandler(
            state,
            FWD_port_provider=lambda current_interface: port,
            FWD_arp_table=arp,
            FWD_arp_timeout_seconds=0.1,
        ).FWD_send_packet(packet, route, interface)

        self.assertTrue(result.FWD_ok)
        self.assertEqual(2, len(port.frames))
        arp_request = parse_ethernet_ii_frame(port.frames[0])
        self.assertEqual(ETHERTYPE_ARP, arp_request.ethertype)
        self.assertEqual("ff:ff:ff:ff:ff:ff", arp_request.destination)
        arp_packet = parse_arp_packet(arp_request.payload)
        self.assertEqual("192.0.2.1", arp_packet.target_ip)

        ipv4_frame = parse_ethernet_ii_frame(port.frames[1])
        self.assertEqual(ETHERTYPE_IPV4, ipv4_frame.ethertype)
        self.assertEqual("66:77:88:99:aa:bb", ipv4_frame.destination)
        self.assertEqual(packet, ipv4_frame.payload[: len(packet)])
        self.assertEqual([], VVRP_event_bus(state)._VVRP_handlers.get(ARP_EntryLearned, []))

    def test_fwd_writes_tx_frames_to_ethernet_debug(self):
        state = {}
        output = io.StringIO()
        ctx = CliContext(state=state, output=output)
        set_ethernet_frame_brief_debug(ctx, True)
        interface = fwd_interface("eth4")
        route = fwd_route(interface, "192.0.2.0/24", "192.0.2.10")
        packet = IP_build_ipv4_packet("192.0.2.10", "192.0.2.1", 1, b"hello")
        arp = ArpTable()
        arp.learn("192.0.2.1", "66:77:88:99:aa:bb", "eth4")

        result = FWD_EthernetOutputHandler(
            state,
            FWD_port_provider=lambda current_interface: FakeRawFramePort(),
            FWD_arp_table=arp,
            FWD_debug_ctx=ctx,
        ).FWD_send_packet(packet, route, interface)

        self.assertTrue(result.FWD_ok)
        self.assertIn("ETHERNET/FRAME: eth4 TX", output.getvalue())
        self.assertIn("type=IPv4(0x0800)", output.getvalue())

    def test_fwd_learns_arp_reply_from_output_port_while_resolving(self):
        state = {}
        interface = fwd_interface("eth4")
        route = fwd_route(interface, "192.0.2.0/24", "192.0.2.10")
        packet = IP_build_ipv4_packet("192.0.2.10", "192.0.2.1", 1, b"hello")
        reply = EthernetFrame(
            destination=interface.mac_address,
            source="66:77:88:99:aa:bb",
            ethertype=ETHERTYPE_ARP,
            payload=ArpPacket(
                operation=ARP_REPLY,
                sender_mac="66:77:88:99:aa:bb",
                sender_ip="192.0.2.1",
                target_mac=interface.mac_address,
                target_ip="192.0.2.10",
            ).to_bytes(),
        ).to_bytes(pad=True)
        port = FakeRawFramePort(received_frames=(reply,))
        arp = ArpTable(event_publisher=VVRP_event_bus(state).VVRP_publish)

        result = FWD_EthernetOutputHandler(
            state,
            FWD_port_provider=lambda current_interface: port,
            FWD_arp_table=arp,
            FWD_arp_timeout_seconds=0.1,
        ).FWD_send_packet(packet, route, interface)

        self.assertTrue(result.FWD_ok)
        self.assertIsNotNone(arp.lookup("192.0.2.1", "eth4"))
        self.assertEqual(2, len(port.frames))
        self.assertEqual(ETHERTYPE_IPV4, parse_ethernet_ii_frame(port.frames[1]).ethertype)

    def test_fwd_subscribes_for_arp_event_before_sending_request(self):
        state = {}
        interface = fwd_interface("eth4")
        route = fwd_route(interface, "192.0.2.0/24", "192.0.2.10")
        packet = IP_build_ipv4_packet("192.0.2.10", "192.0.2.1", 1, b"hello")
        arp = ArpTable(event_publisher=VVRP_event_bus(state).VVRP_publish)
        test_case = self

        class AssertingPort(FakeRawFramePort):
            def send_frame(self, frame: bytes) -> None:
                parsed = parse_ethernet_ii_frame(frame)
                if parsed.ethertype == ETHERTYPE_ARP:
                    test_case.assertTrue(VVRP_event_bus(state)._VVRP_handlers.get(ARP_EntryLearned))
                super().send_frame(frame)
                if parsed.ethertype == ETHERTYPE_ARP:
                    arp.learn("192.0.2.1", "66:77:88:99:aa:bb", "eth4")

        port = AssertingPort()
        result = FWD_EthernetOutputHandler(
            state,
            FWD_port_provider=lambda current_interface: port,
            FWD_arp_table=arp,
            FWD_arp_timeout_seconds=0.1,
        ).FWD_send_packet(packet, route, interface)

        self.assertTrue(result.FWD_ok)
        self.assertEqual(2, len(port.frames))

    def test_fwd_arp_wait_unsubscribes_after_timeout(self):
        state = {}
        interface = fwd_interface("eth4")
        route = fwd_route(interface, "192.0.2.0/24", "192.0.2.10")
        packet = IP_build_ipv4_packet("192.0.2.10", "192.0.2.1", 1, b"hello")
        port = FakeRawFramePort()
        bus = VVRP_event_bus(state)

        result = FWD_EthernetOutputHandler(
            state,
            FWD_port_provider=lambda current_interface: port,
            FWD_arp_table=ArpTable(event_publisher=bus.VVRP_publish),
            FWD_arp_timeout_seconds=0,
        ).FWD_send_packet(packet, route, interface)

        self.assertFalse(result.FWD_ok)
        self.assertEqual([], bus._VVRP_handlers.get(ARP_EntryLearned, []))

    def test_fwd_reports_unsupported_future_interface_type(self):
        state = {}
        interface = fwd_interface("ppp0", kind="ppp")
        route = fwd_route(interface, "192.0.2.0/24", "192.0.2.10")
        packet = IP_build_ipv4_packet("192.0.2.10", "192.0.2.1", 1, b"hello")
        forwarder = FWD_Forwarder(state, FWD_interfaces_provider=lambda: (interface,))

        result = forwarder.FWD_send_packet(packet, route)

        self.assertFalse(result.FWD_ok)
        self.assertIn("unsupported interface type: ppp", result.FWD_message)

    def test_fwd_input_dispatches_by_interface_type(self):
        calls = []

        class Handler:
            def FWD_handle_frame(self, FWD_interface, FWD_frame):
                calls.append((FWD_interface.name, FWD_frame))

        dispatcher = FWD_InputDispatcher({}, FWD_handlers={"ethernet": Handler()})

        dispatcher.FWD_handle_frame(fwd_interface("eth4"), b"frame")
        dispatcher.FWD_handle_frame(fwd_interface("ppp0", kind="ppp"), b"ignored")

        self.assertEqual([("eth4", b"frame")], calls)

    def test_default_fwd_input_dispatcher_delivers_ethernet_frame(self):
        from src.CCmd import CliContext
        from src.ETHERNET import build_ethernet_ii_frame
        from src.IP.ICMP.packet import ICMP_build_echo_request, ICMP_parse_echo
        from src.IP.ICMP.ping import (
            ICMP_build_ipv4_packet,
            ICMP_parse_ipv4_packet,
            g_ICMP_IPV4_PROTOCOL_ICMP,
        )

        ctx = CliContext()
        interface = fwd_interface("eth4")
        interface = NetworkInterface(
            name=interface.name,
            kind=interface.kind,
            index=interface.index,
            is_up=interface.is_up,
            mac_address=interface.mac_address,
            speed_mbps=interface.speed_mbps,
            ifnet_index=interface.ifnet_index,
            mtu=interface.mtu,
            addresses=(
                InterfaceAddress(
                    family="ipv4",
                    address="192.0.2.10",
                    prefix_length=24,
                ),
            ),
        )
        echo_request = ICMP_build_echo_request(0x1234, 1, b"hello")
        ipv4 = ICMP_build_ipv4_packet(
            "192.0.2.1",
            "192.0.2.10",
            g_ICMP_IPV4_PROTOCOL_ICMP,
            echo_request,
        )
        raw = build_ethernet_ii_frame(
            destination=interface.mac_address,
            source="66:77:88:99:aa:bb",
            ethertype=ETHERTYPE_IPV4,
            payload=ipv4,
        )
        sent = []
        dispatcher = FWD_default_input_dispatcher(
            ctx,
            FWD_ethernet_send_frame=lambda frame: sent.append(frame),
        )

        dispatcher.FWD_handle_frame(interface, raw)

        self.assertEqual(1, len(sent))
        reply_frame = parse_ethernet_ii_frame(sent[0])
        reply_ipv4 = ICMP_parse_ipv4_packet(reply_frame.payload)
        self.assertEqual("192.0.2.10", reply_ipv4.ICMP_source)
        self.assertEqual("192.0.2.1", reply_ipv4.ICMP_destination)
        echo = ICMP_parse_echo(reply_ipv4.ICMP_payload)
        self.assertIsNotNone(echo)
        self.assertTrue(echo.ICMP_is_echo_reply)

    def test_default_fwd_input_dispatcher_replies_to_arp_request_for_local_ip(self):
        from src.CCmd import CliContext

        ctx = CliContext()
        interface = NetworkInterface(
            name="eth4",
            kind="ethernet",
            index=1,
            is_up=True,
            mac_address="02:00:00:00:00:01",
            speed_mbps=1000,
            ifnet_index=1,
            mtu=1500,
            addresses=(
                InterfaceAddress(
                    family="ipv4",
                    address="192.0.2.10",
                    prefix_length=24,
                ),
            ),
        )
        request = ArpPacket(
            operation=ARP_REQUEST,
            sender_mac="66:77:88:99:aa:bb",
            sender_ip="192.0.2.1",
            target_mac=ZERO_MAC,
            target_ip="192.0.2.10",
        )
        raw = EthernetFrame(
            destination=BROADCAST_MAC,
            source="66:77:88:99:aa:bb",
            ethertype=ETHERTYPE_ARP,
            payload=request.to_bytes(),
        ).to_bytes()
        sent = []
        dispatcher = FWD_default_input_dispatcher(
            ctx,
            FWD_ethernet_send_frame=lambda frame: sent.append(frame),
        )

        dispatcher.FWD_handle_frame(interface, raw)

        self.assertEqual(1, len(sent))
        reply_frame = parse_ethernet_ii_frame(sent[0])
        self.assertEqual(ETHERTYPE_ARP, reply_frame.ethertype)
        self.assertEqual("66:77:88:99:aa:bb", reply_frame.destination)
        self.assertEqual("02:00:00:00:00:01", reply_frame.source)
        reply = parse_arp_packet(reply_frame.payload)
        self.assertEqual(ARP_REPLY, reply.operation)
        self.assertEqual("02:00:00:00:00:01", reply.sender_mac)
        self.assertEqual("192.0.2.10", reply.sender_ip)
        self.assertEqual("66:77:88:99:aa:bb", reply.target_mac)
        self.assertEqual("192.0.2.1", reply.target_ip)
        learned = get_arp_table(ctx.state).lookup("192.0.2.1", "eth4")
        self.assertIsNotNone(learned)
        self.assertEqual("66:77:88:99:aa:bb", learned.mac_address)

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
