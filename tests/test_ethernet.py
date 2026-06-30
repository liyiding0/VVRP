from __future__ import annotations

import io
import unittest
from ipaddress import IPv4Network

from src.ETHERNET import (
    ETHERNET_MIN_FRAME_LENGTH,
    ETHERTYPE_ARP,
    ETHERTYPE_IPV4,
    EthernetFrame,
    EthernetFrameError,
    EthernetPort,
    UnsupportedEthernetFrame,
    build_ethernet_ii_frame,
    debug_ethernet_frame,
    encode_ethertype,
    format_ethernet_frame_brief,
    format_mac_address,
    is_ethernet_frame_brief_debug_enabled,
    parse_ethernet_ii_frame,
    parse_mac_address,
    register_ethernet_commands,
)
from src.CMD import CliContext, CommandParser, CommandRegistry, ParseStatus, dispatch_line
from src.CMD.examples import build_default_registry
from src.ARP import ARP_REPLY, ARP_REQUEST, ArpPacket, get_arp_table
from src.ETHERNET.adjacency import ETHERNET_resolve_adjacency
from src.ETHERNET.device import ETHERNET_commit_device_changes, ETHERNET_stage_device_install
from src.ETHERNET.state import ETHERNET_set_interface_mac_address
from src.FIB import FIBEntry
from src.IFNET.interfaces import IFNET_ethernet_interface_snapshots
from src.IFNET import InterfaceAddress, NetworkInterface
from src.IP.ipv4 import IP_build_ipv4_packet


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


def fake_interface() -> NetworkInterface:
    return NetworkInterface(
        name="eth4",
        ifnet_index=1,
        index=7,
        kind="ethernet",
        is_up=True,
        mac_address="00:11:22:33:44:55",
        mtu=1500,
        speed_mbps=1000,
        addresses=(InterfaceAddress(family="ipv4", address="10.0.0.1", prefix_length=24),),
    )


class FakeInterfaceProvider:
    def list_interfaces(self) -> tuple[NetworkInterface, ...]:
        return (fake_interface(),)


class EthernetAdjacencyTests(unittest.TestCase):
    def test_gateway_route_uses_fib_next_hop(self):
        packet = IP_build_ipv4_packet("192.0.2.10", "198.51.100.1", 1, b"hello")
        route = self._route(next_hop_ip="192.0.2.254")

        adjacency = ETHERNET_resolve_adjacency(packet, route)

        self.assertEqual("192.0.2.254", adjacency.ETHERNET_target_ip)

    def test_direct_route_uses_ipv4_destination(self):
        packet = IP_build_ipv4_packet("192.0.2.10", "198.51.100.1", 1, b"hello")

        adjacency = ETHERNET_resolve_adjacency(packet, self._route())

        self.assertEqual("198.51.100.1", adjacency.ETHERNET_target_ip)

    @staticmethod
    def _route(*, next_hop_ip: str = "") -> FIBEntry:
        interface = fake_interface()
        return FIBEntry(
            destination=IPv4Network("0.0.0.0/0"),
            out_if_name=interface.name,
            out_if_index=interface.ifnet_index,
            source_ip="192.0.2.10",
            source_mac=interface.mac_address,
            next_hop_ip=next_hop_ip,
            mtu=interface.mtu,
        )


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


class EthernetDebugTests(unittest.TestCase):
    def test_format_ethernet_frame_brief(self):
        frame = EthernetFrame(
            destination="ff:ff:ff:ff:ff:ff",
            source="00:11:22:33:44:55",
            ethertype=ETHERTYPE_ARP,
            payload=b"arp",
        )

        self.assertEqual(
            "ETHERNET/FRAME: eth2 RX dst=ff:ff:ff:ff:ff:ff "
            "src=00:11:22:33:44:55 type=ARP(0x0806) len=17",
            format_ethernet_frame_brief("eth2", "rx", frame),
        )

    def test_debug_ethernet_frame_writes_only_when_enabled(self):
        output = io.StringIO()
        ctx = CliContext(output=output)
        frame = EthernetFrame(
            destination="ff:ff:ff:ff:ff:ff",
            source="00:11:22:33:44:55",
            ethertype=ETHERTYPE_IPV4,
            payload=b"ip",
        )

        debug_ethernet_frame(ctx, "eth2", "tx", frame)
        self.assertEqual("", output.getvalue())

        registry = build_default_registry()
        ctx.push_mode("privileged")
        self.assertTrue(dispatch_line(ctx, registry, "debugging ethernet frame brief").executed)
        output.truncate(0)
        output.seek(0)

        debug_ethernet_frame(ctx, "eth2", "tx", frame)

        self.assertIn("ETHERNET/FRAME: eth2 TX", output.getvalue())
        self.assertIn("type=IPv4(0x0800)", output.getvalue())

    def test_debugging_ethernet_commands(self):
        registry = build_default_registry()
        output = io.StringIO()
        ctx = CliContext(output=output)
        ctx.push_mode("privileged")

        self.assertFalse(is_ethernet_frame_brief_debug_enabled(ctx))
        self.assertTrue(dispatch_line(ctx, registry, "show debugging ethernet").executed)
        self.assertIn("off", output.getvalue())

    def test_main_ethernet_input_writes_rx_to_current_debug_output(self):
        from src.ETHERNET.input import ETHERNET_InputHandler

        stale_output = io.StringIO()
        current_output = io.StringIO()
        ctx = CliContext(output=current_output)
        registry = CommandRegistry()
        register_ethernet_commands(registry)
        ctx.push_mode("privileged")
        self.assertTrue(dispatch_line(ctx, registry, "debugging ethernet frame brief").executed)
        runtime_ctx = CliContext(state=ctx.state, output=stale_output)
        raw = build_ethernet_ii_frame(
            destination="00:11:22:33:44:55",
            source="66:77:88:99:aa:bb",
            ethertype=ETHERTYPE_IPV4,
            payload=b"not-an-ip-packet",
        )
        ETHERNET_InputHandler(runtime_ctx, lambda frame: None).ETHERNET_handle_frame(
            fake_interface(),
            raw,
        )

        self.assertIn("ETHERNET/FRAME: eth4 RX", current_output.getvalue())
        self.assertEqual("", stale_output.getvalue())

    def test_ethernet_input_learns_arp_seen_on_interface_even_for_other_subnet(self):
        from src.ETHERNET.input import ETHERNET_InputHandler

        ctx = CliContext(output=io.StringIO())
        interface = fake_interface()
        arp = ArpPacket(
            operation=ARP_REQUEST,
            sender_mac="66:77:88:99:aa:bb",
            sender_ip="192.168.21.1",
            target_mac="00:00:00:00:00:00",
            target_ip="192.168.21.2",
        )
        raw = build_ethernet_ii_frame(
            destination="ff:ff:ff:ff:ff:ff",
            source="66:77:88:99:aa:bb",
            ethertype=ETHERTYPE_ARP,
            payload=arp.to_bytes(),
        )

        ETHERNET_InputHandler(ctx, lambda frame: None).ETHERNET_handle_frame(interface, raw)

        learned = get_arp_table(ctx.state).lookup("192.168.21.1", interface.name)
        self.assertIsNotNone(learned)
        self.assertEqual("66:77:88:99:aa:bb", learned.mac_address)

    def test_runtime_snapshot_uses_configured_ethernet_mac_not_host_mac(self):
        ctx = CliContext(output=io.StringIO())
        ETHERNET_stage_device_install(ctx.state, "eth4")
        ETHERNET_commit_device_changes(ctx.state)
        ETHERNET_set_interface_mac_address(ctx.state, "eth4", "02:00:00:00:00:01")

        interfaces = IFNET_ethernet_interface_snapshots(ctx.state, (fake_interface(),))
        ethernet = next(interface for interface in interfaces if interface.name == "eth4")

        self.assertEqual("02:00:00:00:00:01", ethernet.mac_address)
        self.assertEqual("00:11:22:33:44:55", fake_interface().mac_address)

    def test_debugging_ethernet_command_help_and_modes(self):
        registry = CommandRegistry()
        register_ethernet_commands(registry)
        parser = CommandParser(registry)

        for mode in ("privileged", "config", "hidden"):
            self.assertTrue(parser.parse("debugging ethernet frame brief", mode=mode).executable, mode)
            self.assertTrue(parser.parse("no debugging ethernet frame brief", mode=mode).executable, mode)
            self.assertTrue(parser.parse("show debugging ethernet", mode=mode).executable, mode)
        for mode in ("user", "interface", "host-interface"):
            self.assertEqual(ParseStatus.INVALID, parser.parse("debugging ethernet frame brief", mode=mode).status)
            self.assertEqual(ParseStatus.INVALID, parser.parse("no debugging ethernet frame brief", mode=mode).status)
            self.assertEqual(ParseStatus.INVALID, parser.parse("show debugging ethernet", mode=mode).status)


if __name__ == "__main__":
    unittest.main()
