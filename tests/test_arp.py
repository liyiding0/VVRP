from __future__ import annotations

import io
import unittest

from src.ARP import (
    ARP_REPLY,
    ARP_REQUEST,
    ZERO_MAC,
    ArpPacket,
    ArpPacketError,
    ArpProtocol,
    ArpTable,
    parse_arp_packet,
    register_arp_commands,
)
from src.CMD import CliContext, CommandParser, CommandRegistry, dispatch_line
from src.CMD.examples import build_default_registry
from src.ETHERNET import BROADCAST_MAC, ETHERTYPE_ARP, ETHERTYPE_IPV4, EthernetFrame
from src.IFNET import InterfaceAddress, NetworkInterface


def fake_interface() -> NetworkInterface:
    return NetworkInterface(
        name="eth2",
        ifnet_index=1,
        index=9,
        kind="ethernet",
        is_up=True,
        mac_address="00:11:22:33:44:55",
        mtu=1500,
        speed_mbps=1000,
        addresses=(InterfaceAddress(family="ipv4", address="10.0.0.1", prefix_length=24),),
    )


class ArpPacketTests(unittest.TestCase):
    def test_arp_request_round_trip(self):
        packet = ArpPacket(
            operation=ARP_REQUEST,
            sender_mac="00:11:22:33:44:55",
            sender_ip="10.0.0.1",
            target_mac=ZERO_MAC,
            target_ip="10.0.0.2",
        )

        parsed = parse_arp_packet(packet.to_bytes())

        self.assertEqual(packet, parsed)
        self.assertTrue(parsed.is_request)
        self.assertFalse(parsed.is_reply)

    def test_arp_reply_round_trip(self):
        packet = ArpPacket(
            operation=ARP_REPLY,
            sender_mac="66:77:88:99:aa:bb",
            sender_ip="10.0.0.2",
            target_mac="00:11:22:33:44:55",
            target_ip="10.0.0.1",
        )

        parsed = parse_arp_packet(packet.to_bytes())

        self.assertEqual(packet, parsed)
        self.assertTrue(parsed.is_reply)

    def test_rejects_short_or_non_ipv4_ethernet_arp(self):
        with self.assertRaisesRegex(ArpPacketError, "shorter than 28 bytes"):
            parse_arp_packet(b"\x00" * 27)

        raw = (
            (1).to_bytes(2, "big")
            + ETHERTYPE_IPV4.to_bytes(2, "big")
            + bytes((6, 4))
            + (99).to_bytes(2, "big")
            + (b"\x00" * 20)
        )
        with self.assertRaisesRegex(ArpPacketError, "operation"):
            parse_arp_packet(raw)


class ArpTableTests(unittest.TestCase):
    def test_learn_lookup_and_refresh_dynamic_entry(self):
        table = ArpTable(default_age_seconds=30)

        first = table.learn("10.0.0.2", "66-77-88-99-aa-bb", "eth2", now=100)
        second = table.learn("10.0.0.2", "66:77:88:99:aa:bc", "eth2", now=120)

        self.assertEqual("66:77:88:99:aa:bb", first.mac_address)
        self.assertEqual("66:77:88:99:aa:bc", second.mac_address)
        self.assertEqual(second, table.lookup("10.0.0.2", "eth2", now=130))

    def test_ages_dynamic_entries_but_keeps_static_entries(self):
        table = ArpTable(default_age_seconds=30)
        dynamic = table.learn("10.0.0.2", "66:77:88:99:aa:bb", "eth2", now=100)
        table.learn("10.0.0.3", "66:77:88:99:aa:cc", "eth2", now=100, entry_type="static")

        expired = table.age(now=131)

        self.assertEqual((dynamic,), expired)
        self.assertIsNone(table.lookup("10.0.0.2", "eth2", now=131))
        self.assertIsNotNone(table.lookup("10.0.0.3", "eth2", now=10000))

    def test_ignores_unspecified_ipv4_sender(self):
        table = ArpTable(default_age_seconds=30)

        entry = table.learn("0.0.0.0", "66:77:88:99:aa:bb", "eth2", now=100)

        self.assertIsNone(entry)
        self.assertEqual((), table.entries(now=100))


class ArpProtocolTests(unittest.TestCase):
    def test_build_request_uses_broadcast_ethernet_frame(self):
        protocol = ArpProtocol()

        frame = protocol.build_request(fake_interface(), "10.0.0.2")
        packet = parse_arp_packet(frame.payload)

        self.assertEqual(BROADCAST_MAC, frame.destination)
        self.assertEqual("00:11:22:33:44:55", frame.source)
        self.assertEqual(ETHERTYPE_ARP, frame.ethertype)
        self.assertEqual(ARP_REQUEST, packet.operation)
        self.assertEqual("10.0.0.1", packet.sender_ip)
        self.assertEqual("10.0.0.2", packet.target_ip)

    def test_handle_request_learns_sender_and_returns_reply_for_local_ip(self):
        interface = fake_interface()
        protocol = ArpProtocol()
        request = ArpPacket(
            operation=ARP_REQUEST,
            sender_mac="66:77:88:99:aa:bb",
            sender_ip="10.0.0.2",
            target_mac=ZERO_MAC,
            target_ip="10.0.0.1",
        )
        frame = EthernetFrame(
            destination=BROADCAST_MAC,
            source="66:77:88:99:aa:bb",
            ethertype=ETHERTYPE_ARP,
            payload=request.to_bytes(),
        )

        reply_frame = protocol.handle_frame(interface, frame, now=100)

        self.assertEqual(
            "66:77:88:99:aa:bb",
            protocol.table.lookup("10.0.0.2", "eth2", now=100).mac_address,
        )
        self.assertIsNotNone(reply_frame)
        reply = parse_arp_packet(reply_frame.payload)
        self.assertEqual(ARP_REPLY, reply.operation)
        self.assertEqual("10.0.0.1", reply.sender_ip)
        self.assertEqual("10.0.0.2", reply.target_ip)
        self.assertEqual("66:77:88:99:aa:bb", reply.target_mac)

    def test_handle_request_not_for_local_ip_only_learns(self):
        protocol = ArpProtocol()
        request = ArpPacket(
            operation=ARP_REQUEST,
            sender_mac="66:77:88:99:aa:bb",
            sender_ip="10.0.0.2",
            target_mac=ZERO_MAC,
            target_ip="10.0.0.99",
        )

        reply = protocol.handle_frame(
            fake_interface(),
            EthernetFrame(
                destination=BROADCAST_MAC,
                source="66:77:88:99:aa:bb",
                ethertype=ETHERTYPE_ARP,
                payload=request.to_bytes(),
            ),
        )

        self.assertIsNone(reply)
        self.assertIsNotNone(protocol.table.lookup("10.0.0.2", "eth2"))

    def test_handle_arp_probe_does_not_learn_unspecified_sender(self):
        protocol = ArpProtocol()
        request = ArpPacket(
            operation=ARP_REQUEST,
            sender_mac="66:77:88:99:aa:bb",
            sender_ip="0.0.0.0",
            target_mac=ZERO_MAC,
            target_ip="10.0.0.99",
        )

        reply = protocol.handle_frame(
            fake_interface(),
            EthernetFrame(
                destination=BROADCAST_MAC,
                source="66:77:88:99:aa:bb",
                ethertype=ETHERTYPE_ARP,
                payload=request.to_bytes(),
            ),
        )

        self.assertIsNone(reply)
        self.assertEqual((), protocol.table.entries())


class ArpCommandTests(unittest.TestCase):
    def test_show_arp_displays_dynamic_and_static_entries(self):
        table = ArpTable(default_age_seconds=1200)
        table.learn("10.0.0.2", "66:77:88:99:aa:bb", "eth2")
        table.learn("10.0.0.3", "66:77:88:99:aa:cc", "eth3", entry_type="static")
        registry = build_default_registry(arp_table=table)
        output = io.StringIO()
        ctx = CliContext(output=output)

        self.assertTrue(dispatch_line(ctx, registry, "show arp").executed)
        text = output.getvalue()

        self.assertIn("IP ADDRESS", text)
        self.assertIn("MAC ADDRESS", text)
        self.assertIn("10.0.0.2", text)
        self.assertIn("66:77:88:99:aa:bb", text)
        self.assertIn("dynamic", text)
        self.assertIn("10.0.0.3", text)
        self.assertIn("static", text)

    def test_show_arp_filters_by_type_interface_and_ip(self):
        table = ArpTable(default_age_seconds=1200)
        table.learn("10.0.0.2", "66:77:88:99:aa:bb", "eth2")
        table.learn("10.0.0.3", "66:77:88:99:aa:cc", "eth3", entry_type="static")
        registry = build_default_registry(arp_table=table)
        output = io.StringIO()
        ctx = CliContext(output=output)

        self.assertTrue(dispatch_line(ctx, registry, "show arp dynamic").executed)
        self.assertIn("10.0.0.2", output.getvalue())
        self.assertNotIn("10.0.0.3", output.getvalue())

        output.truncate(0)
        output.seek(0)
        self.assertTrue(dispatch_line(ctx, registry, "show arp static").executed)
        self.assertNotIn("10.0.0.2", output.getvalue())
        self.assertIn("10.0.0.3", output.getvalue())

        output.truncate(0)
        output.seek(0)
        self.assertTrue(dispatch_line(ctx, registry, "show arp interface eth2").executed)
        self.assertIn("10.0.0.2", output.getvalue())
        self.assertNotIn("10.0.0.3", output.getvalue())

        output.truncate(0)
        output.seek(0)
        self.assertTrue(dispatch_line(ctx, registry, "show arp 10.0.0.3").executed)
        self.assertNotIn("10.0.0.2", output.getvalue())
        self.assertIn("10.0.0.3", output.getvalue())

    def test_show_arp_reports_empty_and_invalid_ip(self):
        registry = build_default_registry(arp_table=ArpTable())
        output = io.StringIO()
        ctx = CliContext(output=output)

        self.assertTrue(dispatch_line(ctx, registry, "show arp").executed)
        self.assertEqual("ARP entry not found\n", output.getvalue())

        outcome = dispatch_line(ctx, registry, "show arp 999.0.0.1")
        self.assertTrue(outcome.executed)
        self.assertEqual("% Invalid IPv4 address: 999.0.0.1", outcome.message)

    def test_show_arp_command_help_and_modes(self):
        registry = CommandRegistry()
        register_arp_commands(registry)
        parser = CommandParser(registry)

        for mode in ("user", "privileged", "config", "hidden", "interface", "host-interface"):
            self.assertTrue(parser.parse("show arp", mode=mode).executable, mode)
            self.assertTrue(parser.parse("show arp dynamic", mode=mode).executable, mode)
            self.assertTrue(parser.parse("show arp static", mode=mode).executable, mode)
            self.assertTrue(parser.parse("show arp interface eth2", mode=mode).executable, mode)
            self.assertTrue(parser.parse("show arp 10.0.0.2", mode=mode).executable, mode)

        candidates = parser.help_candidates("show arp ", mode="user")
        self.assertEqual(
            [
                ("dynamic", "Show dynamic ARP entries"),
                ("interface", "Show ARP entries for an interface"),
                ("static", "Show static ARP entries"),
                ("<ip_address>", "Show ARP entries for an IPv4 address"),
                ("<cr>", "Show ARP mapping table"),
            ],
            [(candidate.display, candidate.help_text) for candidate in candidates],
        )


if __name__ == "__main__":
    unittest.main()
