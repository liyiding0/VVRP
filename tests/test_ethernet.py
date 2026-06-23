from __future__ import annotations

import io
import time
import unittest

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
from src.CCmd import CliContext, CommandParser, CommandRegistry, ParseStatus, dispatch_line
from src.CCmd.examples import build_default_registry
from src.ARP import ARP_REPLY, ArpPacket, get_arp_table
from src.DPlane import DPlane_PlatformInfo, DPlane_Result
from src.DPlane.frame_debug import DplaneEthernetFrameDebugService
from src.DPlane.Windows.npcap import NpcapDevice
from src.IFNET.imports import commit_imports, stage_import_interface
from src.IFNET.state import set_interface_mac_address
from src.IFNET import InterfaceAddress, NetworkInterface


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


class FakeNpcapLibrary:
    def list_devices(self) -> tuple[NpcapDevice, ...]:
        return (
            NpcapDevice(
                name=r"\Device\NPF_{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}",
                description="eth4",
            ),
        )


class FakeDPlaneBackend:
    def DPlane_list_packet_devices(self) -> tuple[NpcapDevice, ...]:
        return FakeNpcapLibrary().list_devices()

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


class DebugPacketPort(FakePacketPort):
    def recv_frame(self) -> bytes | None:
        frame = super().recv_frame()
        if frame is None:
            time.sleep(0.01)
        return frame


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

    def test_debugging_ethernet_command_starts_dplane_listener(self):
        arp = ArpPacket(
            operation=ARP_REPLY,
            sender_mac="66:77:88:99:aa:bb",
            sender_ip="10.0.0.2",
            target_mac="00:11:22:33:44:55",
            target_ip="10.0.0.1",
        )
        raw = build_ethernet_ii_frame(
            destination="00:11:22:33:44:55",
            source="66:77:88:99:aa:bb",
            ethertype=ETHERTYPE_ARP,
            payload=arp.to_bytes(),
        )
        ports: list[DebugPacketPort] = []

        def port_factory(device):
            port = DebugPacketPort(frames=(raw,))
            ports.append(port)
            return port

        service = DplaneEthernetFrameDebugService(
            ifnet_provider=FakeInterfaceProvider(),
            dplane_backend=FakeDPlaneBackend(),
            port_factory=port_factory,
            packet_filter="ether proto 0x0806",
        )
        registry = CommandRegistry()
        register_ethernet_commands(
            registry,
            frame_debug_start=service.start,
            frame_debug_stop=service.stop,
            frame_debug_status=service.status,
        )
        output = io.StringIO()
        ctx = CliContext(output=output)
        ctx.push_mode("privileged")
        stage_import_interface(ctx.state, "eth4")
        commit_imports(ctx.state)

        self.assertTrue(dispatch_line(ctx, registry, "debugging ethernet frame brief").executed)

        deadline = time.time() + 1
        while "ETHERNET/FRAME: eth4 RX" not in output.getvalue() and time.time() < deadline:
            time.sleep(0.01)

        self.assertIn("1 listener(s) running", output.getvalue())
        self.assertIn("ETHERNET/FRAME: eth4 RX", output.getvalue())
        self.assertEqual(["ether proto 0x0806"], ports[0].filters)
        learned = get_arp_table(ctx.state).lookup("10.0.0.2", "eth4")
        self.assertIsNotNone(learned)
        self.assertEqual("66:77:88:99:aa:bb", learned.mac_address)

        self.assertTrue(dispatch_line(ctx, registry, "no debugging ethernet frame brief").executed)

        output.truncate(0)
        output.seek(0)
        self.assertTrue(dispatch_line(ctx, registry, "debugging ethernet frame brief").executed)
        self.assertTrue(is_ethernet_frame_brief_debug_enabled(ctx))
        self.assertIn("on", output.getvalue())

        output.truncate(0)
        output.seek(0)
        self.assertTrue(dispatch_line(ctx, registry, "no debugging ethernet frame brief").executed)
        self.assertFalse(is_ethernet_frame_brief_debug_enabled(ctx))
        self.assertIn("off", output.getvalue())

    def test_debugging_ethernet_filters_host_mac_after_VVRP_mac_override(self):
        host_raw = build_ethernet_ii_frame(
            destination="66:77:88:99:aa:bb",
            source="00:11:22:33:44:55",
            ethertype=ETHERTYPE_IPV4,
            payload=b"host",
        )
        VVRP_raw = build_ethernet_ii_frame(
            destination="02:00:00:00:00:01",
            source="66:77:88:99:aa:bb",
            ethertype=ETHERTYPE_IPV4,
            payload=b"VVRP",
        )
        ports: list[DebugPacketPort] = []

        def port_factory(device):
            port = DebugPacketPort(frames=(host_raw, VVRP_raw))
            ports.append(port)
            return port

        service = DplaneEthernetFrameDebugService(
            ifnet_provider=FakeInterfaceProvider(),
            dplane_backend=FakeDPlaneBackend(),
            port_factory=port_factory,
            packet_filter="ether proto 0x0800",
        )
        registry = CommandRegistry()
        register_ethernet_commands(
            registry,
            frame_debug_start=service.start,
            frame_debug_stop=service.stop,
            frame_debug_status=service.status,
        )
        output = io.StringIO()
        ctx = CliContext(output=output)
        ctx.push_mode("privileged")
        stage_import_interface(ctx.state, "eth4")
        commit_imports(ctx.state)
        set_interface_mac_address(ctx.state, "eth4", "02:00:00:00:00:01")

        self.assertTrue(dispatch_line(ctx, registry, "debugging ethernet frame brief").executed)

        deadline = time.time() + 1
        while "dst=02:00:00:00:00:01" not in output.getvalue() and time.time() < deadline:
            time.sleep(0.01)

        text = output.getvalue()
        self.assertNotIn("src=00:11:22:33:44:55", text)
        self.assertIn("dst=02:00:00:00:00:01", text)

        self.assertTrue(dispatch_line(ctx, registry, "no debugging ethernet frame brief").executed)

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
