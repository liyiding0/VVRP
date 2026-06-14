from __future__ import annotations

import io
import importlib.util
import unittest
from dataclasses import replace
from unittest.mock import patch

from VVRP.CCmd import (
    CliContext,
    CommandParser,
    CommandRegistry,
    CommandResult,
    ParseStatus,
    TokenStyle,
    dispatch_line,
)
from VVRP.CCmd.examples import build_default_registry
from VVRP.CCmd.help import format_help
from VVRP.CCmd.interactive import run_interactive_cli
from VVRP.IFNET.Ethernet import is_ethernet_interface
from VVRP.IFNET.Ethernet.admin import EthernetAdminProvider
from VVRP.IFNET.Ethernet.dhcp import EthernetDhcpClientProvider
from VVRP.IFNET.Ethernet.static import EthernetStaticIpv4Provider
from VVRP.IFNET.Loopback import is_loopback_interface
from VVRP.IFNET import (
    InterfaceAddress,
    InterfaceAdminResult,
    NetworkInterface,
    register_ifnet_commands,
)
from VVRP.IFNET.discovery import (
    assign_ifnet_indices,
    _interface_index,
    _interface_index_map,
    _interface_metadata_map,
)
from VVRP.IP.dhcp import DhcpClientResult
from VVRP.IP.ping import build_ping_command, classify_ping_target
from VVRP.IP.static import (
    StaticIpv4Address,
    StaticIpv4Result,
    StaticIpv4ValidationError,
    parse_ipv4_mask,
    parse_static_ipv4_address,
)


def build_registry(calls: list[tuple[str, dict[str, str]]] | None = None) -> CommandRegistry:
    registry = CommandRegistry()
    calls = calls if calls is not None else []

    @registry.command("show", help_text="Show command group")
    def show(ctx, args):
        calls.append(("show", args))
        return CommandResult(message="show ok")

    @registry.command("show version", help_text="Show version")
    def show_version(ctx, args):
        calls.append(("show version", args))
        return CommandResult(message="version ok")

    @registry.command("show interface <name:[A-Za-z0-9_/.-]+>", help_text="Show interface")
    def show_interface(ctx, args):
        calls.append(("show interface", args))
        return CommandResult(message=f"interface {args['name']} ok")

    @registry.command("shutdown", help_text="Shutdown")
    def shutdown(ctx, args):
        calls.append(("shutdown", args))
        return CommandResult(message="shutdown ok")

    return registry


class ParserTests(unittest.TestCase):
    def test_unique_abbreviation_completes_to_show(self):
        parser = CommandParser(build_registry())
        result = parser.parse("sho")

        self.assertEqual(ParseStatus.VALID_UNIQUE, result.status)
        self.assertEqual("show", result.complete_command)
        self.assertTrue(result.executable)

    def test_ambiguous_prefix(self):
        parser = CommandParser(build_registry())

        for text in ("s", "sh"):
            result = parser.parse(text)
            self.assertEqual(ParseStatus.AMBIGUOUS, result.status)
            self.assertEqual(("show", "shutdown"), result.candidates)

    def test_invalid_prefix(self):
        parser = CommandParser(build_registry())
        result = parser.parse("sha")

        self.assertEqual(ParseStatus.INVALID, result.status)
        self.assertEqual(0, result.error_position)

    def test_regex_parameter_accepts_valid_value(self):
        parser = CommandParser(build_registry())
        result = parser.parse("show interface eth3.10")

        self.assertEqual(ParseStatus.VALID_UNIQUE, result.status)
        self.assertEqual("show interface eth3.10", result.complete_command)
        self.assertEqual({"name": "eth3.10"}, result.args)
        self.assertTrue(result.executable)

    def test_regex_parameter_rejects_invalid_value(self):
        parser = CommandParser(build_registry())
        result = parser.parse("show interface eth3!")

        self.assertEqual(ParseStatus.INVALID, result.status)
        self.assertEqual(len("show interface "), result.error_position)

    def test_incomplete_command_is_valid_but_not_executable(self):
        parser = CommandParser(build_registry())
        result = parser.parse("show interface")

        self.assertEqual(ParseStatus.VALID_UNIQUE, result.status)
        self.assertEqual("show interface", result.complete_command)
        self.assertFalse(result.executable)

    def test_help_candidates_for_literal_children(self):
        parser = CommandParser(build_default_registry())
        candidates = parser.help_candidates("show ", mode="user")

        self.assertEqual(
            [("interfaces", "Show system interfaces"), ("version", "Show software version")],
            [(candidate.display, candidate.help_text) for candidate in candidates],
        )

    def test_help_candidates_for_parameter_position(self):
        parser = CommandParser(build_default_registry())
        candidates = parser.help_candidates("show interfaces ", mode="user")

        self.assertEqual(
            [
                ("brief", "Show brief system interface summary"),
                ("<name>", "Show system interface detail"),
            ],
            [(candidate.display, candidate.help_text) for candidate in candidates],
        )

    def test_help_candidates_for_interfaces_brief_cr(self):
        parser = CommandParser(build_default_registry())
        candidates = parser.help_candidates("show interfaces brief ", mode="user")

        self.assertEqual(
            [("<cr>", "Show brief system interface summary")],
            [(candidate.display, candidate.help_text) for candidate in candidates],
        )

    def test_help_candidates_for_complete_command(self):
        parser = CommandParser(build_default_registry())
        candidates = parser.help_candidates("show version ", mode="user")

        self.assertEqual(
            [("<cr>", "Show software version")],
            [(candidate.display, candidate.help_text) for candidate in candidates],
        )

    def test_question_mark_is_valid_when_help_is_available(self):
        parser = CommandParser(build_default_registry())
        result = parser.parse("sho ?", mode="user")

        self.assertEqual(ParseStatus.VALID_UNIQUE, result.status)
        self.assertEqual("show ?", result.complete_command)
        self.assertEqual(("interfaces", "version"), result.candidates)

    def test_unique_token_completes_before_space_for_any_command(self):
        parser = CommandParser(build_default_registry())

        self.assertEqual("show ", parser.complete_before_space("sho", mode="user"))
        self.assertEqual("config ", parser.complete_before_space("conf", mode="privileged"))
        self.assertEqual(
            "interface ",
            parser.complete_before_space("inter", mode="config"),
        )

    def test_quoted_parameter_accepts_interface_names_with_spaces(self):
        parser = CommandParser(build_default_registry())

        result = parser.parse(
            'interface "VMware Network Adapter VMnet1"',
            mode="config",
        )

        self.assertEqual(ParseStatus.VALID_UNIQUE, result.status)
        self.assertEqual({"name": "VMware Network Adapter VMnet1"}, result.args)
        self.assertEqual(
            'interface "VMware Network Adapter VMnet1"',
            result.complete_command,
        )
        self.assertTrue(result.executable)

    def test_dynamic_interface_parameter_marks_prefix_ambiguous_and_unknown_invalid(self):
        registry = build_default_registry(
            ifnet_provider=FakeInterfaceProvider((fake_ethernet("eth0"), fake_ethernet("eth4")))
        )
        ctx = CliContext(output=io.StringIO())
        ctx.push_mode("privileged")
        ctx.push_mode("config")
        registry.initialize_context(ctx)
        parser = CommandParser(registry)

        prefix = parser.parse("interface eth", mode="config", ctx=ctx)
        self.assertEqual(ParseStatus.AMBIGUOUS, prefix.status)
        self.assertEqual(("eth0", "eth4"), prefix.candidates)
        self.assertEqual(TokenStyle.VALID, prefix.token_statuses[0].style)
        self.assertEqual(TokenStyle.AMBIGUOUS, prefix.token_statuses[1].style)

        unknown = parser.parse("interface eth5", mode="config", ctx=ctx)
        self.assertEqual(ParseStatus.INVALID, unknown.status)
        self.assertEqual(TokenStyle.VALID, unknown.token_statuses[0].style)
        self.assertEqual(TokenStyle.INVALID, unknown.token_statuses[1].style)

        exact = parser.parse("interface eth4", mode="config", ctx=ctx)
        self.assertEqual(ParseStatus.VALID_UNIQUE, exact.status)
        self.assertTrue(exact.executable)

    def test_ambiguous_token_does_not_complete_before_space(self):
        parser = CommandParser(build_default_registry())

        self.assertEqual("show ", parser.complete_before_space("s", mode="privileged"))

    def test_help_candidates_are_filtered_by_mode(self):
        parser = CommandParser(build_default_registry())

        user_candidates = parser.help_candidates("", mode="user")
        config_candidates = parser.help_candidates("", mode="config")

        self.assertIn("enable", [candidate.display for candidate in user_candidates])
        self.assertNotIn("_", [candidate.display for candidate in user_candidates])
        self.assertNotIn("quit", [candidate.display for candidate in user_candidates])
        self.assertNotIn("config", [candidate.display for candidate in user_candidates])
        self.assertIn("interface", [candidate.display for candidate in config_candidates])
        self.assertNotIn("_", [candidate.display for candidate in config_candidates])
        self.assertIn("show", [candidate.display for candidate in config_candidates])


class RegistryTests(unittest.TestCase):
    def test_duplicate_registration_raises(self):
        registry = CommandRegistry()

        @registry.command("show")
        def show(ctx, args):
            return CommandResult()

        with self.assertRaises(ValueError):
            registry.register("show", show)

    def test_handler_and_args_are_bound(self):
        calls: list[tuple[str, dict[str, str]]] = []
        registry = build_registry(calls)
        ctx = CliContext(output=io.StringIO())

        outcome = dispatch_line(ctx, registry, "show inter eth3")

        self.assertTrue(outcome.executed)
        self.assertEqual("show interface eth3", outcome.display_command)
        self.assertEqual([("show interface", {"name": "eth3"})], calls)


class DispatchTests(unittest.TestCase):
    def test_enter_unique_abbreviation_completes_and_executes(self):
        calls: list[tuple[str, dict[str, str]]] = []
        registry = build_registry(calls)
        output = io.StringIO()
        ctx = CliContext(output=output)

        outcome = dispatch_line(ctx, registry, "sho")

        self.assertTrue(outcome.executed)
        self.assertEqual("show", outcome.display_command)
        self.assertEqual([("show", {})], calls)
        self.assertIn("show ok", output.getvalue())

    def test_ambiguous_command_does_not_execute(self):
        calls: list[tuple[str, dict[str, str]]] = []
        registry = build_registry(calls)
        ctx = CliContext(output=io.StringIO())

        outcome = dispatch_line(ctx, registry, "s")

        self.assertFalse(outcome.executed)
        self.assertEqual([], calls)
        self.assertEqual("% Ambiguous command", outcome.message)

    def test_invalid_command_does_not_execute(self):
        calls: list[tuple[str, dict[str, str]]] = []
        registry = build_registry(calls)
        ctx = CliContext(output=io.StringIO())

        outcome = dispatch_line(ctx, registry, "sha")

        self.assertFalse(outcome.executed)
        self.assertEqual([], calls)
        self.assertEqual("% Invalid input", outcome.message)

    def test_question_mark_prints_help_without_executing(self):
        calls: list[tuple[str, dict[str, str]]] = []
        registry = build_registry(calls)
        output = io.StringIO()
        ctx = CliContext(output=output)

        outcome = dispatch_line(ctx, registry, "show ?")

        self.assertFalse(outcome.executed)
        self.assertEqual([], calls)
        self.assertIn("interface", output.getvalue())
        self.assertIn("version", output.getvalue())

    def test_help_formatter_aligns_candidates(self):
        parser = CommandParser(build_default_registry())
        help_text = format_help(parser.help_candidates("show ", mode="user"))

        self.assertIn("interfaces  Show system interfaces", help_text)
        self.assertIn("version     Show software version", help_text)


class InteractiveTests(unittest.TestCase):
    def test_non_tty_fallback_dispatches_lines(self):
        output = io.StringIO()

        with (
            patch("VVRP.CCmd.interactive.sys.stdin.isatty", return_value=False),
            patch("VVRP.CCmd.interactive.sys.stdout.isatty", return_value=False),
            patch("builtins.input", side_effect=["show version", EOFError]),
            patch("VVRP.CCmd.models.sys.stdout", output),
        ):
            result = run_interactive_cli(build_default_registry())

        self.assertEqual(0, result)
        self.assertIn("VVRP CCmd version 0.1.0", output.getvalue())


class ModuleBoundaryTests(unittest.TestCase):
    def test_ping_module_lives_in_ip_not_ccmd(self):
        self.assertIsNone(importlib.util.find_spec("VVRP.CCmd.ping"))
        self.assertIsNotNone(importlib.util.find_spec("VVRP.IP.ping"))
        self.assertIsNotNone(importlib.util.find_spec("VVRP.IFNET"))
        self.assertIsNotNone(importlib.util.find_spec("VVRP.IFNET.Ethernet"))
        self.assertIsNotNone(importlib.util.find_spec("VVRP.IFNET.Loopback"))

    def test_ifnet_type_specific_classifiers_live_in_subpackages(self):
        self.assertTrue(is_ethernet_interface("eth3", "AA:BB:CC:DD:EE:FF"))
        self.assertFalse(is_ethernet_interface("Wi-Fi", "AA:BB:CC:DD:EE:FF"))
        self.assertFalse(is_ethernet_interface("eth3", ""))

        self.assertTrue(is_loopback_interface("loopback_0", ()))
        self.assertTrue(
            is_loopback_interface(
                "lo0",
                (InterfaceAddress(family="ipv4", address="127.0.0.1"),),
            )
        )
        self.assertFalse(
            is_loopback_interface(
                "eth3",
                (InterfaceAddress(family="ipv4", address="192.0.2.10"),),
            )
        )


class FakeInterfaceProvider:
    def __init__(self, interfaces: tuple[NetworkInterface, ...]):
        self.interfaces = interfaces
        self.known_interfaces = {interface.name: interface for interface in interfaces}
        self.calls = 0

    def list_interfaces(self) -> tuple[NetworkInterface, ...]:
        self.calls += 1
        return self.interfaces

    def set_interface_up(self, name: str, is_up: bool) -> None:
        found = False
        self.interfaces = tuple(
            replace(interface, is_up=is_up) if interface.name == name else interface
            for interface in self.interfaces
        )
        for interface in self.interfaces:
            if interface.name == name:
                found = True
                break
        if not found and is_up and name in self.known_interfaces:
            self.interfaces = (
                *self.interfaces,
                replace(self.known_interfaces[name], is_up=True),
            )


class FakeRawAddress:
    def __init__(self, family, address: str):
        self.family = family
        self.address = address


class FakeAdminProvider:
    def __init__(self, provider: FakeInterfaceProvider | None = None):
        self.calls: list[tuple[str, str]] = []
        self.fail_next: InterfaceAdminResult | None = None
        self.provider = provider

    def shutdown(self, interface: NetworkInterface) -> InterfaceAdminResult:
        self.calls.append(("shutdown", interface.name))
        if self.fail_next is not None:
            result = self.fail_next
            self.fail_next = None
            return result
        if self.provider is not None:
            self.provider.set_interface_up(interface.name, False)
        return InterfaceAdminResult(ok=True)

    def no_shutdown(self, interface: NetworkInterface) -> InterfaceAdminResult:
        self.calls.append(("no shutdown", interface.name))
        if self.fail_next is not None:
            result = self.fail_next
            self.fail_next = None
            return result
        if self.provider is not None:
            self.provider.set_interface_up(interface.name, True)
        return InterfaceAdminResult(ok=True)


class FakeDhcpProvider:
    def __init__(self):
        self.calls: list[tuple[str, str]] = []
        self.fail_next: DhcpClientResult | None = None

    def enable_dhcp(self, interface: NetworkInterface) -> DhcpClientResult:
        self.calls.append(("enable dhcp", interface.name))
        if self.fail_next is not None:
            result = self.fail_next
            self.fail_next = None
            return result
        return DhcpClientResult(ok=True)

    def disable_dhcp(self, interface: NetworkInterface) -> DhcpClientResult:
        self.calls.append(("disable dhcp", interface.name))
        if self.fail_next is not None:
            result = self.fail_next
            self.fail_next = None
            return result
        return DhcpClientResult(ok=True)


class FakeStaticIpv4Provider:
    def __init__(self):
        self.calls: list[tuple[str, str, StaticIpv4Address | None]] = []
        self.fail_next: StaticIpv4Result | None = None

    def set_static_ipv4(
        self,
        interface: NetworkInterface,
        address: StaticIpv4Address,
    ) -> StaticIpv4Result:
        self.calls.append(("set static ipv4", interface.name, address))
        if self.fail_next is not None:
            result = self.fail_next
            self.fail_next = None
            return result
        return StaticIpv4Result(ok=True)

    def remove_static_ipv4(
        self,
        interface: NetworkInterface,
        address: StaticIpv4Address | None = None,
    ) -> StaticIpv4Result:
        self.calls.append(("remove static ipv4", interface.name, address))
        if self.fail_next is not None:
            result = self.fail_next
            self.fail_next = None
            return result
        return StaticIpv4Result(ok=True)


def fake_interfaces() -> tuple[NetworkInterface, ...]:
    return (
        fake_ethernet("eth3"),
        NetworkInterface(
            name="loopback_0",
            ifnet_index=0,
            index=1,
            kind="loopback",
            is_up=True,
            mac_address="",
            mtu=None,
            speed_mbps=None,
            addresses=(
                InterfaceAddress(family="ipv4", address="127.0.0.1", prefix_length=8),
                InterfaceAddress(family="ipv6", address="::1", prefix_length=128),
            ),
        ),
    )


def fake_ethernet(name: str, index: int = 2) -> NetworkInterface:
    return NetworkInterface(
        name=name,
        ifnet_index=0,
        index=index,
        kind="ethernet",
        is_up=True,
        mac_address="AA:BB:CC:DD:EE:FF",
        mtu=1500,
        speed_mbps=1000,
        addresses=(
            InterfaceAddress(family="ipv4", address="192.0.2.10", prefix_length=24),
            InterfaceAddress(family="ipv6", address="2001:db8::10", prefix_length=64),
        ),
    )


def fake_interface_with_spaces() -> NetworkInterface:
    return NetworkInterface(
        name="VMware Network Adapter VMnet1",
        ifnet_index=0,
        index=77,
        kind="ethernet",
        is_up=True,
        mac_address="00:50:56:C0:00:01",
        mtu=1500,
        speed_mbps=1000,
        addresses=(),
    )


class IFNETCommandTests(unittest.TestCase):
    def test_ifnet_indices_put_loopback_first(self):
        interfaces = assign_ifnet_indices(fake_interfaces())

        self.assertEqual(["loopback_0", "eth3"], [item.name for item in interfaces])
        self.assertEqual([1, 2], [item.ifnet_index for item in interfaces])

    def test_windows_index_map_resolves_friendly_names(self):
        class FakePsutil:
            AF_LINK = object()

        raw_addresses = {
            "eth4": [FakeRawAddress(FakePsutil.AF_LINK, "00-E0-4C-68-00-BE")],
        }

        with (
            patch("VVRP.IFNET.discovery.platform.system", return_value="Windows"),
            patch(
                "VVRP.IFNET.discovery._windows_interface_index_map",
                return_value={
                    "eth4": {
                        "index": 40,
                        "names": ("eth4", r"\DEVICE\TCPIP_{test}"),
                        "mac_address": "00:E0:4C:68:00:BE",
                    }
                },
            ),
        ):
            index_map = _interface_index_map(FakePsutil, raw_addresses)

        self.assertEqual(40, _interface_index("eth4", "", index_map))
        self.assertEqual(
            40,
            _interface_index("missing-name", "00:E0:4C:68:00:BE", index_map),
        )

    def test_windows_metadata_map_preserves_stable_os_identity(self):
        class FakePsutil:
            AF_LINK = object()

        raw_addresses = {
            "eth4": [FakeRawAddress(FakePsutil.AF_LINK, "00-E0-4C-68-00-BE")],
        }

        with (
            patch("VVRP.IFNET.discovery.platform.system", return_value="Windows"),
            patch(
                "VVRP.IFNET.discovery._windows_interface_index_map",
                return_value={
                    "eth4": {
                        "index": 70,
                        "os_id": "{13ED46E6-5AA8-4B75-BB3B-71F6CC306B6A}",
                        "names": (
                            "eth4",
                            "{13ED46E6-5AA8-4B75-BB3B-71F6CC306B6A}",
                            "Realtek USB GbE Family Controller #2",
                        ),
                        "mac_address": "00:E0:4C:68:00:BE",
                    }
                },
            ),
        ):
            metadata_map = _interface_metadata_map(FakePsutil, raw_addresses)

        metadata = metadata_map["eth4"]
        self.assertEqual(70, metadata["index"])
        self.assertEqual("{13ED46E6-5AA8-4B75-BB3B-71F6CC306B6A}", metadata["os_id"])
        self.assertIn("Realtek USB GbE Family Controller #2", metadata["os_aliases"])

    def test_show_interfaces_brief_lists_fake_provider(self):
        registry = CommandRegistry()
        register_ifnet_commands(registry, provider=FakeInterfaceProvider(fake_interfaces()))
        output = io.StringIO()
        ctx = CliContext(output=output)

        outcome = dispatch_line(ctx, registry, "show interfaces brief")

        self.assertTrue(outcome.executed)
        text = output.getvalue()
        self.assertIn("PHY: Physical", text)
        self.assertIn("Interface", text)
        self.assertIn("PHY", text)
        self.assertIn("Protocol", text)
        self.assertIn("InUti", text)
        self.assertIn("OutUti", text)
        self.assertIn("inErrors", text)
        self.assertIn("outErrors", text)
        self.assertIn("eth3", text)
        self.assertIn("loopback_0", text)
        self.assertIn("up(l)", text)
        self.assertIn("up(s)", text)
        self.assertNotIn("IFNET Index", text)
        self.assertNotIn("AA:BB:CC:DD:EE:FF", text)
        self.assertNotIn("192.0.2.10/24", text)
        self.assertNotIn("2001:db8::10/64", text)

    def test_show_interfaces_detail_uses_fake_provider(self):
        registry = CommandRegistry()
        register_ifnet_commands(registry, provider=FakeInterfaceProvider(fake_interfaces()))
        output = io.StringIO()
        ctx = CliContext(output=output)

        outcome = dispatch_line(ctx, registry, "show interfaces eth3")

        self.assertTrue(outcome.executed)
        text = output.getvalue()
        self.assertIn("eth3 is up, line protocol is up", text)
        self.assertIn("IFNET Index is 0x2", text)
        self.assertIn("OS interface index is 2", text)
        self.assertIn("Hardware address is AA:BB:CC:DD:EE:FF", text)
        self.assertIn("MTU 1500 bytes", text)
        self.assertIn("bandwidth 1000 Mbps", text)

    def test_show_interfaces_without_brief_shows_all_details(self):
        registry = CommandRegistry()
        register_ifnet_commands(registry, provider=FakeInterfaceProvider(fake_interfaces()))
        output = io.StringIO()
        ctx = CliContext(output=output)

        outcome = dispatch_line(ctx, registry, "show interfaces")

        self.assertTrue(outcome.executed)
        text = output.getvalue()
        self.assertLess(text.index("loopback_0"), text.index("eth3"))
        self.assertIn("IFNET Index is 0x1", text)
        self.assertIn("IFNET Index is 0x2", text)
        self.assertIn("eth3 is up, line protocol is up", text)
        self.assertIn("loopback_0 is up, line protocol is up", text)
        self.assertNotIn("Name", text)

    def test_show_interfaces_unknown_name(self):
        registry = CommandRegistry()
        register_ifnet_commands(registry, provider=FakeInterfaceProvider(fake_interfaces()))
        output = io.StringIO()
        ctx = CliContext(output=output)

        outcome = dispatch_line(ctx, registry, "show interfaces missing0")

        self.assertTrue(outcome.executed)
        self.assertEqual("% Interface not found: missing0", outcome.message)
        self.assertIn("% Interface not found: missing0", output.getvalue())

    def test_default_registry_has_ifnet_commands(self):
        parser = CommandParser(build_default_registry())

        for mode in ("user", "privileged", "config", "interface", "hidden"):
            self.assertTrue(parser.parse("show interfaces", mode=mode).executable, mode)
            self.assertTrue(parser.parse("show interfaces brief", mode=mode).executable, mode)
            self.assertTrue(parser.parse("show interfaces eth3", mode=mode).executable, mode)
        self.assertTrue(parser.parse("shutdown", mode="interface").executable)
        self.assertTrue(parser.parse("no shutdown", mode="interface").executable)
        self.assertEqual(ParseStatus.INVALID, parser.parse("shutdown", mode="privileged").status)
        self.assertEqual(ParseStatus.INVALID, parser.parse("no shutdown", mode="config").status)

    def test_shutdown_and_no_shutdown_ethernet_interface(self):
        registry = CommandRegistry()
        provider = FakeInterfaceProvider(fake_interfaces())
        admin_provider = FakeAdminProvider(provider)
        register_ifnet_commands(
            registry,
            provider=provider,
            admin_provider=admin_provider,
            modes=("user", "privileged", "config", "interface", "hidden"),
        )
        output = io.StringIO()
        ctx = CliContext(output=output)
        ctx.push_mode("interface", "eth3")

        self.assertTrue(dispatch_line(ctx, registry, "shutdown").executed)
        self.assertEqual([("shutdown", "eth3")], admin_provider.calls)
        output.truncate(0)
        output.seek(0)
        dispatch_line(ctx, registry, "show interfaces eth3")
        self.assertIn("eth3 is administratively down, line protocol is down", output.getvalue())

        self.assertTrue(dispatch_line(ctx, registry, "no shutdown").executed)
        self.assertEqual(
            [("shutdown", "eth3"), ("no shutdown", "eth3")],
            admin_provider.calls,
        )
        output.truncate(0)
        output.seek(0)
        dispatch_line(ctx, registry, "show interfaces eth3")
        self.assertIn("eth3 is up, line protocol is up", output.getvalue())

    def test_shutdown_accepts_quoted_interface_name_with_spaces(self):
        registry = CommandRegistry()
        provider = FakeInterfaceProvider((fake_interface_with_spaces(),))
        admin_provider = FakeAdminProvider(provider)
        register_ifnet_commands(
            registry,
            provider=provider,
            admin_provider=admin_provider,
            modes=("user", "privileged", "config", "interface", "hidden"),
        )
        ctx = CliContext(output=io.StringIO())
        ctx.push_mode("config")

        self.assertTrue(
            dispatch_line(
                ctx,
                registry,
                'interface "VMware Network Adapter VMnet1"',
            ).executed
        )
        self.assertEqual("VMware Network Adapter VMnet1", ctx.mode_label)
        self.assertTrue(dispatch_line(ctx, registry, "shutdown").executed)
        self.assertEqual(
            [("shutdown", "VMware Network Adapter VMnet1")],
            admin_provider.calls,
        )

    def test_shutdown_marks_brief_phy_down(self):
        registry = CommandRegistry()
        provider = FakeInterfaceProvider(fake_interfaces())
        admin_provider = FakeAdminProvider(provider)
        register_ifnet_commands(
            registry,
            provider=provider,
            admin_provider=admin_provider,
            modes=("user", "privileged", "config", "interface", "hidden"),
        )
        output = io.StringIO()
        ctx = CliContext(output=output)
        ctx.push_mode("interface", "eth3")

        dispatch_line(ctx, registry, "shutdown")
        output.truncate(0)
        output.seek(0)
        dispatch_line(ctx, registry, "show interfaces brief")

        self.assertIn("eth3", output.getvalue())
        self.assertIn("*down", output.getvalue())

    def test_shutdown_rejects_loopback_interface(self):
        registry = CommandRegistry()
        admin_provider = FakeAdminProvider()
        register_ifnet_commands(
            registry,
            provider=FakeInterfaceProvider(fake_interfaces()),
            admin_provider=admin_provider,
            modes=("user", "privileged", "config", "interface", "hidden"),
        )
        output = io.StringIO()
        ctx = CliContext(output=output)
        ctx.push_mode("interface", "loopback_0")

        outcome = dispatch_line(ctx, registry, "shutdown")

        self.assertTrue(outcome.executed)
        self.assertEqual(
            "% Loopback interface cannot be shut down: loopback_0",
            outcome.message,
        )
        self.assertEqual([], admin_provider.calls)
        output.truncate(0)
        output.seek(0)
        dispatch_line(ctx, registry, "show interfaces loopback_0")
        self.assertIn("loopback_0 is up, line protocol is up(s)", output.getvalue())

    def test_shutdown_unknown_interface_reports_error(self):
        registry = CommandRegistry()
        admin_provider = FakeAdminProvider()
        register_ifnet_commands(
            registry,
            provider=FakeInterfaceProvider(fake_interfaces()),
            admin_provider=admin_provider,
            modes=("user", "privileged", "config", "interface", "hidden"),
        )
        ctx = CliContext(output=io.StringIO())
        ctx.push_mode("interface", "missing0")

        outcome = dispatch_line(ctx, registry, "shutdown")

        self.assertTrue(outcome.executed)
        self.assertEqual("% Interface not found: missing0", outcome.message)
        self.assertEqual([], admin_provider.calls)

    def test_shutdown_does_not_mark_state_when_os_admin_fails(self):
        registry = CommandRegistry()
        admin_provider = FakeAdminProvider()
        admin_provider.fail_next = InterfaceAdminResult(
            ok=False,
            message="% OS interface API failed: access denied",
        )
        register_ifnet_commands(
            registry,
            provider=FakeInterfaceProvider(fake_interfaces()),
            admin_provider=admin_provider,
            modes=("user", "privileged", "config", "interface", "hidden"),
        )
        output = io.StringIO()
        ctx = CliContext(output=output)
        ctx.push_mode("interface", "eth3")

        outcome = dispatch_line(ctx, registry, "shutdown")

        self.assertTrue(outcome.executed)
        self.assertEqual("% OS interface API failed: access denied", outcome.message)
        output.truncate(0)
        output.seek(0)
        dispatch_line(ctx, registry, "show interfaces eth3")
        self.assertIn("eth3 is up, line protocol is up", output.getvalue())

    def test_shutdown_does_not_mark_state_when_os_readback_stays_up(self):
        registry = CommandRegistry()
        provider = FakeInterfaceProvider(fake_interfaces())
        admin_provider = FakeAdminProvider()
        register_ifnet_commands(
            registry,
            provider=provider,
            admin_provider=admin_provider,
            modes=("user", "privileged", "config", "interface", "hidden"),
        )
        output = io.StringIO()
        ctx = CliContext(output=output)
        ctx.push_mode("interface", "eth3")

        with patch("VVRP.IFNET.commands.time.sleep", return_value=None):
            outcome = dispatch_line(ctx, registry, "shutdown")

        self.assertTrue(outcome.executed)
        self.assertIn("did not take effect", outcome.message)
        output.truncate(0)
        output.seek(0)
        dispatch_line(ctx, registry, "show interfaces brief")
        self.assertIn("eth3", output.getvalue())
        eth3_line = next(
            line for line in output.getvalue().splitlines() if line.startswith("eth3")
        )
        self.assertIn(" up ", eth3_line)
        self.assertNotIn("*down", eth3_line)

    def test_ifnet_inventory_cache_keeps_shutdown_interface_available(self):
        registry = CommandRegistry()
        provider = FakeInterfaceProvider(fake_interfaces())
        admin_provider = FakeAdminProvider(provider)
        register_ifnet_commands(
            registry,
            provider=provider,
            admin_provider=admin_provider,
            modes=("user", "privileged", "config", "interface", "hidden"),
        )
        ctx = CliContext(output=io.StringIO())

        registry.initialize_context(ctx)
        provider.interfaces = tuple(
            interface for interface in fake_interfaces() if interface.name != "eth3"
        )
        ctx.push_mode("interface", "eth3")

        self.assertTrue(dispatch_line(ctx, registry, "shutdown").executed)
        self.assertTrue(dispatch_line(ctx, registry, "no shutdown").executed)

        self.assertEqual(
            [("shutdown", "eth3"), ("no shutdown", "eth3")],
            admin_provider.calls,
        )
        self.assertEqual(3, provider.calls)

    def test_missing_psutil_returns_cli_error(self):
        registry = CommandRegistry()
        register_ifnet_commands(registry)
        output = io.StringIO()
        ctx = CliContext(output=output)

        with patch(
            "VVRP.IFNET.discovery.importlib.import_module",
            side_effect=ImportError("No module named psutil"),
        ):
            outcome = dispatch_line(ctx, registry, "show interfaces")

        self.assertTrue(outcome.executed)
        self.assertIn("psutil is required for IFNET interface discovery", outcome.message)
        self.assertIn("psutil is required for IFNET interface discovery", output.getvalue())

    def test_ethernet_admin_backend_dispatches_to_windows_api(self):
        interface = fake_interfaces()[0]

        with patch("VVRP.IFNET.Ethernet.admin._set_windows_interface_enabled") as api:
            result = EthernetAdminProvider(system="Windows").shutdown(interface)

        self.assertTrue(result.ok)
        api.assert_called_once_with(interface, False)

        with patch("VVRP.IFNET.Ethernet.admin._set_windows_interface_enabled") as api:
            result = EthernetAdminProvider(system="Windows").no_shutdown(interface)

        self.assertTrue(result.ok)
        api.assert_called_once_with(interface, True)

    def test_windows_admin_wrapper_uses_device_level_backend(self):
        interface = fake_interfaces()[0]

        with patch(
            "VVRP.IFNET.Ethernet.windows.set_windows_network_adapter_enabled"
        ) as api:
            from VVRP.IFNET.Ethernet.admin import _set_windows_interface_enabled

            _set_windows_interface_enabled(interface, False)

        api.assert_called_once_with(interface, False)

    def test_windows_identity_prefers_cached_os_id_when_ifindex_is_unavailable(self):
        from VVRP.IFNET.Ethernet.windows import _adapter_identity_for_interface

        interface = replace(
            fake_interfaces()[0],
            index=None,
            os_id="{13ED46E6-5AA8-4B75-BB3B-71F6CC306B6A}",
            os_aliases=("Realtek USB GbE Family Controller #2",),
        )

        identity = _adapter_identity_for_interface(interface)

        self.assertEqual(
            "{13ED46E6-5AA8-4B75-BB3B-71F6CC306B6A}",
            identity["adapter_name"],
        )
        self.assertIn("Realtek USB GbE Family Controller #2", identity["names"])

    def test_ethernet_admin_backend_dispatches_to_linux_api(self):
        interface = fake_interfaces()[0]

        with patch("VVRP.IFNET.Ethernet.admin._set_linux_interface_enabled") as api:
            result = EthernetAdminProvider(system="Linux").shutdown(interface)

        self.assertTrue(result.ok)
        api.assert_called_once_with(interface, False)

    def test_ethernet_admin_backend_reports_unsupported_os(self):
        result = EthernetAdminProvider(system="FreeBSD").shutdown(fake_interfaces()[0])

        self.assertFalse(result.ok)
        self.assertIn("unsupported OS API backend", result.message)

    def test_ethernet_admin_backend_reports_permission_errors(self):
        with patch(
            "VVRP.IFNET.Ethernet.admin._set_windows_interface_enabled",
            side_effect=PermissionError("Administrator privileges are required"),
        ):
            result = EthernetAdminProvider(system="Windows").shutdown(fake_interfaces()[0])

        self.assertFalse(result.ok)
        self.assertIn("permission denied", result.message)


class DhcpClientCommandTests(unittest.TestCase):
    def test_dhcp_alloc_commands_are_interface_only(self):
        registry = build_default_registry(ifnet_provider=FakeInterfaceProvider(fake_interfaces()))
        parser = CommandParser(registry)

        self.assertTrue(parser.parse("ip address dhcp-alloc", mode="interface").executable)
        self.assertTrue(parser.parse("no ip address dhcp-alloc", mode="interface").executable)
        self.assertEqual(
            ParseStatus.INVALID,
            parser.parse("ip address dhcp-alloc", mode="config").status,
        )
        self.assertEqual(
            ParseStatus.INVALID,
            parser.parse("no ip address dhcp-alloc", mode="config").status,
        )

    def test_ip_address_dhcp_alloc_calls_provider(self):
        ifnet_provider = FakeInterfaceProvider(fake_interfaces())
        dhcp_provider = FakeDhcpProvider()
        registry = build_default_registry(
            ifnet_provider=ifnet_provider,
            ip_dhcp_provider=dhcp_provider,
        )
        ctx = CliContext(output=io.StringIO())
        ctx.push_mode("interface", "eth3")

        outcome = dispatch_line(ctx, registry, "ip address dhcp-alloc")

        self.assertTrue(outcome.executed)
        self.assertEqual([("enable dhcp", "eth3")], dhcp_provider.calls)

    def test_no_ip_address_dhcp_alloc_calls_provider(self):
        ifnet_provider = FakeInterfaceProvider(fake_interfaces())
        dhcp_provider = FakeDhcpProvider()
        registry = build_default_registry(
            ifnet_provider=ifnet_provider,
            ip_dhcp_provider=dhcp_provider,
        )
        ctx = CliContext(output=io.StringIO())
        ctx.push_mode("interface", "eth3")

        outcome = dispatch_line(ctx, registry, "no ip address dhcp-alloc")

        self.assertTrue(outcome.executed)
        self.assertEqual([("disable dhcp", "eth3")], dhcp_provider.calls)

    def test_dhcp_alloc_rejects_loopback_interface(self):
        ifnet_provider = FakeInterfaceProvider(fake_interfaces())
        dhcp_provider = FakeDhcpProvider()
        registry = build_default_registry(
            ifnet_provider=ifnet_provider,
            ip_dhcp_provider=dhcp_provider,
        )
        ctx = CliContext(output=io.StringIO())
        ctx.push_mode("interface", "loopback_0")

        outcome = dispatch_line(ctx, registry, "ip address dhcp-alloc")

        self.assertTrue(outcome.executed)
        self.assertEqual(
            "% Loopback interface does not support DHCP client: loopback_0",
            outcome.message,
        )
        self.assertEqual([], dhcp_provider.calls)

    def test_dhcp_alloc_unknown_current_interface_reports_error(self):
        dhcp_provider = FakeDhcpProvider()
        registry = build_default_registry(
            ifnet_provider=FakeInterfaceProvider(fake_interfaces()),
            ip_dhcp_provider=dhcp_provider,
        )
        ctx = CliContext(output=io.StringIO())
        ctx.push_mode("interface", "missing0")

        outcome = dispatch_line(ctx, registry, "ip address dhcp-alloc")

        self.assertTrue(outcome.executed)
        self.assertEqual("% Interface not found: missing0", outcome.message)
        self.assertEqual([], dhcp_provider.calls)

    def test_dhcp_provider_failure_is_reported(self):
        dhcp_provider = FakeDhcpProvider()
        dhcp_provider.fail_next = DhcpClientResult(
            ok=False,
            message="% OS interface API failed: DHCP backend failed",
        )
        registry = build_default_registry(
            ifnet_provider=FakeInterfaceProvider(fake_interfaces()),
            ip_dhcp_provider=dhcp_provider,
        )
        ctx = CliContext(output=io.StringIO())
        ctx.push_mode("interface", "eth3")

        outcome = dispatch_line(ctx, registry, "ip address dhcp-alloc")

        self.assertTrue(outcome.executed)
        self.assertEqual("% OS interface API failed: DHCP backend failed", outcome.message)

    def test_ethernet_dhcp_backend_dispatches_to_windows_api(self):
        interface = fake_interfaces()[0]

        with patch(
            "VVRP.IFNET.Ethernet.dhcp._set_windows_ethernet_dhcp",
            return_value="% DHCP client enabled; lease renewal pending",
        ) as api:
            result = EthernetDhcpClientProvider(system="Windows").enable_dhcp(interface)

        self.assertTrue(result.ok)
        self.assertIn("lease renewal pending", result.message)
        api.assert_called_once_with(interface, True)

        with patch("VVRP.IFNET.Ethernet.dhcp._set_windows_ethernet_dhcp") as api:
            result = EthernetDhcpClientProvider(system="Windows").disable_dhcp(interface)

        self.assertTrue(result.ok)
        api.assert_called_once_with(interface, False)

    def test_ethernet_dhcp_backend_reports_unsupported_linux(self):
        result = EthernetDhcpClientProvider(system="Linux").enable_dhcp(fake_interfaces()[0])

        self.assertFalse(result.ok)
        self.assertIn("unsupported OS API backend for DHCP client: linux", result.message)

    def test_windows_dhcp_updates_msft_netipinterface_with_put(self):
        from VVRP.IFNET.Ethernet.windows import _set_msft_netipinterface_dhcp

        class FakeIpInterface:
            def __init__(self):
                self.Dhcp = 0
                self.put_calls = 0

            def Put_(self):
                self.put_calls += 1

        ip_interface = FakeIpInterface()

        _set_msft_netipinterface_dhcp(ip_interface, enabled=True)
        self.assertEqual(1, ip_interface.Dhcp)
        self.assertEqual(1, ip_interface.put_calls)

        _set_msft_netipinterface_dhcp(ip_interface, enabled=False)
        self.assertEqual(0, ip_interface.Dhcp)
        self.assertEqual(2, ip_interface.put_calls)

    def test_windows_dhcp_invokes_wmi_instance_method_directly(self):
        from VVRP.IFNET.Ethernet.windows import _call_wmi_instance_method

        class FakeAdapterConfiguration:
            def __init__(self):
                self.calls: list[str] = []

            def EnableDHCP(self):
                self.calls.append("EnableDHCP")
                return 0

        adapter_config = FakeAdapterConfiguration()

        result = _call_wmi_instance_method(adapter_config, "EnableDHCP")

        self.assertEqual(0, result)
        self.assertEqual(["EnableDHCP"], adapter_config.calls)

    def test_windows_dhcp_accepts_eager_wmi_method_return_value(self):
        from VVRP.IFNET.Ethernet.windows import _call_wmi_instance_method

        class FakeAdapterConfiguration:
            EnableDHCP = 0

        result = _call_wmi_instance_method(FakeAdapterConfiguration(), "EnableDHCP")

        self.assertEqual(0, result)


class StaticIpv4CommandTests(unittest.TestCase):
    def test_static_ipv4_commands_are_interface_only(self):
        registry = build_default_registry(ifnet_provider=FakeInterfaceProvider(fake_interfaces()))
        parser = CommandParser(registry)

        self.assertTrue(parser.parse("ip address 192.0.2.10 24", mode="interface").executable)
        self.assertTrue(
            parser.parse("ip address 192.0.2.11 255.255.255.0 sub", mode="interface").executable
        )
        self.assertTrue(parser.parse("no ip address", mode="interface").executable)
        self.assertTrue(
            parser.parse("no ip address 192.0.2.10 255.255.255.0", mode="interface").executable
        )
        self.assertEqual(
            ParseStatus.INVALID,
            parser.parse("ip address 192.0.2.10 24", mode="config").status,
        )

    def test_parse_static_ipv4_accepts_mask_length_and_dotted_mask(self):
        primary = parse_static_ipv4_address("1.1.1.1", "8")
        secondary = parse_static_ipv4_address("10.0.0.10", "255.255.255.0", secondary=True)

        self.assertEqual(8, primary.prefix_length)
        self.assertEqual("255.0.0.0", primary.subnet_mask)
        self.assertFalse(primary.secondary)
        self.assertEqual(24, secondary.prefix_length)
        self.assertTrue(secondary.secondary)

    def test_parse_static_ipv4_rejects_non_contiguous_mask(self):
        with self.assertRaises(StaticIpv4ValidationError):
            parse_static_ipv4_address("192.0.2.10", "255.252.0.255")

    def test_parse_static_ipv4_rejects_multicast_reserved_network_and_broadcast(self):
        for address, mask in (
            ("224.0.0.1", "24"),
            ("240.0.0.1", "24"),
            ("0.1.1.1", "8"),
            ("192.0.2.10", "24"),
            ("255.255.255.255", "32"),
            ("1.1.1.0", "24"),
            ("1.1.1.255", "24"),
        ):
            with self.subTest(address=address, mask=mask):
                with self.assertRaises(StaticIpv4ValidationError):
                    parse_static_ipv4_address(address, mask)

    def test_parse_static_ipv4_accepts_31_and_32_host_prefixes(self):
        self.assertEqual(31, parse_static_ipv4_address("1.1.1.0", "31").prefix_length)
        self.assertEqual(32, parse_static_ipv4_address("1.1.1.1", "32").prefix_length)

    def test_parse_ipv4_mask_rejects_bad_lengths_and_formats(self):
        for mask in ("33", "-1", "255.0.255.0", "255.255.255.256", "255.025.0.0"):
            with self.subTest(mask=mask):
                with self.assertRaises(StaticIpv4ValidationError):
                    parse_ipv4_mask(mask)

    def test_ip_address_static_calls_provider(self):
        ifnet_provider = FakeInterfaceProvider(fake_interfaces())
        static_provider = FakeStaticIpv4Provider()
        registry = build_default_registry(
            ifnet_provider=ifnet_provider,
            ip_static_ipv4_provider=static_provider,
        )
        ctx = CliContext(output=io.StringIO())
        ctx.push_mode("interface", "eth3")

        outcome = dispatch_line(ctx, registry, "ip address 1.1.1.1 8")

        self.assertTrue(outcome.executed)
        self.assertEqual(1, len(static_provider.calls))
        action, interface_name, address = static_provider.calls[0]
        self.assertEqual("set static ipv4", action)
        self.assertEqual("eth3", interface_name)
        self.assertEqual(StaticIpv4Address("1.1.1.1", 8), address)

    def test_ip_address_static_sub_calls_provider_with_secondary_flag(self):
        static_provider = FakeStaticIpv4Provider()
        registry = build_default_registry(
            ifnet_provider=FakeInterfaceProvider(fake_interfaces()),
            ip_static_ipv4_provider=static_provider,
        )
        ctx = CliContext(output=io.StringIO())
        ctx.push_mode("interface", "eth3")

        outcome = dispatch_line(ctx, registry, "ip address 1.1.1.2 255.0.0.0 sub")

        self.assertTrue(outcome.executed)
        _, _, address = static_provider.calls[0]
        self.assertEqual(StaticIpv4Address("1.1.1.2", 8, secondary=True), address)

    def test_no_ip_address_without_arguments_removes_all_static_ipv4(self):
        static_provider = FakeStaticIpv4Provider()
        registry = build_default_registry(
            ifnet_provider=FakeInterfaceProvider(fake_interfaces()),
            ip_static_ipv4_provider=static_provider,
        )
        ctx = CliContext(output=io.StringIO())
        ctx.push_mode("interface", "eth3")

        outcome = dispatch_line(ctx, registry, "no ip address")

        self.assertTrue(outcome.executed)
        self.assertEqual([("remove static ipv4", "eth3", None)], static_provider.calls)

    def test_no_ip_address_with_arguments_removes_one_static_ipv4(self):
        static_provider = FakeStaticIpv4Provider()
        registry = build_default_registry(
            ifnet_provider=FakeInterfaceProvider(fake_interfaces()),
            ip_static_ipv4_provider=static_provider,
        )
        ctx = CliContext(output=io.StringIO())
        ctx.push_mode("interface", "eth3")

        outcome = dispatch_line(ctx, registry, "no ip address 1.1.1.2 255.0.0.0 sub")

        self.assertTrue(outcome.executed)
        self.assertEqual(
            [("remove static ipv4", "eth3", StaticIpv4Address("1.1.1.2", 8, secondary=True))],
            static_provider.calls,
        )

    def test_static_ipv4_rejects_loopback_interface(self):
        static_provider = FakeStaticIpv4Provider()
        registry = build_default_registry(
            ifnet_provider=FakeInterfaceProvider(fake_interfaces()),
            ip_static_ipv4_provider=static_provider,
        )
        ctx = CliContext(output=io.StringIO())
        ctx.push_mode("interface", "loopback_0")

        outcome = dispatch_line(ctx, registry, "ip address 1.1.1.1 8")

        self.assertTrue(outcome.executed)
        self.assertEqual(
            "% Loopback interface does not support static IPv4: loopback_0",
            outcome.message,
        )
        self.assertEqual([], static_provider.calls)

    def test_static_ipv4_provider_failure_is_reported(self):
        static_provider = FakeStaticIpv4Provider()
        static_provider.fail_next = StaticIpv4Result(
            ok=False,
            message="% OS interface API failed: static backend failed",
        )
        registry = build_default_registry(
            ifnet_provider=FakeInterfaceProvider(fake_interfaces()),
            ip_static_ipv4_provider=static_provider,
        )
        ctx = CliContext(output=io.StringIO())
        ctx.push_mode("interface", "eth3")

        outcome = dispatch_line(ctx, registry, "ip address 1.1.1.1 8")

        self.assertTrue(outcome.executed)
        self.assertEqual("% OS interface API failed: static backend failed", outcome.message)

    def test_ethernet_static_backend_dispatches_to_windows_api(self):
        interface = fake_interfaces()[0]
        address = StaticIpv4Address("1.1.1.1", 8)

        with patch("VVRP.IFNET.Ethernet.static._set_windows_ethernet_static_ipv4") as api:
            result = EthernetStaticIpv4Provider(system="Windows").set_static_ipv4(
                interface,
                address,
            )

        self.assertTrue(result.ok)
        api.assert_called_once_with(interface, address)

        with patch("VVRP.IFNET.Ethernet.static._remove_windows_ethernet_static_ipv4") as api:
            result = EthernetStaticIpv4Provider(system="Windows").remove_static_ipv4(
                interface,
                address,
            )

        self.assertTrue(result.ok)
        api.assert_called_once_with(interface, address)

    def test_ethernet_static_backend_reports_unsupported_linux(self):
        result = EthernetStaticIpv4Provider(system="Linux").set_static_ipv4(
            fake_interfaces()[0],
            StaticIpv4Address("1.1.1.1", 8),
        )

        self.assertFalse(result.ok)
        self.assertIn("unsupported OS API backend for static IPv4: linux", result.message)

    def test_windows_static_ipv4_class_method_helper_passes_inputs(self):
        from VVRP.IFNET.Ethernet.windows import _call_wmi_class_method

        class FakeInParameters:
            def SpawnInstance_(self):
                return type("FakeInput", (), {})()

        class FakeMethod:
            InParameters = FakeInParameters()

        class FakeClass:
            Path_ = type("FakePath", (), {"Path": "MSFT_NetIPAddress"})

            def Methods_(self, method_name):
                self.method_name = method_name
                return FakeMethod()

        class FakeService:
            def ExecMethod_(self, path, method_name, in_params):
                self.call = (path, method_name, in_params)
                return 0

        service = FakeService()
        wmi_class = FakeClass()

        result = _call_wmi_class_method(
            service,
            wmi_class,
            "Create",
            {"IPAddress": "1.1.1.1", "PrefixLength": 8},
        )

        self.assertEqual(0, result)
        self.assertEqual(("MSFT_NetIPAddress", "Create"), service.call[:2])
        self.assertEqual("1.1.1.1", service.call[2].IPAddress)
        self.assertEqual(8, service.call[2].PrefixLength)

    def test_windows_static_ipv4_delete_helper_accepts_eager_return_value(self):
        from VVRP.IFNET.Ethernet.windows import _delete_wmi_instance

        class FakeAddress:
            Delete_ = 0

        _delete_wmi_instance(FakeAddress(), "MSFT_NetIPAddress.Delete_")

    def test_windows_static_ipv4_manual_match_helpers(self):
        from VVRP.IFNET.Ethernet.windows import (
            _wmi_ipv4_address_is_manual,
            _wmi_ipv4_address_matches,
        )

        row = type(
            "FakeAddressRow",
            (),
            {
                "PrefixOrigin": 1,
                "SuffixOrigin": 1,
                "IPAddress": "1.1.1.1",
                "PrefixLength": 8,
            },
        )()

        self.assertTrue(_wmi_ipv4_address_is_manual(row))
        self.assertTrue(_wmi_ipv4_address_matches(row, StaticIpv4Address("1.1.1.1", 8)))
        self.assertFalse(_wmi_ipv4_address_matches(row, StaticIpv4Address("1.1.1.2", 8)))


class PingTests(unittest.TestCase):
    def test_ping_target_classification_accepts_ip_and_names(self):
        self.assertEqual("ipv4", classify_ping_target("192.168.1.1"))
        self.assertEqual("ipv6", classify_ping_target("2001:db8::1"))
        self.assertEqual("ipv6", classify_ping_target("::1"))
        self.assertEqual("hostname", classify_ping_target("router"))
        self.assertEqual("hostname", classify_ping_target("example.com"))

    def test_ping_target_classification_rejects_options_and_bad_names(self):
        with self.assertRaises(ValueError):
            classify_ping_target("-n")
        with self.assertRaises(ValueError):
            classify_ping_target("bad_name")

    def test_ping_command_builder_is_platform_aware(self):
        with patch("VVRP.IP.ping.platform.system", return_value="Windows"):
            self.assertEqual(
                ["ping", "-6", "-n", "4", "-w", "1000", "::1"],
                build_ping_command("::1", "ipv6"),
            )

        with patch("VVRP.IP.ping.platform.system", return_value="Linux"):
            with patch("VVRP.IP.ping.shutil.which", return_value=None):
                self.assertEqual(
                    ["ping", "-6", "-c", "4", "-W", "1", "::1"],
                    build_ping_command("::1", "ipv6"),
                )

    def test_ping_command_is_available_in_all_modes(self):
        registry = build_default_registry()
        parser = CommandParser(registry)

        for mode in ("user", "privileged", "config", "interface", "hidden"):
            result = parser.parse("ping example.com", mode=mode)
            self.assertTrue(result.executable, mode)

    def test_ping_dispatch_passes_target_to_runner(self):
        registry = build_default_registry()
        ctx = CliContext(output=io.StringIO())

        with patch(
            "VVRP.IP.commands.run_ping",
            return_value=CommandResult(message="pong"),
        ) as run_ping_mock:
            outcome = dispatch_line(ctx, registry, "ping 2001:db8::1")

        self.assertTrue(outcome.executed)
        run_ping_mock.assert_called_once_with("2001:db8::1")
        self.assertIn("pong", ctx.output.getvalue())


class ModeTests(unittest.TestCase):
    def test_default_prompt_is_user_mode(self):
        ctx = CliContext(hostname="R1", output=io.StringIO())

        self.assertEqual("user", ctx.mode)
        self.assertEqual("<R1> ", ctx.prompt)

    def test_mode_stack_and_prompts(self):
        registry = build_default_registry(ifnet_provider=FakeInterfaceProvider(fake_interfaces()))
        ctx = CliContext(hostname="R1", output=io.StringIO())

        self.assertTrue(dispatch_line(ctx, registry, "enable").executed)
        self.assertEqual("privileged", ctx.mode)
        self.assertEqual("R1# ", ctx.prompt)

        self.assertTrue(dispatch_line(ctx, registry, "config").executed)
        self.assertEqual("config", ctx.mode)
        self.assertEqual("R1(config)# ", ctx.prompt)

        self.assertTrue(dispatch_line(ctx, registry, "interface eth3").executed)
        self.assertEqual("interface", ctx.mode)
        self.assertEqual("R1(config-if-eth3)# ", ctx.prompt)

        self.assertTrue(dispatch_line(ctx, registry, "_").executed)
        self.assertEqual("hidden", ctx.mode)
        self.assertEqual("(R1-hidden)# ", ctx.prompt)

        self.assertTrue(dispatch_line(ctx, registry, "quit").executed)
        self.assertEqual("interface", ctx.mode)
        self.assertEqual("R1(config-if-eth3)# ", ctx.prompt)

        self.assertTrue(dispatch_line(ctx, registry, "quit").executed)
        self.assertEqual("config", ctx.mode)
        self.assertEqual("R1(config)# ", ctx.prompt)

        self.assertTrue(dispatch_line(ctx, registry, "quit").executed)
        self.assertEqual("privileged", ctx.mode)
        self.assertEqual("R1# ", ctx.prompt)

        self.assertTrue(dispatch_line(ctx, registry, "quit").executed)
        self.assertEqual("user", ctx.mode)
        self.assertEqual("<R1> ", ctx.prompt)

    def test_quit_is_not_available_in_user_mode(self):
        registry = build_default_registry()
        ctx = CliContext(output=io.StringIO())

        outcome = dispatch_line(ctx, registry, "quit")

        self.assertFalse(outcome.executed)
        self.assertEqual(ParseStatus.INVALID, outcome.status)
        self.assertFalse(ctx.exit_requested)

    def test_hidden_command_still_executes_without_help_visibility(self):
        registry = build_default_registry()
        parser = CommandParser(registry)
        ctx = CliContext(output=io.StringIO())

        self.assertTrue(dispatch_line(ctx, registry, "_").executed)
        self.assertEqual("hidden", ctx.mode)
        self.assertNotIn(
            "_",
            [candidate.display for candidate in parser.help_candidates("", mode="user")],
        )

    def test_commands_are_visible_only_in_registered_modes(self):
        registry = build_default_registry(ifnet_provider=FakeInterfaceProvider(fake_interfaces()))
        ctx = CliContext(output=io.StringIO())

        self.assertEqual(ParseStatus.INVALID, dispatch_line(ctx, registry, "config").status)

        dispatch_line(ctx, registry, "enable")
        self.assertEqual(ParseStatus.INVALID, dispatch_line(ctx, registry, "enable").status)
        self.assertTrue(dispatch_line(ctx, registry, "show").executed)

        dispatch_line(ctx, registry, "config")
        show_outcome = dispatch_line(ctx, registry, "show")
        self.assertTrue(show_outcome.executed)
        self.assertIn("hostname", show_outcome.message)
        self.assertEqual(ParseStatus.INVALID, dispatch_line(ctx, registry, "show version").status)
        show_interface_outcome = dispatch_line(ctx, registry, "show interface eth3")
        self.assertTrue(show_interface_outcome.executed)
        self.assertEqual("show interfaces eth3", show_interface_outcome.display_command)
        self.assertEqual(ParseStatus.INVALID, dispatch_line(ctx, registry, "shutdown").status)
        self.assertTrue(dispatch_line(ctx, registry, "interface eth3").executed)
        self.assertTrue(CommandParser(registry).parse("shutdown", mode=ctx.mode).executable)

    def test_unknown_interface_does_not_enter_interface_mode(self):
        registry = build_default_registry(ifnet_provider=FakeInterfaceProvider(fake_interfaces()))
        output = io.StringIO()
        ctx = CliContext(output=output)

        dispatch_line(ctx, registry, "enable")
        dispatch_line(ctx, registry, "config")
        outcome = dispatch_line(ctx, registry, "interface eth100")

        self.assertFalse(outcome.executed)
        self.assertEqual(ParseStatus.INVALID, outcome.status)
        self.assertEqual("% Invalid input", outcome.message)
        self.assertEqual("config", ctx.mode)
        self.assertEqual("Router(config)# ", ctx.prompt)
        self.assertIn("% Invalid input", output.getvalue())

    def test_interface_command_switches_interface_from_interface_mode(self):
        registry = build_default_registry(
            ifnet_provider=FakeInterfaceProvider((fake_ethernet("eth0"), fake_ethernet("eth4")))
        )
        ctx = CliContext(output=io.StringIO())

        dispatch_line(ctx, registry, "enable")
        dispatch_line(ctx, registry, "config")
        self.assertTrue(dispatch_line(ctx, registry, "interface eth4").executed)
        self.assertEqual("Router(config-if-eth4)# ", ctx.prompt)

        self.assertTrue(dispatch_line(ctx, registry, "interface eth0").executed)

        self.assertEqual("interface", ctx.mode)
        self.assertEqual("eth0", ctx.mode_label)
        self.assertEqual("Router(config-if-eth0)# ", ctx.prompt)

    def test_hostname_command_is_config_only_and_updates_prompt(self):
        registry = build_default_registry()
        ctx = CliContext(hostname="R1", output=io.StringIO())

        self.assertEqual(
            ParseStatus.INVALID,
            dispatch_line(ctx, registry, "hostname R2").status,
        )

        dispatch_line(ctx, registry, "enable")
        self.assertEqual(
            ParseStatus.INVALID,
            dispatch_line(ctx, registry, "hostname R2").status,
        )

        dispatch_line(ctx, registry, "config")
        self.assertTrue(dispatch_line(ctx, registry, "hostname R2").executed)
        self.assertEqual("R2", ctx.hostname)
        self.assertEqual("R2(config)# ", ctx.prompt)

    def test_show_hostname_is_available_in_privileged_and_config_modes(self):
        registry = build_default_registry()
        output = io.StringIO()
        ctx = CliContext(hostname="R1", output=output)

        self.assertEqual(
            ParseStatus.INVALID,
            dispatch_line(ctx, registry, "show hostname").status,
        )

        dispatch_line(ctx, registry, "enable")
        self.assertTrue(dispatch_line(ctx, registry, "show hostname").executed)
        self.assertIn("R1", output.getvalue())

        dispatch_line(ctx, registry, "config")
        dispatch_line(ctx, registry, "hostname R2")
        self.assertTrue(dispatch_line(ctx, registry, "show hostname").executed)
        self.assertIn("R2", output.getvalue())

    def test_show_command_lists_show_family_by_current_mode(self):
        registry = build_default_registry()
        output = io.StringIO()
        ctx = CliContext(output=output)

        dispatch_line(ctx, registry, "show")
        user_text = output.getvalue()
        self.assertIn("version", user_text)
        self.assertIn("interfaces", user_text)
        self.assertNotIn("hostname", user_text)

        output.truncate(0)
        output.seek(0)
        dispatch_line(ctx, registry, "enable")
        dispatch_line(ctx, registry, "config")
        dispatch_line(ctx, registry, "show")
        config_text = output.getvalue()
        self.assertIn("hostname", config_text)
        self.assertIn("interfaces", config_text)
        self.assertNotIn("version", config_text)

    def test_parser_filters_candidates_by_mode(self):
        registry = build_default_registry()
        parser = CommandParser(registry)

        user_result = parser.parse("s", mode="user")
        privileged_result = parser.parse("s", mode="privileged")
        config_result = parser.parse("s", mode="config")

        self.assertEqual(ParseStatus.VALID_UNIQUE, user_result.status)
        self.assertEqual("show", user_result.complete_command)
        self.assertEqual(ParseStatus.VALID_UNIQUE, privileged_result.status)
        self.assertEqual("show", privileged_result.complete_command)
        self.assertEqual(ParseStatus.VALID_UNIQUE, config_result.status)
        self.assertEqual("show", config_result.complete_command)


if __name__ == "__main__":
    unittest.main()
