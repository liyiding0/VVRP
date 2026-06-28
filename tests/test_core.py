from __future__ import annotations

import io
import importlib.util
import os
import subprocess
import struct
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from src.CCmd import (
    CliContext,
    CommandParser,
    CommandRegistry,
    CommandResult,
    ParseStatus,
    TokenStyle,
    dispatch_line,
)
from src.ARP import ARP_REPLY, ArpPacket, ArpTable, get_arp_table
from src.CCmd.examples import build_default_registry
from src.CCmd.help import format_help
from src.CCmd.interactive import (
    _PromptToolkitAnsiOutput,
    _format_colored_help_screen_update,
    _format_help_screen_update,
    _preserve_help_input,
    _render_input_with_token_styles,
    _reload_context,
    run_interactive_cli,
)
from src.CCmd.models import TokenStatus
from src.CCmd.running_config import (
    default_saved_configuration_path,
    default_runtime_directory,
    load_saved_configuration,
    render_running_configuration,
    set_interface_config_command,
    set_saved_configuration_path,
)
from src.IFNET.Ethernet import is_ethernet_interface
from src.DPlane.interface_admin import DPlane_InterfaceAdminProvider
from src.DPlane.interface_discovery import (
    _interface_index,
    _interface_index_map,
    _interface_metadata_map,
)
from src.DPlane.ip_config import DPlane_DhcpClientProvider, DPlane_StaticIpv4Provider
from src.IFNET.Loopback import is_loopback_interface
from src.DPlane import DPlane_Result
from src.DPlane.Windows.npcap import NpcapDevice
from src.IFNET import (
    InterfaceAddress,
    InterfaceAdminResult,
    NetworkInterface,
    register_ifnet_commands,
)
from src.DPlane import register_dplane_commands
from src.IFNET.discovery import (
    assign_ifnet_indices,
)
from src.ETHERNET.device import ETHERNET_commit_device_changes, ETHERNET_stage_device_install
from src.IFNET.state import set_interface_mac_address
from src.IP.state import IP_set_interface_addresses
from src.ETHERNET import ETHERTYPE_ARP, ETHERTYPE_IPV4, build_ethernet_ii_frame, parse_ethernet_ii_frame
from src.IP.dhcp import IP_DhcpClientResult
from src.IP.ICMP.ping import (
    ICMP_SocketPinger,
    ICMP_PingOptions,
    ICMP_PingReply,
    ICMP_PingResult,
    ICMP_VvrpPacketPinger,
    ICMP_build_echo_packet,
    ICMP_build_ipv4_packet,
    ICMP_classify_ping_target,
    ICMP_format_ping_reply,
    ICMP_format_ping_statistics,
    ICMP_parse_ipv4_packet,
    ICMP_parse_ping_arguments,
    ICMP_run_ping,
)
from src.IP.ICMP.packet import g_ICMP_CODE, g_ICMP_ECHO_REPLY, ICMP_checksum, ICMP_parse_echo
from src.IP.ICMP.replies import ICMP_record_echo_reply
from src.IP.static import (
    IP_StaticIpv4Address,
    IP_StaticIpv4Result,
    IP_StaticIpv4ValidationError,
    IP_parse_ipv4_mask,
    IP_parse_static_ipv4_address,
    IP_validate_static_ipv4_address_for_interface,
)
from src.VVRP import VVRP_Runtime


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

    def test_literal_command_tokens_are_case_insensitive(self):
        parser = CommandParser(build_registry())
        result = parser.parse("SHOW INTERFACE eth3")

        self.assertEqual(ParseStatus.VALID_UNIQUE, result.status)
        self.assertEqual("show interface eth3", result.complete_command)
        self.assertEqual({"name": "eth3"}, result.args)
        self.assertTrue(result.executable)

    def test_default_registry_binds_runtime_arp_table_to_context_state(self):
        table = ArpTable()
        registry = build_default_registry(arp_table=table)
        ctx = CliContext(output=io.StringIO())

        registry.initialize_context(ctx)

        self.assertIs(table, get_arp_table(ctx.state))

    def test_literal_abbreviations_are_case_insensitive(self):
        parser = CommandParser(build_registry())
        result = parser.parse("ShO InT eth3")

        self.assertEqual(ParseStatus.VALID_UNIQUE, result.status)
        self.assertEqual("show interface eth3", result.complete_command)
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
            [
                ("arp", "Show ARP mapping table"),
                ("fib", "Show IPv4 FIB entries"),
                ("interfaces", "Show VVRP interfaces"),
                ("ip", "Show IP information"),
                ("running-configuration", "Show current running configuration"),
                ("saved-configuration", "Show saved configuration"),
                ("version", "Show software version"),
                ("<cr>", "Show command group"),
            ],
            [(candidate.display, candidate.help_text) for candidate in candidates],
        )

    def test_help_candidates_for_parameter_position(self):
        parser = CommandParser(build_default_registry())
        candidates = parser.help_candidates("show host interface ", mode="hidden")

        self.assertEqual(
            [
                ("brief", "Show brief host system interface summary"),
                ("<name>", "Show host system interface detail"),
                ("<cr>", "Show host system interfaces"),
            ],
            [(candidate.display, candidate.help_text) for candidate in candidates],
        )

    def test_help_candidates_for_interfaces_brief_cr(self):
        parser = CommandParser(build_default_registry())
        candidates = parser.help_candidates("show host interface brief ", mode="hidden")

        self.assertEqual(
            [("<cr>", "Show brief host system interface summary")],
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
        self.assertEqual(
            (
                "arp",
                "fib",
                "interfaces",
                "ip",
                "running-configuration",
                "saved-configuration",
                "version",
                "<cr>",
            ),
            result.candidates,
        )

    def test_question_mark_suffix_keeps_prefix_token_style(self):
        parser = CommandParser(build_default_registry())

        ambiguous = parser.parse("show host i?", mode="hidden")
        self.assertEqual(ParseStatus.VALID_UNIQUE, ambiguous.status)
        self.assertEqual(("interface", "ip"), ambiguous.candidates)
        self.assertEqual(TokenStyle.VALID, ambiguous.token_statuses[0].style)
        self.assertEqual(TokenStyle.VALID, ambiguous.token_statuses[1].style)
        self.assertEqual(TokenStyle.AMBIGUOUS, ambiguous.token_statuses[2].style)
        self.assertEqual((10, 12), (ambiguous.token_statuses[2].start, ambiguous.token_statuses[2].end))

        unique = parser.parse("show host ip?", mode="hidden")
        self.assertEqual(ParseStatus.VALID_UNIQUE, unique.status)
        self.assertEqual(("ip",), unique.candidates)
        self.assertEqual(TokenStyle.VALID, unique.token_statuses[2].style)

    def test_partial_ipv4_parameter_token_style(self):
        parser = CommandParser(build_default_registry())

        partial = parser.parse("ip address 192.168.211", mode="interface")
        self.assertEqual(ParseStatus.AMBIGUOUS, partial.status)
        self.assertEqual(TokenStyle.VALID, partial.token_statuses[0].style)
        self.assertEqual(TokenStyle.VALID, partial.token_statuses[1].style)
        self.assertEqual(TokenStyle.AMBIGUOUS, partial.token_statuses[2].style)

        valid = parser.parse("ip address 192.168.211.1 24", mode="interface")
        self.assertEqual(ParseStatus.VALID_UNIQUE, valid.status)
        self.assertEqual(TokenStyle.VALID, valid.token_statuses[2].style)
        self.assertEqual(TokenStyle.VALID, valid.token_statuses[3].style)

        invalid = parser.parse("ip address 192.168.999", mode="interface")
        self.assertEqual(ParseStatus.INVALID, invalid.status)
        self.assertEqual(TokenStyle.INVALID, invalid.token_statuses[2].style)

    def test_partial_ipv4_mask_parameter_token_style(self):
        parser = CommandParser(build_default_registry())

        partial = parser.parse("ip address 192.168.211.1 255.255", mode="interface")
        self.assertEqual(ParseStatus.AMBIGUOUS, partial.status)
        self.assertEqual(TokenStyle.AMBIGUOUS, partial.token_statuses[3].style)

        invalid = parser.parse("ip address 192.168.211.1 255.999", mode="interface")
        self.assertEqual(ParseStatus.INVALID, invalid.status)
        self.assertEqual(TokenStyle.INVALID, invalid.token_statuses[3].style)

    def test_partial_mac_address_parameter_token_style(self):
        parser = CommandParser(build_default_registry())

        partial = parser.parse("mac-address 00:E0:4C:11:22:", mode="interface")
        self.assertEqual(ParseStatus.AMBIGUOUS, partial.status)
        self.assertEqual(TokenStyle.VALID, partial.token_statuses[0].style)
        self.assertEqual(TokenStyle.AMBIGUOUS, partial.token_statuses[1].style)

        valid = parser.parse("mac-address 00:E0:4C:11:22:33", mode="interface")
        self.assertEqual(ParseStatus.VALID_UNIQUE, valid.status)
        self.assertEqual(TokenStyle.VALID, valid.token_statuses[1].style)

        invalid = parser.parse("mac-address 00:E0:4C:11:22:333", mode="interface")
        self.assertEqual(ParseStatus.INVALID, invalid.status)
        self.assertEqual(TokenStyle.INVALID, invalid.token_statuses[1].style)

    def test_unique_token_completes_before_space_for_any_command(self):
        parser = CommandParser(build_default_registry())

        self.assertEqual("show ", parser.complete_before_space("sho", mode="user"))
        self.assertEqual("config ", parser.complete_before_space("conf", mode="privileged"))
        self.assertEqual("interface ", parser.complete_before_space("inter", mode="config"))
        self.assertEqual(
            "host interface ",
            parser.complete_before_space("host inter", mode="hidden"),
        )

    def test_quoted_parameter_accepts_interface_names_with_spaces(self):
        parser = CommandParser(build_default_registry())

        result = parser.parse(
            'host interface "VMware Network Adapter VMnet1"',
            mode="hidden",
        )

        self.assertEqual(ParseStatus.VALID_UNIQUE, result.status)
        self.assertEqual({"name": "VMware Network Adapter VMnet1"}, result.args)
        self.assertEqual(
            'host interface "VMware Network Adapter VMnet1"',
            result.complete_command,
        )
        self.assertTrue(result.executable)

    def test_dynamic_interface_parameter_marks_prefix_ambiguous_and_unknown_invalid(self):
        registry = build_default_registry(
            ifnet_provider=FakeInterfaceProvider((fake_ethernet("eth0"), fake_ethernet("eth4")))
        )
        ctx = CliContext(output=io.StringIO())
        ctx.push_mode("hidden")
        registry.initialize_context(ctx)
        parser = CommandParser(registry)

        prefix = parser.parse("host interface eth", mode="hidden", ctx=ctx)
        self.assertEqual(ParseStatus.AMBIGUOUS, prefix.status)
        self.assertEqual(("eth0", "eth4"), prefix.candidates)
        self.assertEqual(TokenStyle.VALID, prefix.token_statuses[0].style)
        self.assertEqual(TokenStyle.VALID, prefix.token_statuses[1].style)
        self.assertEqual(TokenStyle.AMBIGUOUS, prefix.token_statuses[2].style)

        unknown = parser.parse("host interface eth5", mode="hidden", ctx=ctx)
        self.assertEqual(ParseStatus.INVALID, unknown.status)
        self.assertEqual(TokenStyle.VALID, unknown.token_statuses[0].style)
        self.assertEqual(TokenStyle.VALID, unknown.token_statuses[1].style)
        self.assertEqual(TokenStyle.INVALID, unknown.token_statuses[2].style)

        exact = parser.parse("host interface eth4", mode="hidden", ctx=ctx)
        self.assertEqual(ParseStatus.VALID_UNIQUE, exact.status)
        self.assertTrue(exact.executable)

    def test_unique_dynamic_interface_prefix_is_valid_and_canonical(self):
        registry = build_default_registry(
            ifnet_provider=FakeInterfaceProvider((fake_ethernet_without_ipv4("eth0"),))
        )
        ctx = CliContext(output=io.StringIO())
        ctx.push_mode("hidden")
        registry.initialize_context(ctx)
        ETHERNET_stage_device_install(ctx.state, "eth0")
        ETHERNET_commit_device_changes(ctx.state)
        parser = CommandParser(registry)

        inloopback = parser.parse("show interfaces in", mode="hidden", ctx=ctx)
        self.assertEqual(ParseStatus.VALID_UNIQUE, inloopback.status)
        self.assertEqual(TokenStyle.VALID, inloopback.token_statuses[2].style)
        self.assertEqual({"name": "InLoopBack0"}, inloopback.args)
        self.assertEqual("show interfaces InLoopBack0", inloopback.complete_command)

        null0 = parser.parse("show interfaces n", mode="hidden", ctx=ctx)
        self.assertEqual(ParseStatus.VALID_UNIQUE, null0.status)
        self.assertEqual(TokenStyle.VALID, null0.token_statuses[2].style)
        self.assertEqual({"name": "NULL0"}, null0.args)
        self.assertEqual("show interfaces NULL0", null0.complete_command)

    def test_ambiguous_top_level_token_does_not_complete_before_space(self):
        parser = CommandParser(build_default_registry())

        self.assertIsNone(parser.complete_before_space("s", mode="privileged"))

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

    def test_dispatch_accepts_uppercase_command_literals(self):
        calls: list[tuple[str, dict[str, str]]] = []
        registry = build_registry(calls)
        ctx = CliContext(output=io.StringIO())

        outcome = dispatch_line(ctx, registry, "SHOW INTERFACE eth3")

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

        self.assertIn("interfaces             Show VVRP interfaces", help_text)
        self.assertIn("running-configuration  Show current running configuration", help_text)
        self.assertIn("saved-configuration    Show saved configuration", help_text)
        self.assertIn("version                Show software version", help_text)


class InteractiveTests(unittest.TestCase):
    def test_preserve_help_input_removes_question_mark_and_suffix(self):
        self.assertEqual("show ip ", _preserve_help_input("show ip ?"))
        self.assertEqual("show ip", _preserve_help_input("show ip?"))
        self.assertEqual("show ip ", _preserve_help_input("show ip ? anything"))

    def test_help_screen_update_preserves_original_input_line(self):
        self.assertEqual(
            "Router(config)# show ?\n  <cr>  Show command group",
            _format_help_screen_update(
                "Router(config)# ",
                "show ?",
                "  <cr>  Show command group",
            ),
        )

    def test_colored_help_screen_update_preserves_input_token_styles(self):
        token_statuses = (
            TokenStatus(0, 4, TokenStyle.VALID),
            TokenStatus(5, 7, TokenStyle.AMBIGUOUS),
            TokenStatus(8, 9, TokenStyle.INVALID),
        )

        self.assertEqual(
            "\x1b[32mshow\x1b[0m \x1b[33mip\x1b[0m \x1b[31m?\x1b[0m",
            _render_input_with_token_styles("show ip ?", token_statuses),
        )
        self.assertEqual(
            "Router(config)# \x1b[32mshow\x1b[0m \x1b[33mip\x1b[0m "
            "\x1b[31m?\x1b[0m\n  <cr>  Show command group",
            _format_colored_help_screen_update(
                "Router(config)# ",
                "show ip ?",
                "  <cr>  Show command group",
                token_statuses,
            ),
        )

    def test_prompt_toolkit_ansi_output_routes_command_text_through_ansi(self):
        calls: list[tuple[str, str]] = []

        def fake_ansi(text):
            calls.append(("ansi", text))
            return f"ANSI({text})"

        def fake_print(value, end="\n"):
            calls.append(("print", f"{value}|{end}"))

        output = _PromptToolkitAnsiOutput(fake_print, fake_ansi)

        self.assertEqual(12, output.write("\x1b[31mred\x1b[0m"))
        output.flush()

        self.assertEqual(
            [
                ("ansi", "\x1b[31mred\x1b[0m"),
                ("print", "ANSI(\x1b[31mred\x1b[0m)|"),
            ],
            calls,
        )

    def test_non_tty_fallback_dispatches_lines(self):
        output = io.StringIO()

        with tempfile.TemporaryDirectory() as temp_dir:
            with (
                patch("src.CCmd.interactive.sys.stdin.isatty", return_value=False),
                patch("src.CCmd.interactive.sys.stdout.isatty", return_value=False),
                patch("builtins.input", side_effect=["show version", EOFError]),
                patch("src.CCmd.models.sys.stdout", output),
            ):
                result = run_interactive_cli(
                    build_default_registry(),
                    saved_configuration_file=Path(temp_dir) / "saved-configuration",
                )

        self.assertEqual(0, result)
        self.assertIn("VVRP CCmd version 0.1.0", output.getvalue())

    def test_non_tty_fallback_starts_runtime_services_after_configuration_load(self):
        output = io.StringIO()
        calls = []

        class FakeRuntime(VVRP_Runtime):
            def VVRP_refresh_control_plane(self, ctx):
                calls.append(ctx.hostname)
                return "1 listener(s) running"

        with tempfile.TemporaryDirectory() as temp_dir:
            with (
                patch("src.CCmd.interactive.sys.stdin.isatty", return_value=False),
                patch("src.CCmd.interactive.sys.stdout.isatty", return_value=False),
                patch("builtins.input", side_effect=[EOFError]),
                patch("src.CCmd.models.sys.stdout", output),
            ):
                result = run_interactive_cli(
                    build_default_registry(runtime=FakeRuntime()),
                    saved_configuration_file=Path(temp_dir) / "saved-configuration",
                )

        self.assertEqual(0, result)
        self.assertEqual(["Router"], calls)

    def test_non_tty_fallback_preserves_help_prefix_for_next_prompt(self):
        output = io.StringIO()
        prompts: list[str] = []
        responses = iter(["show ?", "version"])

        def fake_input(prompt_text):
            prompts.append(prompt_text)
            try:
                return next(responses)
            except StopIteration:
                raise EOFError

        with tempfile.TemporaryDirectory() as temp_dir:
            with (
                patch("src.CCmd.interactive.sys.stdin.isatty", return_value=False),
                patch("src.CCmd.interactive.sys.stdout.isatty", return_value=False),
                patch("builtins.input", side_effect=fake_input),
                patch("src.CCmd.models.sys.stdout", output),
            ):
                result = run_interactive_cli(
                    build_default_registry(),
                    saved_configuration_file=Path(temp_dir) / "saved-configuration",
                )

        self.assertEqual(0, result)
        self.assertEqual(["<Router> ", "<Router> show ", "<Router> "], prompts)
        self.assertIn("version", output.getvalue())
        self.assertIn("VVRP CCmd version 0.1.0", output.getvalue())


class ModuleBoundaryTests(unittest.TestCase):
    def test_ping_module_lives_in_ip_not_ccmd(self):
        self.assertIsNone(importlib.util.find_spec("src.CCmd.ping"))
        self.assertIsNotNone(importlib.util.find_spec("src.IP.ICMP.ping"))
        self.assertIsNotNone(importlib.util.find_spec("src.IFNET"))
        self.assertIsNotNone(importlib.util.find_spec("src.ETHERNET"))
        self.assertIsNotNone(importlib.util.find_spec("src.ARP"))
        self.assertIsNotNone(importlib.util.find_spec("src.IFNET.Ethernet"))
        self.assertIsNotNone(importlib.util.find_spec("src.IFNET.Loopback"))

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
        self.fail_next: IP_DhcpClientResult | None = None

    def IP_enable_dhcp(self, interface: NetworkInterface) -> IP_DhcpClientResult:
        self.calls.append(("enable dhcp", interface.name))
        if self.fail_next is not None:
            result = self.fail_next
            self.fail_next = None
            return result
        return IP_DhcpClientResult(ok=True)

    def IP_disable_dhcp(self, interface: NetworkInterface) -> IP_DhcpClientResult:
        self.calls.append(("disable dhcp", interface.name))
        if self.fail_next is not None:
            result = self.fail_next
            self.fail_next = None
            return result
        return IP_DhcpClientResult(ok=True)


class FakeNpcapLibrary:
    def __init__(self, devices: tuple[NpcapDevice, ...]):
        self.devices = devices

    def list_devices(self) -> tuple[NpcapDevice, ...]:
        return self.devices


class FakeDPlaneBackend:
    def __init__(self, devices: tuple[NpcapDevice, ...]):
        self.devices = devices

    @property
    def DPlane_platform(self):
        from src.DPlane import DPlane_PlatformInfo

        return DPlane_PlatformInfo(kind="windows", system="Windows")

    def DPlane_list_host_interfaces(self):
        return ()

    def DPlane_list_packet_devices(self):
        return self.devices

    def DPlane_find_packet_device(self, DPlane_interface, DPlane_devices=None):
        from src.DPlane.Windows.npcap import find_npcap_device_for_interface

        return find_npcap_device_for_interface(
            DPlane_interface,
            tuple(DPlane_devices if DPlane_devices is not None else self.devices),
        )

    def DPlane_open_packet_port(self, DPlane_device):
        class FakeDPlanePort:
            def open(self) -> None:
                return None

            def close(self) -> None:
                return None

            def recv_frame(self):
                return None

            def send_frame(self, frame) -> None:
                return None

            def set_filter(self, expression: str) -> None:
                return None

            def __enter__(self):
                self.open()
                return self

            def __exit__(self, exc_type, exc, traceback) -> None:
                self.close()

        return FakeDPlanePort()

    def DPlane_set_interface_enabled(self, DPlane_interface, DPlane_enabled):
        from src.DPlane import DPlane_Result

        return DPlane_Result(ok=True)

    def DPlane_install_forwarding_entry(self, DPlane_entry):
        from src.DPlane import DPlane_Result

        return DPlane_Result(ok=True)

    def DPlane_delete_forwarding_entry(self, DPlane_entry):
        from src.DPlane import DPlane_Result

        return DPlane_Result(ok=True)


class VVRPRuntimeTests(unittest.TestCase):
    def test_ethernet_port_is_opened_before_fwd_uses_it(self):
        class TrackingPort:
            def __init__(self):
                self.opened = False

            def open(self):
                self.opened = True

            def close(self):
                return None

            def recv_frame(self):
                return None

            def send_frame(self, frame):
                if not self.opened:
                    raise RuntimeError("port is not open")

            def set_filter(self, expression):
                return None

        class TrackingDPlaneBackend(FakeDPlaneBackend):
            def __init__(self):
                super().__init__((NpcapDevice(name=r"\Device\NPF_eth0", description="eth0"),))
                self.port = TrackingPort()

            def DPlane_open_packet_port(self, DPlane_device):
                return self.port

        backend = TrackingDPlaneBackend()
        runtime = VVRP_Runtime(VVRP_dplane_backend=backend)
        interface = NetworkInterface(
            name="eth0",
            kind="ethernet",
            index=1,
            is_up=True,
            mac_address="02:00:00:00:00:01",
            speed_mbps=1000,
            ifnet_index=1,
            mtu=1500,
        )

        port = runtime.VVRP_ethernet_port(interface)

        self.assertIs(port, backend.port)
        self.assertTrue(port.opened)


def register_host_interface_commands_for_test(
    registry: CommandRegistry,
    provider=None,
    admin_provider=None,
    modes=("hidden", "interface", "host-interface"),
) -> None:
    register_dplane_commands(
        registry,
        ifnet_provider=provider,
        ifnet_admin_provider=admin_provider,
        dplane_backend=FakeDPlaneBackend(
            (NpcapDevice(name=r"\Device\NPF_eth3", description="eth3"),)
        ),
        modes=modes,
    )


class FakePingPacketPort:
    def __init__(self, frames: tuple[bytes | None, ...] = ()):
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
            return None
        return self.frames.pop(0)

    def send_frame(self, frame: bytes) -> None:
        self.sent.append(frame)

    def set_filter(self, expression: str) -> None:
        self.filters.append(expression)

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()


class FakeClock:
    def __init__(self) -> None:
        self.value = 0.0

    def monotonic(self) -> float:
        self.value += 0.001
        return self.value

    def sleep(self, seconds: float) -> None:
        self.value += seconds


class FakeStaticIpv4Provider:
    def __init__(self):
        self.calls: list[tuple[str, str, IP_StaticIpv4Address | None]] = []
        self.fail_next: IP_StaticIpv4Result | None = None

    def IP_set_static_ipv4(
        self,
        interface: NetworkInterface,
        address: IP_StaticIpv4Address,
    ) -> IP_StaticIpv4Result:
        self.calls.append(("set static ipv4", interface.name, address))
        if self.fail_next is not None:
            result = self.fail_next
            self.fail_next = None
            return result
        return IP_StaticIpv4Result(ok=True)

    def IP_remove_static_ipv4(
        self,
        interface: NetworkInterface,
        address: IP_StaticIpv4Address | None = None,
    ) -> IP_StaticIpv4Result:
        self.calls.append(("remove static ipv4", interface.name, address))
        if self.fail_next is not None:
            result = self.fail_next
            self.fail_next = None
            return result
        return IP_StaticIpv4Result(ok=True)


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


def fake_ethernet_without_ipv4(name: str, index: int = 3) -> NetworkInterface:
    return replace(
        fake_ethernet(name, index=index),
        addresses=(
            InterfaceAddress(family="ipv6", address="2001:db8::20", prefix_length=64),
        ),
    )


def with_ipv4(
    interface: NetworkInterface,
    address: str,
    prefix_length: int,
) -> NetworkInterface:
    return replace(
        interface,
        addresses=(InterfaceAddress(family="ipv4", address=address, prefix_length=prefix_length),),
    )


def _build_icmp_echo_reply(identifier: int, sequence: int, payload: bytes) -> bytes:
    header = struct.pack("!BBHHH", g_ICMP_ECHO_REPLY, g_ICMP_CODE, 0, identifier, sequence)
    checksum = ICMP_checksum(header + payload)
    return struct.pack("!BBHHH", g_ICMP_ECHO_REPLY, g_ICMP_CODE, checksum, identifier, sequence) + payload


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
            patch("src.DPlane.interface_discovery.platform.system", return_value="Windows"),
            patch(
                "src.DPlane.interface_discovery._windows_interface_index_map",
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

    def test_windows_metadata_map_preserves_stable_interface_index(self):
        class FakePsutil:
            AF_LINK = object()

        raw_addresses = {
            "eth4": [FakeRawAddress(FakePsutil.AF_LINK, "00-E0-4C-68-00-BE")],
        }

        with (
            patch("src.DPlane.interface_discovery.platform.system", return_value="Windows"),
            patch(
                "src.DPlane.interface_discovery._windows_interface_index_map",
                return_value={
                    "eth4": {
                        "index": 70,
                        "adapter_name": "{13ED46E6-5AA8-4B75-BB3B-71F6CC306B6A}",
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

    def test_show_interfaces_brief_lists_fake_provider(self):
        registry = CommandRegistry()
        register_host_interface_commands_for_test(
            registry,
            provider=FakeInterfaceProvider(fake_interfaces()),
        )
        output = io.StringIO()
        ctx = CliContext(output=output)
        ctx.push_mode("hidden")

        outcome = dispatch_line(ctx, registry, "show host interface brief")

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
        register_host_interface_commands_for_test(
            registry,
            provider=FakeInterfaceProvider(fake_interfaces()),
        )
        output = io.StringIO()
        ctx = CliContext(output=output)
        ctx.push_mode("hidden")

        outcome = dispatch_line(ctx, registry, "show host interface eth3")

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
        register_host_interface_commands_for_test(
            registry,
            provider=FakeInterfaceProvider(fake_interfaces()),
        )
        output = io.StringIO()
        ctx = CliContext(output=output)
        ctx.push_mode("hidden")

        outcome = dispatch_line(ctx, registry, "show host interface")

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
        register_host_interface_commands_for_test(
            registry,
            provider=FakeInterfaceProvider(fake_interfaces()),
        )
        output = io.StringIO()
        ctx = CliContext(output=output)
        ctx.push_mode("hidden")

        outcome = dispatch_line(ctx, registry, "show host interface missing0")

        self.assertFalse(outcome.executed)
        self.assertEqual("% Invalid input", outcome.message)
        self.assertIn("% Invalid input", output.getvalue())

    def test_show_vvrp_interfaces_lists_only_installed_interfaces(self):
        registry = build_default_registry(ifnet_provider=FakeInterfaceProvider(fake_interfaces()))
        output = io.StringIO()
        ctx = CliContext(output=output)
        registry.initialize_context(ctx)

        self.assertTrue(dispatch_line(ctx, registry, "show interfaces brief").executed)
        self.assertIn("NULL0", output.getvalue())
        self.assertIn("NULL0                        up       up(s)", output.getvalue())

        ETHERNET_stage_device_install(ctx.state, "eth3")
        ETHERNET_commit_device_changes(ctx.state)
        output.truncate(0)
        output.seek(0)

        self.assertTrue(dispatch_line(ctx, registry, "show interfaces brief").executed)

        text = output.getvalue()
        self.assertIn("PHY: Physical", text)
        self.assertIn("NULL0", text)
        self.assertIn("eth3", text)
        self.assertNotIn("loopback_0", text)
        self.assertNotIn("AA:BB:CC:DD:EE:FF", text)
        self.assertNotIn("192.0.2.10/24", text)

    def test_show_vvrp_interfaces_brief_shows_ethernet_protocol_down_without_ipv4(self):
        registry = build_default_registry(
            ifnet_provider=FakeInterfaceProvider((fake_ethernet_without_ipv4("eth0", index=7),))
        )
        output = io.StringIO()
        ctx = CliContext(output=output)
        registry.initialize_context(ctx)
        ETHERNET_stage_device_install(ctx.state, "eth0")
        ETHERNET_commit_device_changes(ctx.state)

        self.assertTrue(dispatch_line(ctx, registry, "show interfaces brief").executed)

        text = output.getvalue()
        self.assertIn("eth0", text)
        self.assertIn("eth0                         up       down", text)

    def test_show_vvrp_interfaces_detail_uses_imported_ifnet_indices(self):
        registry = build_default_registry(ifnet_provider=FakeInterfaceProvider(fake_interfaces()))
        output = io.StringIO()
        ctx = CliContext(output=output)
        registry.initialize_context(ctx)
        ETHERNET_stage_device_install(ctx.state, "eth3")
        ETHERNET_stage_device_install(ctx.state, "loopback_0")
        ETHERNET_commit_device_changes(ctx.state)

        self.assertTrue(dispatch_line(ctx, registry, "show interfaces").executed)

        text = output.getvalue()
        self.assertLess(text.index("loopback_0 current state"), text.index("eth3 current state"))
        self.assertIn("loopback_0 current state : UP", text)
        self.assertIn("Line protocol current state : UP(spoofing)", text)
        self.assertIn("IFNET Index : 0x1", text)
        self.assertIn("eth3 current state : UP", text)
        self.assertIn("IFNET Index : 0x2", text)
        self.assertIn("Route Port,The Maximum Transmit Unit is 1500", text)
        self.assertIn("Hardware address is AA:BB:CC:DD:EE:FF", text)
        self.assertIn("Internet Address is unassigned", text)

    def test_builtin_vvrp_interfaces_use_reserved_ifnet_indices(self):
        registry = build_default_registry(ifnet_provider=FakeInterfaceProvider(fake_interfaces()))
        output = io.StringIO()
        ctx = CliContext(output=output)
        registry.initialize_context(ctx)

        self.assertTrue(dispatch_line(ctx, registry, "show interfaces NULL0").executed)

        text = output.getvalue()
        self.assertIn("NULL0 current state : UP", text)
        self.assertIn("Line protocol current state : UP(spoofing)", text)
        self.assertIn("IFNET Index : 0xffff", text)
        self.assertIn("Interface type : null", text)
        output.truncate(0)
        output.seek(0)

        self.assertTrue(dispatch_line(ctx, registry, "show interfaces InLoopBack0").executed)

        text = output.getvalue()
        self.assertIn("InLoopBack0 current state : UP", text)
        self.assertIn("Line protocol current state : UP(spoofing)", text)
        self.assertIn("IFNET Index : 0x0", text)
        self.assertIn("Interface type : loopback", text)

    def test_null0_ip_interface_is_up_spoofing_without_ip_processing(self):
        registry = build_default_registry(ifnet_provider=FakeInterfaceProvider(fake_interfaces()))
        output = io.StringIO()
        ctx = CliContext(output=output)
        registry.initialize_context(ctx)

        self.assertTrue(dispatch_line(ctx, registry, "show ip interface NULL0").executed)

        text = output.getvalue()
        self.assertIn("NULL0 current state : UP", text)
        self.assertIn("Line protocol current state : UP (spoofing)", text)
        self.assertIn("Internet protocol processing : disabled", text)
        self.assertIn("Broadcast address : 0.0.0.0", text)

    def test_null0_rejects_shutdown_and_ip_address(self):
        registry = build_default_registry(ifnet_provider=FakeInterfaceProvider(fake_interfaces()))
        ctx = CliContext(output=io.StringIO())
        registry.initialize_context(ctx)
        ctx.push_mode("hidden")

        self.assertTrue(dispatch_line(ctx, registry, "interface NULL0").executed)
        shutdown = dispatch_line(ctx, registry, "shutdown")
        self.assertTrue(shutdown.executed)
        self.assertEqual("% Null interface cannot be shut down: NULL0", shutdown.message)
        ip_address = dispatch_line(ctx, registry, "ip address 192.0.2.1 24")
        self.assertTrue(ip_address.executed)
        self.assertEqual("% NULL interface does not support static IPv4: NULL0", ip_address.message)

    def test_inloopback0_rejects_interface_configuration_view(self):
        registry = build_default_registry(ifnet_provider=FakeInterfaceProvider(fake_interfaces()))
        ctx = CliContext(output=io.StringIO())
        registry.initialize_context(ctx)
        ctx.push_mode("hidden")

        outcome = dispatch_line(ctx, registry, "interface InLoopBack0")

        self.assertTrue(outcome.executed)
        self.assertEqual("% Interface does not support configuration view: InLoopBack0", outcome.message)
        self.assertEqual("hidden", ctx.mode)

    def test_vvrp_interface_commands_match_names_case_insensitively(self):
        registry = build_default_registry(ifnet_provider=FakeInterfaceProvider(fake_interfaces()))
        output = io.StringIO()
        ctx = CliContext(output=output)
        registry.initialize_context(ctx)
        ctx.push_mode("hidden")

        self.assertTrue(dispatch_line(ctx, registry, "interface null0").executed)
        self.assertEqual("interface", ctx.mode)
        self.assertEqual("NULL0", ctx.mode_label)
        ctx.quit_mode()

        self.assertTrue(dispatch_line(ctx, registry, "show interfaces null0").executed)
        self.assertIn("NULL0 current state : UP", output.getvalue())
        output.truncate(0)
        output.seek(0)
        self.assertTrue(dispatch_line(ctx, registry, "show interfaces brief null0").executed)
        self.assertIn("NULL0", output.getvalue())
        output.truncate(0)
        output.seek(0)
        self.assertTrue(dispatch_line(ctx, registry, "show interfaces inloopback0").executed)
        self.assertIn("InLoopBack0 current state : UP", output.getvalue())

        parser = CommandParser(registry)
        candidates = parser.help_candidates("show interfaces ", mode="hidden", ctx=ctx)
        candidate_names = [candidate.display for candidate in candidates]
        self.assertIn("NULL0", candidate_names)
        self.assertIn("InLoopBack0", candidate_names)
        self.assertNotIn("null0", candidate_names)
        self.assertNotIn("inloopback0", candidate_names)

    def test_show_vvrp_interfaces_name_requires_installed_interface(self):
        registry = build_default_registry(ifnet_provider=FakeInterfaceProvider(fake_interfaces()))
        output = io.StringIO()
        ctx = CliContext(output=output)
        registry.initialize_context(ctx)
        ETHERNET_stage_device_install(ctx.state, "eth3")
        ETHERNET_commit_device_changes(ctx.state)

        self.assertTrue(dispatch_line(ctx, registry, "show interfaces eth3").executed)
        self.assertIn("eth3 current state : UP", output.getvalue())
        output.truncate(0)
        output.seek(0)

        outcome = dispatch_line(ctx, registry, "show interfaces loopback_0")

        self.assertFalse(outcome.executed)
        self.assertEqual(ParseStatus.INVALID, outcome.status)
        self.assertIn("% Invalid input", output.getvalue())

    def test_interface_command_enters_only_imported_vvrp_interface(self):
        registry = build_default_registry(ifnet_provider=FakeInterfaceProvider(fake_interfaces()))
        output = io.StringIO()
        ctx = CliContext(output=output)
        registry.initialize_context(ctx)
        ctx.push_mode("privileged")
        ctx.push_mode("config")

        outcome = dispatch_line(ctx, registry, "interface eth3")

        self.assertFalse(outcome.executed)
        self.assertEqual(ParseStatus.INVALID, outcome.status)
        self.assertIn("% Invalid input", output.getvalue())
        self.assertEqual("config", ctx.mode)

        ETHERNET_stage_device_install(ctx.state, "eth3")
        ETHERNET_stage_device_install(ctx.state, "loopback_0")
        ETHERNET_commit_device_changes(ctx.state)
        output.truncate(0)
        output.seek(0)

        self.assertTrue(dispatch_line(ctx, registry, "interface eth3").executed)
        self.assertEqual("interface", ctx.mode)
        self.assertEqual("eth3", ctx.mode_label)
        self.assertTrue(dispatch_line(ctx, registry, "interface loopback_0").executed)
        self.assertEqual("interface", ctx.mode)
        self.assertEqual("loopback_0", ctx.mode_label)

    def test_dynamic_vvrp_interface_parameter_marks_prefix_and_unknown(self):
        registry = build_default_registry(
            ifnet_provider=FakeInterfaceProvider((fake_ethernet("eth0"), fake_ethernet("eth4")))
        )
        ctx = CliContext(output=io.StringIO())
        registry.initialize_context(ctx)
        ETHERNET_stage_device_install(ctx.state, "eth0")
        ETHERNET_stage_device_install(ctx.state, "eth4")
        ETHERNET_commit_device_changes(ctx.state)
        parser = CommandParser(registry)

        prefix = parser.parse("interface eth", mode="config", ctx=ctx)
        self.assertEqual(ParseStatus.AMBIGUOUS, prefix.status)
        self.assertEqual(("eth0", "eth4"), prefix.candidates)
        self.assertEqual(TokenStyle.AMBIGUOUS, prefix.token_statuses[1].style)

        unknown = parser.parse("interface eth5", mode="config", ctx=ctx)
        self.assertEqual(ParseStatus.INVALID, unknown.status)
        self.assertEqual(TokenStyle.INVALID, unknown.token_statuses[1].style)

        show_unknown = parser.parse("show interfaces eth5", mode="config", ctx=ctx)
        self.assertEqual(ParseStatus.INVALID, show_unknown.status)
        self.assertEqual(TokenStyle.INVALID, show_unknown.token_statuses[2].style)

    def test_default_registry_has_ifnet_commands(self):
        parser = CommandParser(build_default_registry())

        for mode in ("hidden", "host-interface"):
            self.assertTrue(parser.parse("show host interface", mode=mode).executable, mode)
            self.assertTrue(parser.parse("show host interface brief", mode=mode).executable, mode)
            self.assertTrue(parser.parse("show host interface eth3", mode=mode).executable, mode)
        for mode in ("user", "privileged", "config", "interface"):
            self.assertEqual(ParseStatus.INVALID, parser.parse("show host interface", mode=mode).status, mode)
        for mode in ("user", "privileged", "config", "hidden", "interface", "host-interface"):
            self.assertTrue(parser.parse("show interfaces", mode=mode).executable, mode)
            self.assertTrue(parser.parse("show interfaces brief", mode=mode).executable, mode)
            self.assertTrue(parser.parse("show interfaces eth3", mode=mode).executable, mode)
            self.assertTrue(parser.parse("show interfaces brief eth3", mode=mode).executable, mode)
        abbreviated_host_interfaces = parser.parse("host interface eth3", mode="hidden")
        self.assertTrue(abbreviated_host_interfaces.executable)
        self.assertEqual("host interface eth3", abbreviated_host_interfaces.complete_command)
        self.assertTrue(parser.parse("interface eth3", mode="config").executable)
        self.assertTrue(parser.parse("interface eth3", mode="hidden").executable)
        self.assertTrue(parser.parse("shutdown", mode="interface").executable)
        self.assertTrue(parser.parse("no shutdown", mode="interface").executable)
        self.assertTrue(parser.parse("mac-address 02:00:00:00:00:01", mode="interface").executable)
        self.assertTrue(parser.parse("no mac-address", mode="interface").executable)
        self.assertTrue(parser.parse("mtu 1600", mode="interface").executable)
        self.assertTrue(parser.parse("no mtu", mode="interface").executable)
        self.assertEqual(ParseStatus.INVALID, parser.parse("shutdown", mode="privileged").status)
        self.assertEqual(ParseStatus.INVALID, parser.parse("no shutdown", mode="config").status)
        self.assertEqual(ParseStatus.INVALID, parser.parse("mac-address 02:00:00:00:00:01", mode="config").status)
        self.assertEqual(ParseStatus.INVALID, parser.parse("mtu 1600", mode="config").status)

        hidden_candidates = parser.help_candidates("", mode="hidden")
        self.assertIn(
            ("interface", "Enter VVRP interface configuration mode"),
            [(candidate.display, candidate.help_text) for candidate in hidden_candidates],
        )

    def test_default_registry_has_dplane_interface_show_in_hidden_mode(self):
        registry = build_default_registry(
            ifnet_provider=FakeInterfaceProvider(fake_interfaces()),
            dplane_backend=FakeDPlaneBackend(
                (
                    NpcapDevice(
                        name=r"\Device\NPF_{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}",
                        description="eth3",
                    ),
                )
            ),
        )
        parser = CommandParser(registry)

        self.assertTrue(parser.parse("show dplane interfaces", mode="hidden").executable)
        self.assertTrue(parser.parse("show dplane interfaces brief", mode="hidden").executable)
        self.assertTrue(parser.parse("show dplane interfaces", mode="host-interface").executable)
        self.assertTrue(parser.parse("show dplane interfaces brief", mode="host-interface").executable)
        self.assertTrue(parser.parse("host interface eth3", mode="host-interface").executable)
        self.assertTrue(parser.parse("import", mode="host-interface").executable)
        self.assertTrue(parser.parse("no import", mode="host-interface").executable)
        self.assertTrue(parser.parse("commit", mode="host-interface").executable)
        self.assertTrue(parser.parse("show this", mode="host-interface").executable)
        self.assertTrue(parser.parse("show this", mode="interface").executable)
        self.assertTrue(parser.parse("save", mode="host-interface").executable)
        self.assertTrue(parser.parse("save", mode="interface").executable)
        self.assertTrue(parser.parse("save", mode="config").executable)
        self.assertTrue(parser.parse("save", mode="privileged").executable)
        self.assertTrue(parser.parse("save", mode="hidden").executable)
        for mode in ("user",):
            self.assertEqual(ParseStatus.INVALID, parser.parse("save", mode=mode).status, mode)
        for mode in ("user", "privileged", "config", "interface"):
            self.assertEqual(
                ParseStatus.INVALID,
                parser.parse("show dplane interfaces", mode=mode).status,
                mode,
            )
            self.assertEqual(
                ParseStatus.INVALID,
                parser.parse("show dplane interfaces brief", mode=mode).status,
                mode,
            )
            self.assertEqual(
                ParseStatus.INVALID,
                parser.parse("host interface eth3", mode=mode).status,
                mode,
            )

        output = io.StringIO()
        ctx = CliContext(output=output)
        ctx.push_mode("hidden")

        outcome = dispatch_line(ctx, registry, "show dplane interfaces")

        self.assertTrue(outcome.executed)
        text = output.getvalue()
        self.assertIn("Host interface : eth3", text)
        self.assertIn("OS Index       : 2", text)
        self.assertIn("VVRP           : -", text)
        self.assertIn("IFNET Index    : -", text)
        self.assertIn(r"Packet Device  : \Device\NPF_{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}", text)
        self.assertIn("Status         : \x1b[38;2;242;242;242mmatched\x1b[0m", text)

        output.truncate(0)
        output.seek(0)

        outcome = dispatch_line(ctx, registry, "show dplane interfaces brief")

        self.assertTrue(outcome.executed)
        text = output.getvalue()
        self.assertIn("Host Interface", text)
        self.assertIn("OS Index", text)
        self.assertNotIn("OS-Index", text)
        self.assertNotIn("VVRP", text)
        self.assertIn("IFNET Index", text)
        self.assertNotIn("Npcap Device", text)
        eth3_line = next(line for line in text.splitlines() if line.startswith("eth3"))
        self.assertIn("\x1b[38;2;242;242;242mmatched\x1b[0m", eth3_line)
        self.assertNotIn(r"\Device\NPF_{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}", eth3_line)

    def test_ccmd_entrypoint_from_src_uses_canonical_src_package(self):
        project_root = Path(__file__).resolve().parents[1]
        src_dir = project_root / "src"

        completed = subprocess.run(
            [sys.executable, "-m", "CCmd"],
            cwd=src_dir,
            input="_\nshow dplane interfaces brief\nexit\n",
            text=True,
            capture_output=True,
            timeout=10,
        )

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertIn("Host Interface", completed.stdout)
        self.assertIn("OS Index", completed.stdout)

    def test_host_interface_help_has_ip_and_no_descriptions(self):
        registry = build_default_registry(ifnet_provider=FakeInterfaceProvider(fake_interfaces()))
        parser = CommandParser(registry)
        ctx = CliContext(output=io.StringIO())
        ctx.push_mode("host-interface", "eth3")

        candidates = parser.help_candidates("", mode="host-interface", ctx=ctx)

        help_by_display = {candidate.display: candidate.help_text for candidate in candidates}
        self.assertEqual("Configure IP features", help_by_display["ip"])
        self.assertEqual(
            "Negate a command or set its defaults",
            help_by_display["no"],
        )

    def test_host_interface_view_can_switch_host_and_vvrp_interfaces(self):
        registry = build_default_registry(
            ifnet_provider=FakeInterfaceProvider((fake_ethernet("eth2"), fake_ethernet("eth3")))
        )
        ctx = CliContext(output=io.StringIO())
        registry.initialize_context(ctx)
        ETHERNET_stage_device_install(ctx.state, "eth3")
        ETHERNET_commit_device_changes(ctx.state)
        ctx.push_mode("host-interface", "eth2")

        self.assertTrue(dispatch_line(ctx, registry, "host interface eth3").executed)
        self.assertEqual("host-interface", ctx.mode)
        self.assertEqual("eth3", ctx.mode_label)

        self.assertTrue(dispatch_line(ctx, registry, "interface eth3").executed)
        self.assertEqual("interface", ctx.mode)
        self.assertEqual("eth3", ctx.mode_label)

    def test_hidden_view_can_enter_imported_vvrp_interface(self):
        registry = build_default_registry(
            ifnet_provider=FakeInterfaceProvider((fake_ethernet("eth2"), fake_ethernet("eth3")))
        )
        ctx = CliContext(output=io.StringIO())
        registry.initialize_context(ctx)
        ETHERNET_stage_device_install(ctx.state, "eth3")
        ETHERNET_commit_device_changes(ctx.state)
        ctx.push_mode("hidden")

        self.assertTrue(dispatch_line(ctx, registry, "interface eth3").executed)
        self.assertEqual("interface", ctx.mode)
        self.assertEqual("eth3", ctx.mode_label)

    def test_vvrp_interface_show_this_displays_current_interface_config(self):
        registry = build_default_registry(
            ifnet_provider=FakeInterfaceProvider((fake_ethernet("eth2"), fake_ethernet("eth3")))
        )
        output = io.StringIO()
        ctx = CliContext(output=output)
        registry.initialize_context(ctx)
        ETHERNET_stage_device_install(ctx.state, "eth2")
        ETHERNET_stage_device_install(ctx.state, "eth3")
        ETHERNET_commit_device_changes(ctx.state)
        ctx.push_mode("config")

        self.assertTrue(dispatch_line(ctx, registry, "interface eth2").executed)
        self.assertTrue(dispatch_line(ctx, registry, "show this").executed)
        self.assertEqual("interface eth2\n quit\n", output.getvalue())

        output.truncate(0)
        output.seek(0)
        set_interface_config_command(ctx, "eth2", "shutdown", "shutdown")
        output.truncate(0)
        output.seek(0)
        self.assertTrue(dispatch_line(ctx, registry, "show this").executed)
        self.assertEqual("interface eth2\n shutdown\n quit\n", output.getvalue())

        output.truncate(0)
        output.seek(0)
        self.assertTrue(dispatch_line(ctx, registry, "interface eth3").executed)
        self.assertTrue(dispatch_line(ctx, registry, "show this").executed)
        self.assertEqual("interface eth3\n quit\n", output.getvalue())

    def test_vvrp_interface_mac_address_overrides_and_restores_imported_mac(self):
        registry = build_default_registry(
            ifnet_provider=FakeInterfaceProvider((fake_ethernet("eth2"), fake_ethernet("eth3")))
        )
        output = io.StringIO()
        ctx = CliContext(output=output)
        registry.initialize_context(ctx)
        ETHERNET_stage_device_install(ctx.state, "eth2")
        ETHERNET_commit_device_changes(ctx.state)
        ctx.push_mode("config")
        self.assertTrue(dispatch_line(ctx, registry, "interface eth2").executed)

        self.assertTrue(dispatch_line(ctx, registry, "mac-address 02-00-00-00-00-01").executed)
        output.truncate(0)
        output.seek(0)
        self.assertTrue(dispatch_line(ctx, registry, "show interfaces eth2").executed)
        self.assertIn("Hardware address is 02:00:00:00:00:01", output.getvalue())

        output.truncate(0)
        output.seek(0)
        self.assertTrue(dispatch_line(ctx, registry, "_").executed)
        self.assertTrue(dispatch_line(ctx, registry, "show host interface eth2").executed)
        self.assertIn("Hardware address is AA:BB:CC:DD:EE:FF", output.getvalue())
        self.assertTrue(dispatch_line(ctx, registry, "quit").executed)

        output.truncate(0)
        output.seek(0)
        self.assertTrue(dispatch_line(ctx, registry, "show this").executed)
        self.assertEqual("interface eth2\n mac-address 02:00:00:00:00:01\n quit\n", output.getvalue())

        self.assertTrue(dispatch_line(ctx, registry, "no mac-address").executed)
        output.truncate(0)
        output.seek(0)
        self.assertTrue(dispatch_line(ctx, registry, "show interfaces eth2").executed)
        self.assertIn("Hardware address is AA:BB:CC:DD:EE:FF", output.getvalue())
        output.truncate(0)
        output.seek(0)
        self.assertTrue(dispatch_line(ctx, registry, "show this").executed)
        self.assertEqual("interface eth2\n quit\n", output.getvalue())

    def test_vvrp_interface_mac_address_rejects_bad_addresses(self):
        registry = build_default_registry(
            ifnet_provider=FakeInterfaceProvider((fake_ethernet("eth2"),))
        )
        ctx = CliContext(output=io.StringIO())
        registry.initialize_context(ctx)
        ETHERNET_stage_device_install(ctx.state, "eth2")
        ETHERNET_commit_device_changes(ctx.state)
        ctx.push_mode("config")
        dispatch_line(ctx, registry, "interface eth2")

        for command, message in (
            ("mac-address ff:ff:ff:ff:ff:ff", "broadcast"),
            ("mac-address 01:00:00:00:00:01", "multicast"),
            ("mac-address 00:00:00:00:00:00", "all-zero"),
            ("mac-address AA:BB:CC:DD:EE:FF", "must differ"),
        ):
            with self.subTest(command=command):
                outcome = dispatch_line(ctx, registry, command)
                self.assertTrue(outcome.executed)
                self.assertIn(message, outcome.message)

    def test_vvrp_interface_mtu_overrides_and_restores_imported_mtu(self):
        registry = build_default_registry(
            ifnet_provider=FakeInterfaceProvider((fake_ethernet("eth2"), fake_ethernet("eth3")))
        )
        output = io.StringIO()
        ctx = CliContext(output=output)
        registry.initialize_context(ctx)
        ETHERNET_stage_device_install(ctx.state, "eth2")
        ETHERNET_commit_device_changes(ctx.state)
        ctx.push_mode("config")
        self.assertTrue(dispatch_line(ctx, registry, "interface eth2").executed)

        self.assertTrue(dispatch_line(ctx, registry, "mtu 1600").executed)
        output.truncate(0)
        output.seek(0)
        self.assertTrue(dispatch_line(ctx, registry, "show interfaces eth2").executed)
        self.assertIn("Route Port,The Maximum Transmit Unit is 1600", output.getvalue())

        output.truncate(0)
        output.seek(0)
        self.assertTrue(dispatch_line(ctx, registry, "_").executed)
        self.assertTrue(dispatch_line(ctx, registry, "show host interface eth2").executed)
        self.assertIn("MTU 1500 bytes", output.getvalue())
        self.assertTrue(dispatch_line(ctx, registry, "quit").executed)

        output.truncate(0)
        output.seek(0)
        self.assertTrue(dispatch_line(ctx, registry, "show this").executed)
        self.assertEqual("interface eth2\n mtu 1600\n quit\n", output.getvalue())

        self.assertTrue(dispatch_line(ctx, registry, "no mtu").executed)
        output.truncate(0)
        output.seek(0)
        self.assertTrue(dispatch_line(ctx, registry, "show interfaces eth2").executed)
        self.assertIn("Route Port,The Maximum Transmit Unit is 1500", output.getvalue())
        output.truncate(0)
        output.seek(0)
        self.assertTrue(dispatch_line(ctx, registry, "show this").executed)
        self.assertEqual("interface eth2\n quit\n", output.getvalue())

    def test_vvrp_interface_mtu_rejects_bad_values_and_loopback(self):
        registry = build_default_registry(
            ifnet_provider=FakeInterfaceProvider(fake_interfaces())
        )
        ctx = CliContext(output=io.StringIO())
        registry.initialize_context(ctx)
        ETHERNET_stage_device_install(ctx.state, "eth3")
        ETHERNET_stage_device_install(ctx.state, "loopback_0")
        ETHERNET_commit_device_changes(ctx.state)
        ctx.push_mode("config")
        dispatch_line(ctx, registry, "interface eth3")

        outcome = dispatch_line(ctx, registry, "mtu 67")
        self.assertTrue(outcome.executed)
        self.assertIn("between 68 and 9216", outcome.message)

        self.assertTrue(dispatch_line(ctx, registry, "interface loopback_0").executed)
        outcome = dispatch_line(ctx, registry, "mtu 1600")
        self.assertTrue(outcome.executed)
        self.assertEqual("% Unsupported interface type for mtu: loopback", outcome.message)

    def test_host_interface_import_requires_match_and_commit(self):
        registry = build_default_registry(
            ifnet_provider=FakeInterfaceProvider(fake_interfaces()),
            dplane_backend=FakeDPlaneBackend(
                (
                    NpcapDevice(
                        name=r"\Device\NPF_{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}",
                        description="eth3",
                    ),
                )
            ),
        )
        output = io.StringIO()
        ctx = CliContext(output=output)
        ctx.push_mode("hidden")

        self.assertTrue(dispatch_line(ctx, registry, "host interface eth3").executed)
        self.assertEqual("host-interface", ctx.mode)
        self.assertEqual("eth3", ctx.mode_label)
        self.assertEqual("Router(host-if-eth3)# ", ctx.prompt)
        self.assertTrue(dispatch_line(ctx, registry, "show").executed)
        self.assertTrue(dispatch_line(ctx, registry, "show dplane interfaces brief").executed)
        self.assertTrue(dispatch_line(ctx, registry, "show host interface eth3").executed)
        self.assertTrue(dispatch_line(ctx, registry, "show host ip interface eth3").executed)
        output.truncate(0)
        output.seek(0)
        self.assertTrue(dispatch_line(ctx, registry, "show this").executed)
        self.assertEqual("host interface eth3\n quit\n", output.getvalue())

        self.assertTrue(dispatch_line(ctx, registry, "import").executed)
        output.truncate(0)
        output.seek(0)
        self.assertTrue(dispatch_line(ctx, registry, "show this").executed)
        self.assertEqual("host interface eth3\n quit\n", output.getvalue())
        self.assertEqual("", render_running_configuration(ctx))
        output.truncate(0)
        output.seek(0)
        self.assertTrue(dispatch_line(ctx, registry, "show running-configuration").executed)
        self.assertEqual("", output.getvalue())
        output.truncate(0)
        output.seek(0)
        ctx.push_mode("hidden")
        dispatch_line(ctx, registry, "show dplane interfaces brief")
        self.assertIn("pending", output.getvalue())
        self.assertNotIn("imported", output.getvalue())
        ctx.quit_mode()

        self.assertTrue(dispatch_line(ctx, registry, "commit").executed)
        output.truncate(0)
        output.seek(0)
        ctx.push_mode("hidden")
        dispatch_line(ctx, registry, "show dplane interfaces brief")
        text = output.getvalue()
        eth3_line = next(line for line in text.splitlines() if line.startswith("eth3"))
        self.assertIn("0x1", eth3_line)
        self.assertIn("imported", eth3_line)
        ctx.quit_mode()
        output.truncate(0)
        output.seek(0)
        self.assertTrue(dispatch_line(ctx, registry, "show this").executed)
        self.assertEqual("host interface eth3\n import\n quit\n", output.getvalue())

        self.assertTrue(dispatch_line(ctx, registry, "no import").executed)
        output.truncate(0)
        output.seek(0)
        self.assertTrue(dispatch_line(ctx, registry, "show this").executed)
        self.assertEqual("host interface eth3\n import\n quit\n", output.getvalue())
        output.truncate(0)
        output.seek(0)
        ctx.push_mode("hidden")
        dispatch_line(ctx, registry, "show dplane interfaces brief")
        self.assertIn("imported", output.getvalue())
        ctx.quit_mode()

        self.assertTrue(dispatch_line(ctx, registry, "commit").executed)
        output.truncate(0)
        output.seek(0)
        ctx.push_mode("hidden")
        dispatch_line(ctx, registry, "show dplane interfaces brief")
        text = output.getvalue()
        eth3_line = next(line for line in text.splitlines() if line.startswith("eth3"))
        self.assertIn("matched", eth3_line)
        self.assertIn(" - ", eth3_line)
        ctx.quit_mode()
        output.truncate(0)
        output.seek(0)
        self.assertTrue(dispatch_line(ctx, registry, "show this").executed)
        self.assertEqual("host interface eth3\n quit\n", output.getvalue())

    def test_host_interface_import_rejects_unmatched_interfaces(self):
        registry = build_default_registry(
            ifnet_provider=FakeInterfaceProvider(fake_interfaces()),
            dplane_backend=FakeDPlaneBackend(()),
        )
        ctx = CliContext(output=io.StringIO())
        ctx.push_mode("hidden")

        self.assertTrue(dispatch_line(ctx, registry, "host interface eth3").executed)
        outcome = dispatch_line(ctx, registry, "import")

        self.assertTrue(outcome.executed)
        self.assertEqual("% Host interface is not matched to a DPlane packet device: eth3", outcome.message)

        outcome = dispatch_line(ctx, registry, "commit")

        self.assertTrue(outcome.executed)
        self.assertEqual("% No host interface import changes to commit", outcome.message)

    def test_ip_address_change_syncs_connected_route_to_fib(self):
        interface_guid = "FD33D129-8AEC-4C32-B9FB-7057F7FF0782"
        registry = build_default_registry(
            ifnet_provider=FakeInterfaceProvider((fake_ethernet_without_ipv4("eth4", index=7),)),
            dplane_backend=FakeDPlaneBackend(
                (
                    NpcapDevice(
                        name=rf"\Device\NPF_{{{interface_guid}}}",
                        description="Intel(R) Ethernet Connection (14) I219-V",
                    ),
                )
            ),
        )
        output = io.StringIO()
        ctx = CliContext(output=output)
        ctx.push_mode("hidden")

        with patch(
            "src.DPlane.Windows.npcap._windows_interface_identity_values",
            return_value=[f"{{{interface_guid}}}", "Intel(R) Ethernet Connection (14) I219-V"],
        ):
            self.assertTrue(dispatch_line(ctx, registry, "host interface eth4").executed)
            self.assertTrue(dispatch_line(ctx, registry, "import").executed)
            self.assertTrue(dispatch_line(ctx, registry, "commit").executed)
            self.assertTrue(dispatch_line(ctx, registry, "interface eth4").executed)
            self.assertTrue(dispatch_line(ctx, registry, "ip address 1.1.1.1 24").executed)
        output.truncate(0)
        output.seek(0)
        self.assertTrue(dispatch_line(ctx, registry, "show fib").executed)

        text = output.getvalue()
        self.assertIn("1.1.1.0/24", text)
        self.assertIn("127.0.0.0/8", text)
        self.assertIn("127.0.0.1/32", text)
        self.assertIn("eth4", text)
        self.assertIn("InLoopBack0", text)

    def test_ip_address_change_with_default_dplane_backend_does_not_raise(self):
        registry = build_default_registry(
            ifnet_provider=FakeInterfaceProvider((fake_ethernet_without_ipv4("eth0", index=7),)),
            dplane_backend=FakeDPlaneBackend((NpcapDevice(name=r"\Device\NPF_eth0", description="eth0"),)),
        )
        ctx = CliContext(output=io.StringIO())
        registry.initialize_context(ctx)
        ctx.push_mode("hidden")

        self.assertTrue(dispatch_line(ctx, registry, "host interface eth0").executed)
        self.assertTrue(dispatch_line(ctx, registry, "import").executed)
        self.assertTrue(dispatch_line(ctx, registry, "commit").executed)
        self.assertTrue(dispatch_line(ctx, registry, "interface eth0").executed)
        outcome = dispatch_line(ctx, registry, "ip address 1.1.1.1 24")

        self.assertTrue(outcome.executed)
        self.assertIn("%%01IFNET/4/LINK_STATE", outcome.message)
        self.assertIn("The line protocol IP on the interface eth0 has entered the UP state.", outcome.message)

    def test_ip_address_protocol_up_log_is_emitted_once(self):
        registry = build_default_registry(
            ifnet_provider=FakeInterfaceProvider((fake_ethernet_without_ipv4("eth0", index=7),)),
            dplane_backend=FakeDPlaneBackend((NpcapDevice(name=r"\Device\NPF_eth0", description="eth0"),)),
        )
        ctx = CliContext(output=io.StringIO(), hostname="R1")
        registry.initialize_context(ctx)
        ctx.push_mode("hidden")

        self.assertTrue(dispatch_line(ctx, registry, "host interface eth0").executed)
        self.assertTrue(dispatch_line(ctx, registry, "import").executed)
        self.assertTrue(dispatch_line(ctx, registry, "commit").executed)
        self.assertTrue(dispatch_line(ctx, registry, "interface eth0").executed)
        primary = dispatch_line(ctx, registry, "ip address 1.1.1.1 24")
        secondary = dispatch_line(ctx, registry, "ip address 1.1.1.2 24 sub")

        self.assertTrue(primary.executed)
        self.assertIn("R1 %%01IFNET/4/LINK_STATE", primary.message)
        self.assertIn("interface eth0 has entered the UP state.", primary.message)
        self.assertTrue(secondary.executed)
        self.assertEqual("", secondary.message)

    def test_no_ip_address_protocol_down_log_is_emitted_when_last_ipv4_is_removed(self):
        registry = build_default_registry(
            ifnet_provider=FakeInterfaceProvider((fake_ethernet_without_ipv4("eth0", index=7),)),
            dplane_backend=FakeDPlaneBackend((NpcapDevice(name=r"\Device\NPF_eth0", description="eth0"),)),
        )
        ctx = CliContext(output=io.StringIO(), hostname="R1")
        registry.initialize_context(ctx)
        ctx.push_mode("hidden")

        self.assertTrue(dispatch_line(ctx, registry, "host interface eth0").executed)
        self.assertTrue(dispatch_line(ctx, registry, "import").executed)
        self.assertTrue(dispatch_line(ctx, registry, "commit").executed)
        self.assertTrue(dispatch_line(ctx, registry, "interface eth0").executed)
        self.assertTrue(dispatch_line(ctx, registry, "ip address 1.1.1.1 24").executed)
        self.assertTrue(dispatch_line(ctx, registry, "ip address 1.1.1.2 24 sub").executed)
        secondary = dispatch_line(ctx, registry, "no ip address 1.1.1.2 24 sub")
        all_addresses = dispatch_line(ctx, registry, "no ip address")

        self.assertTrue(secondary.executed)
        self.assertEqual("", secondary.message)
        self.assertTrue(all_addresses.executed)
        self.assertIn("R1 %%01IFNET/4/LINK_STATE(l)[2]", all_addresses.message)
        self.assertIn("interface eth0 has entered the DOWN state.", all_addresses.message)

    def test_host_interface_import_writes_and_loads_running_config(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "saved-configuration"
            registry = build_default_registry(
                ifnet_provider=FakeInterfaceProvider(fake_interfaces()),
                dplane_backend=FakeDPlaneBackend(
                    (
                        NpcapDevice(
                            name=r"\Device\NPF_{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}",
                            description="eth3",
                        ),
                    )
                ),
            )
            output = io.StringIO()
            ctx = CliContext(output=output)
            set_saved_configuration_path(ctx, config_path)
            ctx.push_mode("hidden")

            self.assertTrue(dispatch_line(ctx, registry, "host interface eth3").executed)
            self.assertTrue(dispatch_line(ctx, registry, "import").executed)

            self.assertFalse(config_path.exists())
            self.assertTrue(dispatch_line(ctx, registry, "save").executed)
            self.assertIn("Configuration saved.", output.getvalue())
            self.assertEqual("", render_running_configuration(ctx))
            self.assertEqual("", config_path.read_text(encoding="utf-8"))

            self.assertTrue(dispatch_line(ctx, registry, "commit").executed)
            self.assertEqual(
                "host interface eth3\n import\n quit\n",
                render_running_configuration(ctx),
            )
            self.assertTrue(dispatch_line(ctx, registry, "save").executed)
            self.assertEqual(
                "host interface eth3\n import\n quit\n",
                config_path.read_text(encoding="utf-8"),
            )

            config_path.unlink()
            self.assertTrue(dispatch_line(ctx, registry, "save").executed)
            self.assertEqual(
                "host interface eth3\n import\n quit\n",
                config_path.read_text(encoding="utf-8"),
            )

            self.assertTrue(dispatch_line(ctx, registry, "no import").executed)
            self.assertTrue(dispatch_line(ctx, registry, "commit").executed)
            self.assertEqual(
                "host interface eth3\n import\n quit\n",
                config_path.read_text(encoding="utf-8"),
            )

            restored = CliContext(output=io.StringIO())
            restored_registry = build_default_registry(
                ifnet_provider=FakeInterfaceProvider(fake_interfaces()),
                dplane_backend=FakeDPlaneBackend(
                    (
                        NpcapDevice(
                            name=r"\Device\NPF_{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}",
                            description="eth3",
                        ),
                    )
                ),
            )
            restored_registry.initialize_context(restored)

            errors = load_saved_configuration(restored, restored_registry, config_path)

            self.assertEqual([], errors)
            self.assertEqual(
                "host interface eth3\n import\n quit\n",
                render_running_configuration(restored),
            )
            restored.push_mode("hidden")
            dispatch_line(restored, restored_registry, "show dplane interfaces brief")
            self.assertIn("imported", restored.output.getvalue())

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
        register_host_interface_commands_for_test(
            registry,
            provider=provider,
            admin_provider=admin_provider,
        )
        output = io.StringIO()
        ctx = CliContext(output=output)
        ctx.push_mode("interface", "eth3")

        self.assertTrue(dispatch_line(ctx, registry, "shutdown").executed)
        self.assertEqual([("shutdown", "eth3")], admin_provider.calls)
        output.truncate(0)
        output.seek(0)
        dispatch_line(ctx, registry, "show host interface eth3")
        self.assertIn("eth3 is administratively down, line protocol is down", output.getvalue())

        self.assertTrue(dispatch_line(ctx, registry, "no shutdown").executed)
        self.assertEqual(
            [("shutdown", "eth3"), ("no shutdown", "eth3")],
            admin_provider.calls,
        )
        output.truncate(0)
        output.seek(0)
        dispatch_line(ctx, registry, "show host interface eth3")
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
        register_host_interface_commands_for_test(
            registry,
            provider=provider,
            admin_provider=admin_provider,
        )
        ctx = CliContext(output=io.StringIO())
        ETHERNET_stage_device_install(ctx.state, "VMware Network Adapter VMnet1")
        ETHERNET_commit_device_changes(ctx.state)
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
        register_host_interface_commands_for_test(
            registry,
            provider=provider,
            admin_provider=admin_provider,
        )
        output = io.StringIO()
        ctx = CliContext(output=output)
        ctx.push_mode("interface", "eth3")

        dispatch_line(ctx, registry, "shutdown")
        output.truncate(0)
        output.seek(0)
        dispatch_line(ctx, registry, "show host interface brief")

        self.assertIn("eth3", output.getvalue())
        self.assertIn("*down", output.getvalue())

    def test_shutdown_rejects_loopback_interface(self):
        registry = CommandRegistry()
        admin_provider = FakeAdminProvider()
        provider = FakeInterfaceProvider(fake_interfaces())
        register_ifnet_commands(
            registry,
            provider=provider,
            admin_provider=admin_provider,
            modes=("user", "privileged", "config", "interface", "hidden"),
        )
        register_host_interface_commands_for_test(
            registry,
            provider=provider,
            admin_provider=admin_provider,
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
        dispatch_line(ctx, registry, "show host interface loopback_0")
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
        register_host_interface_commands_for_test(
            registry,
            provider=FakeInterfaceProvider(fake_interfaces()),
            admin_provider=admin_provider,
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
        provider = FakeInterfaceProvider(fake_interfaces())
        register_ifnet_commands(
            registry,
            provider=provider,
            admin_provider=admin_provider,
            modes=("user", "privileged", "config", "interface", "hidden"),
        )
        register_host_interface_commands_for_test(
            registry,
            provider=provider,
            admin_provider=admin_provider,
        )
        output = io.StringIO()
        ctx = CliContext(output=output)
        ctx.push_mode("interface", "eth3")

        outcome = dispatch_line(ctx, registry, "shutdown")

        self.assertTrue(outcome.executed)
        self.assertEqual("% OS interface API failed: access denied", outcome.message)
        output.truncate(0)
        output.seek(0)
        dispatch_line(ctx, registry, "show host interface eth3")
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
        register_host_interface_commands_for_test(
            registry,
            provider=provider,
            admin_provider=admin_provider,
        )
        output = io.StringIO()
        ctx = CliContext(output=output)
        ctx.push_mode("interface", "eth3")

        with patch("src.IFNET.commands.time.sleep", return_value=None):
            outcome = dispatch_line(ctx, registry, "shutdown")

        self.assertTrue(outcome.executed)
        self.assertIn("did not take effect", outcome.message)
        output.truncate(0)
        output.seek(0)
        dispatch_line(ctx, registry, "show host interface brief")
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

    def test_ifnet_without_provider_does_not_discover_host_interfaces(self):
        registry = CommandRegistry()
        register_host_interface_commands_for_test(registry)
        output = io.StringIO()
        ctx = CliContext(output=output)
        ctx.push_mode("hidden")

        outcome = dispatch_line(ctx, registry, "show host interface")

        self.assertTrue(outcome.executed)
        self.assertEqual("No interfaces found", outcome.message)
        self.assertIn("No interfaces found", output.getvalue())

    def test_ethernet_admin_backend_dispatches_to_windows_api(self):
        interface = fake_interfaces()[0]

        with patch("src.DPlane.interface_admin.DPlane_set_interface_enabled") as api:
            result = DPlane_InterfaceAdminProvider(system="Windows").shutdown(interface)

        self.assertTrue(result.ok)
        api.assert_called_once_with(interface, False, "windows")

        with patch("src.DPlane.interface_admin.DPlane_set_interface_enabled") as api:
            result = DPlane_InterfaceAdminProvider(system="Windows").no_shutdown(interface)

        self.assertTrue(result.ok)
        api.assert_called_once_with(interface, True, "windows")

    def test_windows_identity_requires_ifindex(self):
        from src.DPlane.Windows.interface_windows import _adapter_identity_for_interface

        interface = replace(
            fake_interfaces()[0],
            index=None,
        )

        with self.assertRaisesRegex(OSError, "missing OS interface index"):
            _adapter_identity_for_interface(interface)

    def test_ethernet_admin_backend_dispatches_to_linux_api(self):
        interface = fake_interfaces()[0]

        with patch("src.DPlane.interface_admin.DPlane_set_interface_enabled") as api:
            result = DPlane_InterfaceAdminProvider(system="Linux").shutdown(interface)

        self.assertTrue(result.ok)
        api.assert_called_once_with(interface, False, "linux")

    def test_ethernet_admin_backend_reports_unsupported_os(self):
        result = DPlane_InterfaceAdminProvider(system="FreeBSD").shutdown(fake_interfaces()[0])

        self.assertFalse(result.ok)
        self.assertIn("unsupported OS API backend", result.message)

    def test_ethernet_admin_backend_reports_permission_errors(self):
        with patch(
            "src.DPlane.interface_admin.DPlane_set_interface_enabled",
            return_value=DPlane_Result(
                ok=False,
                message="% permission denied: Administrator privileges are required",
            ),
        ):
            result = DPlane_InterfaceAdminProvider(system="Windows").shutdown(fake_interfaces()[0])

        self.assertFalse(result.ok)
        self.assertIn("permission denied", result.message)


class DhcpClientCommandTests(unittest.TestCase):
    def test_show_ip_interface_commands_are_host_hidden_commands(self):
        parser = CommandParser(build_default_registry())

        for mode in ("hidden", "interface", "host-interface"):
            self.assertTrue(parser.parse("show host ip interface", mode=mode).executable, mode)
            self.assertTrue(parser.parse("show host ip interface brief", mode=mode).executable, mode)
            self.assertTrue(
                parser.parse("show host ip interface brief ip-configured", mode=mode).executable,
                mode,
            )
            self.assertTrue(
                parser.parse(
                    "show host ip interface brief ip-configured except loopback",
                    mode=mode,
                ).executable,
                mode,
            )
            self.assertTrue(
                parser.parse("show host ip interface description", mode=mode).executable,
                mode,
            )
            self.assertTrue(
                parser.parse(
                    "show host ip interface description ip-configured",
                    mode=mode,
                ).executable,
                mode,
            )
            self.assertTrue(parser.parse("show host ip interface eth3", mode=mode).executable, mode)
            self.assertTrue(
                parser.parse("show host ip interface brief eth3", mode=mode).executable,
                mode,
            )
            self.assertTrue(
                parser.parse("show host ip interface description eth3", mode=mode).executable,
                mode,
            )

        for mode in ("user", "privileged", "config"):
            self.assertEqual(ParseStatus.INVALID, parser.parse("show host ip interface", mode=mode).status, mode)

        for mode in ("user", "privileged", "config", "interface", "hidden", "host-interface"):
            self.assertTrue(parser.parse("show ip interface", mode=mode).executable, mode)
            self.assertTrue(parser.parse("show ip interface brief", mode=mode).executable, mode)
            self.assertTrue(parser.parse("show ip interface brief ip-configured", mode=mode).executable, mode)
            self.assertTrue(parser.parse("show ip interface description", mode=mode).executable, mode)
            self.assertTrue(parser.parse("show ip interface eth3", mode=mode).executable, mode)
            self.assertTrue(parser.parse("show ip interface brief eth3", mode=mode).executable, mode)
            self.assertTrue(parser.parse("show ip interface description eth3", mode=mode).executable, mode)

    def test_help_candidates_for_show_ip_interface_family(self):
        parser = CommandParser(build_default_registry())

        show_ip_candidates = parser.help_candidates("show host ip ", mode="hidden")
        self.assertEqual(
            [("interface", "Show IPv4 interface information")],
            [(candidate.display, candidate.help_text) for candidate in show_ip_candidates],
        )

        vvrp_show_ip_candidates = parser.help_candidates("show ip ", mode="user")
        self.assertIn(
            ("interface", "Show IPv4 interface information"),
            [(candidate.display, candidate.help_text) for candidate in vvrp_show_ip_candidates],
        )

        interface_candidates = parser.help_candidates("show host ip interface ", mode="hidden")
        self.assertEqual(
            [
                ("brief", "Show brief IPv4 interface summary"),
                ("description", "Show IPv4 interface descriptions"),
                ("<name>", "Show IPv4 information for an interface"),
                ("<cr>", "Show IPv4 interface information"),
            ],
            [(candidate.display, candidate.help_text) for candidate in interface_candidates],
        )

        brief_candidates = parser.help_candidates("show host ip interface brief ", mode="hidden")
        self.assertEqual(
            [
                ("ethernet", "Show brief IPv4 summary for Ethernet interfaces"),
                ("ip-configured", "Show brief IPv4 summary for interfaces with IPv4 configured"),
                ("loopback", "Show brief IPv4 summary for loopback interfaces"),
                ("<name>", "Show brief IPv4 summary for an interface"),
                ("<cr>", "Show brief IPv4 interface summary"),
            ],
            [(candidate.display, candidate.help_text) for candidate in brief_candidates],
        )

        vvrp_interface_candidates = parser.help_candidates("show ip interface ", mode="user")
        self.assertEqual(
            [
                ("brief", "Show brief IPv4 interface summary"),
                ("description", "Show IPv4 interface descriptions"),
                ("<name>", "Show IPv4 information for an interface"),
                ("<cr>", "Show IPv4 interface information"),
            ],
            [(candidate.display, candidate.help_text) for candidate in vvrp_interface_candidates],
        )

    def test_show_ip_interface_brief_lists_ipv4_summary(self):
        registry = build_default_registry(ifnet_provider=FakeInterfaceProvider(fake_interfaces()))
        output = io.StringIO()
        ctx = CliContext(output=output)
        ctx.push_mode("hidden")

        outcome = dispatch_line(ctx, registry, "show host ip interface brief")

        self.assertTrue(outcome.executed)
        text = output.getvalue()
        self.assertIn("*down: administratively down", text)
        self.assertIn("!down: FIB overload down", text)
        self.assertIn("The number of interface that is UP in Physical is 2", text)
        self.assertIn("Interface", text)
        self.assertIn("IP Address/Mask", text)
        self.assertNotIn("VPN", text)
        self.assertIn("loopback_0", text)
        self.assertIn("127.0.0.1/8", text)
        self.assertIn("up(l)", text)
        self.assertIn("up(s)", text)
        self.assertIn("eth3", text)
        self.assertIn("192.0.2.10/24", text)

    def test_show_vvrp_ip_interface_brief_lists_imported_ipv4_summary(self):
        registry = build_default_registry(ifnet_provider=FakeInterfaceProvider(fake_interfaces()))
        output = io.StringIO()
        ctx = CliContext(output=output)
        ETHERNET_stage_device_install(ctx.state, "eth3")
        ETHERNET_commit_device_changes(ctx.state)
        IP_set_interface_addresses(
            ctx.state,
            "eth3",
            (InterfaceAddress(family="ipv4", address="192.0.2.10", prefix_length=24),),
        )

        outcome = dispatch_line(ctx, registry, "show ip interface brief")

        self.assertTrue(outcome.executed)
        text = output.getvalue()
        self.assertIn("eth3", text)
        self.assertIn("192.0.2.10/24", text)
        self.assertNotIn("loopback_0", text)

    def test_show_vvrp_ip_interface_detail_lists_installed_interface(self):
        registry = build_default_registry(ifnet_provider=FakeInterfaceProvider(fake_interfaces()))
        output = io.StringIO()
        ctx = CliContext(output=output)
        ETHERNET_stage_device_install(ctx.state, "eth3")
        ETHERNET_commit_device_changes(ctx.state)
        IP_set_interface_addresses(
            ctx.state,
            "eth3",
            (InterfaceAddress(family="ipv4", address="192.0.2.10", prefix_length=24),),
        )

        outcome = dispatch_line(ctx, registry, "show ip interface eth3")

        self.assertTrue(outcome.executed)
        text = output.getvalue()
        self.assertIn("eth3 current state : UP", text)
        self.assertIn("Internet Address is 192.0.2.10/24 Primary", text)

    def test_show_vvrp_ip_interface_description_filters_installed_interfaces(self):
        registry = build_default_registry(ifnet_provider=FakeInterfaceProvider(fake_interfaces()))
        output = io.StringIO()
        ctx = CliContext(output=output)
        ETHERNET_stage_device_install(ctx.state, "loopback_0")
        ETHERNET_commit_device_changes(ctx.state)
        IP_set_interface_addresses(
            ctx.state,
            "loopback_0",
            (InterfaceAddress(family="ipv4", address="127.0.0.1", prefix_length=8),),
        )

        outcome = dispatch_line(ctx, registry, "show ip interface description ip-configured except ethernet")

        self.assertTrue(outcome.executed)
        text = output.getvalue()
        self.assertIn("loopback_0", text)
        self.assertNotIn("eth3", text)

    def test_show_ip_interface_brief_can_filter_one_interface(self):
        registry = build_default_registry(ifnet_provider=FakeInterfaceProvider(fake_interfaces()))
        output = io.StringIO()
        ctx = CliContext(output=output)
        ctx.push_mode("hidden")

        outcome = dispatch_line(ctx, registry, "show host ip interface brief eth3")

        self.assertTrue(outcome.executed)
        text = output.getvalue()
        self.assertIn("eth3", text)
        self.assertIn("192.0.2.10/24", text)
        self.assertNotIn("loopback_0", text)

    def test_show_ip_interface_brief_filters_ip_configured_interfaces(self):
        interfaces = (
            fake_ethernet("eth3"),
            fake_ethernet_without_ipv4("eth9"),
            fake_interfaces()[1],
        )
        registry = build_default_registry(ifnet_provider=FakeInterfaceProvider(interfaces))
        output = io.StringIO()
        ctx = CliContext(output=output)
        ctx.push_mode("hidden")

        outcome = dispatch_line(ctx, registry, "show host ip interface brief ip-configured")

        self.assertTrue(outcome.executed)
        text = output.getvalue()
        self.assertIn("eth3", text)
        self.assertIn("loopback_0", text)
        self.assertNotIn("eth9", text)

    def test_show_ip_interface_brief_filters_interface_type(self):
        registry = build_default_registry(ifnet_provider=FakeInterfaceProvider(fake_interfaces()))
        output = io.StringIO()
        ctx = CliContext(output=output)
        ctx.push_mode("hidden")

        outcome = dispatch_line(ctx, registry, "show host ip interface brief ethernet")

        self.assertTrue(outcome.executed)
        text = output.getvalue()
        self.assertIn("eth3", text)
        self.assertNotIn("loopback_0", text)

    def test_show_ip_interface_description_lists_ipv4_summary(self):
        registry = build_default_registry(ifnet_provider=FakeInterfaceProvider(fake_interfaces()))
        output = io.StringIO()
        ctx = CliContext(output=output)
        ctx.push_mode("hidden")

        outcome = dispatch_line(ctx, registry, "show host ip interface description")

        self.assertTrue(outcome.executed)
        text = output.getvalue()
        self.assertIn("Codes:", text)
        self.assertIn("Number of interfaces whose physical status is Up: 2", text)
        self.assertIn("Interface", text)
        self.assertIn("IP Address/Mask", text)
        self.assertIn("Phy", text)
        self.assertIn("Prot", text)
        self.assertIn("Description", text)
        self.assertIn("eth3", text)
        self.assertIn("192.0.2.10/24", text)
        self.assertIn("loopback_0", text)
        self.assertNotIn("VPN", text)

    def test_show_ip_interface_description_can_exclude_interface_type(self):
        registry = build_default_registry(ifnet_provider=FakeInterfaceProvider(fake_interfaces()))
        output = io.StringIO()
        ctx = CliContext(output=output)
        ctx.push_mode("hidden")

        outcome = dispatch_line(
            ctx,
            registry,
            "show host ip interface description ip-configured except ethernet",
        )

        self.assertTrue(outcome.executed)
        text = output.getvalue()
        self.assertIn("loopback_0", text)
        self.assertNotIn("eth3", text)

    def test_show_ip_interface_detail_lists_ipv4_addresses(self):
        registry = build_default_registry(ifnet_provider=FakeInterfaceProvider(fake_interfaces()))
        output = io.StringIO()
        ctx = CliContext(output=output)
        ctx.push_mode("hidden")

        outcome = dispatch_line(ctx, registry, "show host ip interface eth3")

        self.assertTrue(outcome.executed)
        text = output.getvalue()
        self.assertIn("eth3 current state : UP", text)
        self.assertIn("Line protocol current state : UP", text)
        self.assertIn("The Maximum Transmit Unit : 1500 bytes", text)
        self.assertIn("Internet protocol processing : enabled", text)
        self.assertIn("IPv4 address number : 1", text)
        self.assertIn("Internet Address is 192.0.2.10/24 Primary", text)
        self.assertIn("Broadcast address : 192.0.2.255", text)

    def test_show_ip_interface_unknown_name_reports_error(self):
        registry = build_default_registry(ifnet_provider=FakeInterfaceProvider(fake_interfaces()))
        output = io.StringIO()
        ctx = CliContext(output=output)
        ctx.push_mode("hidden")

        outcome = dispatch_line(ctx, registry, "show host ip interface missing0")

        self.assertTrue(outcome.executed)
        self.assertEqual("% Interface not found: missing0", outcome.message)
        self.assertIn("% Interface not found: missing0", output.getvalue())

    def test_dhcp_alloc_commands_are_host_interface_only(self):
        registry = build_default_registry(ifnet_provider=FakeInterfaceProvider(fake_interfaces()))
        parser = CommandParser(registry)

        self.assertTrue(parser.parse("ip address dhcp-alloc", mode="host-interface").executable)
        self.assertTrue(parser.parse("no ip address dhcp-alloc", mode="host-interface").executable)
        self.assertEqual(
            ParseStatus.INVALID,
            parser.parse("ip address dhcp-alloc", mode="interface").status,
        )
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
        ctx.push_mode("host-interface", "eth3")

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
        ctx.push_mode("host-interface", "eth3")

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
        ctx.push_mode("host-interface", "loopback_0")

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
        ctx.push_mode("host-interface", "missing0")

        outcome = dispatch_line(ctx, registry, "ip address dhcp-alloc")

        self.assertTrue(outcome.executed)
        self.assertEqual("% Interface not found: missing0", outcome.message)
        self.assertEqual([], dhcp_provider.calls)

    def test_dhcp_provider_failure_is_reported(self):
        dhcp_provider = FakeDhcpProvider()
        dhcp_provider.fail_next = IP_DhcpClientResult(
            ok=False,
            message="% OS interface API failed: DHCP backend failed",
        )
        registry = build_default_registry(
            ifnet_provider=FakeInterfaceProvider(fake_interfaces()),
            ip_dhcp_provider=dhcp_provider,
        )
        ctx = CliContext(output=io.StringIO())
        ctx.push_mode("host-interface", "eth3")

        outcome = dispatch_line(ctx, registry, "ip address dhcp-alloc")

        self.assertTrue(outcome.executed)
        self.assertEqual("% OS interface API failed: DHCP backend failed", outcome.message)

    def test_ethernet_dhcp_backend_dispatches_to_windows_api(self):
        interface = fake_interfaces()[0]

        with patch(
            "src.DPlane.ip_config.DPlane_set_dhcp",
            return_value=IP_DhcpClientResult(
                ok=True,
                message="% DHCP client enabled; lease renewal pending",
            ),
        ) as api:
            result = DPlane_DhcpClientProvider(system="Windows").IP_enable_dhcp(interface)

        self.assertTrue(result.ok)
        self.assertIn("lease renewal pending", result.message)
        api.assert_called_once_with(interface, True, "windows")

        with patch("src.DPlane.ip_config.DPlane_set_dhcp") as api:
            result = DPlane_DhcpClientProvider(system="Windows").IP_disable_dhcp(interface)

        self.assertTrue(result.ok)
        api.assert_called_once_with(interface, False, "windows")

    def test_ethernet_dhcp_backend_reports_unsupported_linux(self):
        result = DPlane_DhcpClientProvider(system="Linux").IP_enable_dhcp(fake_interfaces()[0])

        self.assertFalse(result.ok)
        self.assertIn("unsupported OS API backend for DHCP client: linux", result.message)

    def test_windows_dhcp_updates_msft_netipinterface_with_put(self):
        from src.DPlane.Windows.interface_windows import _set_msft_netipinterface_dhcp

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
        from src.DPlane.Windows.interface_windows import _call_wmi_instance_method

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
        from src.DPlane.Windows.interface_windows import _call_wmi_instance_method

        class FakeAdapterConfiguration:
            EnableDHCP = 0

        result = _call_wmi_instance_method(FakeAdapterConfiguration(), "EnableDHCP")

        self.assertEqual(0, result)


class StaticIpv4CommandTests(unittest.TestCase):
    def test_static_ipv4_commands_are_interface_and_host_interface_only(self):
        registry = build_default_registry(ifnet_provider=FakeInterfaceProvider(fake_interfaces()))
        parser = CommandParser(registry)

        self.assertTrue(parser.parse("ip address 192.0.2.10 24", mode="interface").executable)
        self.assertTrue(parser.parse("ip address 192.0.2.10 24", mode="host-interface").executable)
        self.assertTrue(
            parser.parse("ip address 192.0.2.11 255.255.255.0 sub", mode="interface").executable
        )
        self.assertTrue(
            parser.parse("ip address 192.0.2.11 255.255.255.0 sub", mode="host-interface").executable
        )
        self.assertTrue(parser.parse("no ip address", mode="interface").executable)
        self.assertTrue(parser.parse("no ip address", mode="host-interface").executable)
        self.assertTrue(
            parser.parse("no ip address 192.0.2.10 255.255.255.0", mode="interface").executable
        )
        self.assertTrue(
            parser.parse("no ip address 192.0.2.10 255.255.255.0", mode="host-interface").executable
        )
        self.assertEqual(
            ParseStatus.INVALID,
            parser.parse("ip address 192.0.2.10 24", mode="config").status,
        )

    def test_parse_static_ipv4_accepts_mask_length_and_dotted_mask(self):
        primary = IP_parse_static_ipv4_address("1.1.1.1", "8")
        secondary = IP_parse_static_ipv4_address("10.0.0.10", "255.255.255.0", secondary=True)

        self.assertEqual(8, primary.prefix_length)
        self.assertEqual("255.0.0.0", primary.subnet_mask)
        self.assertFalse(primary.secondary)
        self.assertEqual(24, secondary.prefix_length)
        self.assertTrue(secondary.secondary)

    def test_parse_static_ipv4_rejects_non_contiguous_mask(self):
        with self.assertRaises(IP_StaticIpv4ValidationError):
            IP_parse_static_ipv4_address("192.0.2.10", "255.252.0.255")

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
                with self.assertRaises(IP_StaticIpv4ValidationError):
                    IP_parse_static_ipv4_address(address, mask)

    def test_parse_static_ipv4_accepts_31_and_32_host_prefixes(self):
        self.assertEqual(31, IP_parse_static_ipv4_address("1.1.1.0", "31").prefix_length)
        self.assertEqual(32, IP_parse_static_ipv4_address("1.1.1.1", "32").prefix_length)

    def test_parse_ipv4_mask_rejects_bad_lengths_and_formats(self):
        for mask in ("33", "-1", "255.0.255.0", "255.255.255.256", "255.025.0.0"):
            with self.subTest(mask=mask):
                with self.assertRaises(IP_StaticIpv4ValidationError):
                    IP_parse_ipv4_mask(mask)

    def test_host_ip_address_static_calls_provider(self):
        ifnet_provider = FakeInterfaceProvider(fake_interfaces())
        static_provider = FakeStaticIpv4Provider()
        registry = build_default_registry(
            ifnet_provider=ifnet_provider,
            ip_static_ipv4_provider=static_provider,
        )
        ctx = CliContext(output=io.StringIO())
        ctx.push_mode("host-interface", "eth3")

        outcome = dispatch_line(ctx, registry, "ip address 1.1.1.1 8")

        self.assertTrue(outcome.executed)
        self.assertEqual(1, len(static_provider.calls))
        action, interface_name, address = static_provider.calls[0]
        self.assertEqual("set static ipv4", action)
        self.assertEqual("eth3", interface_name)
        self.assertEqual(IP_StaticIpv4Address("1.1.1.1", 8), address)

    def test_vvrp_ip_address_static_updates_interface_state_without_provider(self):
        ifnet_provider = FakeInterfaceProvider(fake_interfaces())
        static_provider = FakeStaticIpv4Provider()
        registry = build_default_registry(
            ifnet_provider=ifnet_provider,
            ip_static_ipv4_provider=static_provider,
        )
        output = io.StringIO()
        ctx = CliContext(output=output)
        registry.initialize_context(ctx)
        ETHERNET_stage_device_install(ctx.state, "eth3")
        ETHERNET_commit_device_changes(ctx.state)
        ctx.push_mode("interface", "eth3")

        outcome = dispatch_line(ctx, registry, "ip address 1.1.1.1 8")

        self.assertTrue(outcome.executed)
        self.assertEqual([], static_provider.calls)
        self.assertEqual(
            "interface eth3\n ip address 1.1.1.1 8\n quit\n",
            render_running_configuration(ctx),
        )

        output.truncate(0)
        output.seek(0)
        self.assertTrue(dispatch_line(ctx, registry, "show interfaces eth3").executed)
        self.assertIn("Internet Address is 1.1.1.1/8 Primary", output.getvalue())

    def test_host_ip_address_static_sub_calls_provider_with_secondary_flag(self):
        static_provider = FakeStaticIpv4Provider()
        registry = build_default_registry(
            ifnet_provider=FakeInterfaceProvider(fake_interfaces()),
            ip_static_ipv4_provider=static_provider,
        )
        ctx = CliContext(output=io.StringIO())
        ctx.push_mode("host-interface", "eth3")

        outcome = dispatch_line(ctx, registry, "ip address 1.1.1.2 255.0.0.0 sub")

        self.assertTrue(outcome.executed)
        _, _, address = static_provider.calls[0]
        self.assertEqual(IP_StaticIpv4Address("1.1.1.2", 8, secondary=True), address)

    def test_host_no_ip_address_without_arguments_removes_all_static_ipv4(self):
        static_provider = FakeStaticIpv4Provider()
        registry = build_default_registry(
            ifnet_provider=FakeInterfaceProvider(fake_interfaces()),
            ip_static_ipv4_provider=static_provider,
        )
        ctx = CliContext(output=io.StringIO())
        ctx.push_mode("host-interface", "eth3")

        outcome = dispatch_line(ctx, registry, "no ip address")

        self.assertTrue(outcome.executed)
        self.assertEqual([("remove static ipv4", "eth3", None)], static_provider.calls)

    def test_host_no_ip_address_with_arguments_removes_one_static_ipv4(self):
        static_provider = FakeStaticIpv4Provider()
        registry = build_default_registry(
            ifnet_provider=FakeInterfaceProvider(fake_interfaces()),
            ip_static_ipv4_provider=static_provider,
        )
        ctx = CliContext(output=io.StringIO())
        ctx.push_mode("host-interface", "eth3")

        outcome = dispatch_line(ctx, registry, "no ip address 1.1.1.2 255.0.0.0 sub")

        self.assertTrue(outcome.executed)
        self.assertEqual(
            [("remove static ipv4", "eth3", IP_StaticIpv4Address("1.1.1.2", 8, secondary=True))],
            static_provider.calls,
        )

    def test_host_static_ipv4_rejects_loopback_non_host_mask(self):
        static_provider = FakeStaticIpv4Provider()
        registry = build_default_registry(
            ifnet_provider=FakeInterfaceProvider(fake_interfaces()),
            ip_static_ipv4_provider=static_provider,
        )
        ctx = CliContext(output=io.StringIO())
        ctx.push_mode("host-interface", "loopback_0")

        outcome = dispatch_line(ctx, registry, "ip address 1.1.1.1 8")

        self.assertTrue(outcome.executed)
        self.assertEqual(
            "% Invalid IPv4 mask length: Loopback interfaces support only /32",
            outcome.message,
        )
        self.assertEqual([], static_provider.calls)

    def test_host_static_ipv4_accepts_loopback_host_address(self):
        static_provider = FakeStaticIpv4Provider()
        registry = build_default_registry(
            ifnet_provider=FakeInterfaceProvider(fake_interfaces()),
            ip_static_ipv4_provider=static_provider,
        )
        ctx = CliContext(output=io.StringIO())
        ctx.push_mode("host-interface", "loopback_0")

        outcome = dispatch_line(ctx, registry, "ip address 10.10.10.1 32")

        self.assertTrue(outcome.executed)
        self.assertEqual(
            [("set static ipv4", "loopback_0", IP_StaticIpv4Address("10.10.10.1", 32))],
            static_provider.calls,
        )

    def test_host_static_ipv4_rejects_ethernet_host_mask(self):
        static_provider = FakeStaticIpv4Provider()
        registry = build_default_registry(
            ifnet_provider=FakeInterfaceProvider(fake_interfaces()),
            ip_static_ipv4_provider=static_provider,
        )
        ctx = CliContext(output=io.StringIO())
        ctx.push_mode("host-interface", "eth3")

        outcome = dispatch_line(ctx, registry, "ip address 10.10.10.1 32")

        self.assertTrue(outcome.executed)
        self.assertEqual(
            "% Invalid IPv4 mask length: /32 is supported only on Loopback interfaces",
            outcome.message,
        )
        self.assertEqual([], static_provider.calls)

    def test_static_ipv4_primary_replaces_previous_primary_config_slot(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "saved-configuration"
            static_provider = FakeStaticIpv4Provider()
            registry = build_default_registry(
                ifnet_provider=FakeInterfaceProvider(fake_interfaces()),
                ip_static_ipv4_provider=static_provider,
                enable_host_interface_config=True,
            )
            ctx = CliContext(output=io.StringIO())
            set_saved_configuration_path(ctx, config_path)
            ctx.push_mode("host-interface", "eth3")

            self.assertTrue(dispatch_line(ctx, registry, "ip address 10.1.1.1 24").executed)
            self.assertTrue(dispatch_line(ctx, registry, "ip address 10.1.2.1 24").executed)

            self.assertFalse(config_path.exists())
            self.assertEqual(
                "host interface eth3\n ip address 10.1.2.1 24\n quit\n",
                render_running_configuration(ctx),
            )
            self.assertTrue(dispatch_line(ctx, registry, "save").executed)
            self.assertEqual(
                "host interface eth3\n ip address 10.1.2.1 24\n quit\n",
                config_path.read_text(encoding="utf-8"),
            )

    def test_static_ipv4_rejects_cross_interface_duplicate_and_overlap(self):
        eth3 = with_ipv4(fake_ethernet("eth3", index=2), "10.1.1.1", 24)
        eth4 = fake_ethernet_without_ipv4("eth4", index=4)
        interfaces = (eth3, eth4)

        with self.assertRaisesRegex(IP_StaticIpv4ValidationError, "duplicate address"):
            IP_validate_static_ipv4_address_for_interface(
                IP_StaticIpv4Address("10.1.1.1", 24),
                eth4,
                interfaces,
            )

        with self.assertRaisesRegex(IP_StaticIpv4ValidationError, "subnet overlaps"):
            IP_validate_static_ipv4_address_for_interface(
                IP_StaticIpv4Address("10.1.1.2", 25),
                eth4,
                interfaces,
            )

    def test_static_ipv4_rejects_cross_interface_broadcast_conflicts(self):
        eth3 = with_ipv4(fake_ethernet("eth3", index=2), "10.1.1.1", 24)
        eth4 = fake_ethernet_without_ipv4("eth4", index=4)
        interfaces = (eth3, eth4)

        with self.assertRaisesRegex(IP_StaticIpv4ValidationError, "broadcast address"):
            IP_validate_static_ipv4_address_for_interface(
                IP_StaticIpv4Address("10.1.1.255", 25),
                eth4,
                interfaces,
            )

        with self.assertRaisesRegex(IP_StaticIpv4ValidationError, "broadcast address"):
            IP_validate_static_ipv4_address_for_interface(
                IP_StaticIpv4Address("10.1.1.128", 25),
                eth4,
                interfaces,
            )

    def test_no_ip_address_primary_rejects_when_secondary_exists(self):
        static_provider = FakeStaticIpv4Provider()
        registry = build_default_registry(
            ifnet_provider=FakeInterfaceProvider(
                (
                    replace(
                        fake_ethernet("eth3"),
                        addresses=(
                            InterfaceAddress(family="ipv4", address="10.1.1.1", prefix_length=24),
                            InterfaceAddress(family="ipv4", address="10.1.2.1", prefix_length=24),
                        ),
                    ),
                )
            ),
            ip_static_ipv4_provider=static_provider,
        )
        ctx = CliContext(output=io.StringIO())
        ctx.push_mode("host-interface", "eth3")

        outcome = dispatch_line(ctx, registry, "no ip address 10.1.1.1 24")

        self.assertTrue(outcome.executed)
        self.assertEqual(
            "% Please delete all secondary IPv4 addresses before deleting the primary address",
            outcome.message,
        )
        self.assertEqual([], static_provider.calls)

    def test_static_ipv4_provider_failure_is_reported(self):
        static_provider = FakeStaticIpv4Provider()
        static_provider.fail_next = IP_StaticIpv4Result(
            ok=False,
            message="% OS interface API failed: static backend failed",
        )
        registry = build_default_registry(
            ifnet_provider=FakeInterfaceProvider(fake_interfaces()),
            ip_static_ipv4_provider=static_provider,
        )
        ctx = CliContext(output=io.StringIO())
        ctx.push_mode("host-interface", "eth3")

        outcome = dispatch_line(ctx, registry, "ip address 1.1.1.1 8")

        self.assertTrue(outcome.executed)
        self.assertEqual("% OS interface API failed: static backend failed", outcome.message)

    def test_ethernet_static_backend_dispatches_to_windows_api(self):
        interface = fake_interfaces()[0]
        address = IP_StaticIpv4Address("1.1.1.1", 8)

        with patch("src.DPlane.ip_config.DPlane_set_static_ipv4") as api:
            result = DPlane_StaticIpv4Provider(system="Windows").IP_set_static_ipv4(
                interface,
                address,
            )

        self.assertTrue(result.ok)
        api.assert_called_once_with(interface, address, "windows")

        with patch("src.DPlane.ip_config.DPlane_remove_static_ipv4") as api:
            result = DPlane_StaticIpv4Provider(system="Windows").IP_remove_static_ipv4(
                interface,
                address,
            )

        self.assertTrue(result.ok)
        api.assert_called_once_with(interface, address, "windows")

    def test_ethernet_static_backend_reports_unsupported_linux(self):
        result = DPlane_StaticIpv4Provider(system="Linux").IP_set_static_ipv4(
            fake_interfaces()[0],
            IP_StaticIpv4Address("1.1.1.1", 8),
        )

        self.assertFalse(result.ok)
        self.assertIn("unsupported OS API backend for static IPv4: linux", result.message)

    def test_loopback_static_backend_dispatches_to_windows_api(self):
        interface = fake_interfaces()[1]
        address = IP_StaticIpv4Address("10.10.10.1", 32)

        with patch("src.DPlane.ip_config.DPlane_set_static_ipv4") as api:
            result = DPlane_StaticIpv4Provider(system="Windows").IP_set_static_ipv4(
                interface,
                address,
            )

        self.assertTrue(result.ok)
        api.assert_called_once_with(interface, address, "windows")

        with patch("src.DPlane.ip_config.DPlane_remove_static_ipv4") as api:
            result = DPlane_StaticIpv4Provider(system="Windows").IP_remove_static_ipv4(
                interface,
                address,
            )

        self.assertTrue(result.ok)
        api.assert_called_once_with(interface, address, "windows")

    def test_windows_static_ipv4_class_method_helper_passes_inputs(self):
        from src.DPlane.Windows.interface_windows import _call_wmi_class_method

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

    def test_windows_static_ipv4_builds_unicast_iphelper_row(self):
        from src.DPlane.Windows.interface_windows import AF_INET, _unicast_ipv4_row

        row = _unicast_ipv4_row(fake_ethernet("eth3"), IP_StaticIpv4Address("1.1.1.1", 24))

        self.assertEqual(AF_INET, row.Address.Ipv4.sin_family)
        self.assertEqual([1, 1, 1, 1], list(row.Address.Ipv4.sin_addr.S_un_b))
        self.assertEqual(2, row.InterfaceIndex)
        self.assertEqual(24, row.OnLinkPrefixLength)

    def test_windows_static_ipv4_uses_iphelper_create(self):
        from src.DPlane.Windows.interface_windows import _create_unicast_ipv4_address

        class FakeIphlpapi:
            def InitializeUnicastIpAddressEntry(self, row):
                return None

            def CreateUnicastIpAddressEntry(self, row):
                self.row = row._obj
                return 0

        iphlpapi = FakeIphlpapi()
        interface = fake_ethernet("eth3")

        with patch("src.DPlane.Windows.interface_windows._iphlpapi", return_value=iphlpapi):
            _create_unicast_ipv4_address(interface, IP_StaticIpv4Address("1.1.1.1", 24))

        self.assertEqual([1, 1, 1, 1], list(iphlpapi.row.Address.Ipv4.sin_addr.S_un_b))
        self.assertEqual(24, iphlpapi.row.OnLinkPrefixLength)

    def test_windows_adapter_configuration_queries_use_interface_index(self):
        from src.DPlane.Windows.interface_windows import _wmi_adapter_configuration_queries

        interface = fake_ethernet("eth3")

        queries = _wmi_adapter_configuration_queries(interface)

        self.assertIn("WHERE InterfaceIndex = 2", queries[0])

    def test_windows_secondary_static_ipv4_uses_iphelper_create(self):
        from src.DPlane.Windows.interface_windows import set_windows_static_ipv4

        class FakeIphlpapi:
            def InitializeUnicastIpAddressEntry(self, row):
                return None

            def CreateUnicastIpAddressEntry(self, row):
                self.row = row._obj
                return 0

        interface = fake_ethernet("eth3")
        address = IP_StaticIpv4Address("1.1.1.2", 24, secondary=True)
        iphlpapi = FakeIphlpapi()

        with (
            patch(
                "src.DPlane.Windows.interface_windows._wmi_ipv4_interface_for_interface",
                return_value=(object(), object()),
            ),
            patch("src.DPlane.Windows.interface_windows._set_msft_netipinterface_dhcp"),
            patch(
                "src.DPlane.Windows.interface_windows._wmi_manual_ipv4_addresses",
                return_value=(),
            ),
            patch("src.DPlane.Windows.interface_windows._wmi_service", return_value=object()),
            patch("src.DPlane.Windows.interface_windows._iphlpapi", return_value=iphlpapi),
        ):
            set_windows_static_ipv4(interface, address)

        self.assertEqual([1, 1, 1, 2], list(iphlpapi.row.Address.Ipv4.sin_addr.S_un_b))
        self.assertEqual(24, iphlpapi.row.OnLinkPrefixLength)

    def test_windows_static_ipv4_delete_helper_accepts_eager_return_value(self):
        from src.DPlane.Windows.interface_windows import _delete_wmi_instance

        class FakeAddress:
            Delete_ = 0

        _delete_wmi_instance(FakeAddress(), "MSFT_NetIPAddress.Delete_")

    def test_windows_static_ipv4_manual_match_helpers(self):
        from src.DPlane.Windows.interface_windows import (
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
        self.assertTrue(_wmi_ipv4_address_matches(row, IP_StaticIpv4Address("1.1.1.1", 8)))
        self.assertFalse(_wmi_ipv4_address_matches(row, IP_StaticIpv4Address("1.1.1.2", 8)))


class ConfigurationTests(unittest.TestCase):
    def test_reboot_command_stops_runtime_and_reexecs_process_from_any_mode(self):
        registry = build_default_registry()
        output = io.StringIO()
        ctx = CliContext(output=output)
        ctx.push_mode("hidden")
        ctx.push_mode("interface", "NULL0")

        with patch("src.CCmd.examples.CCMD_process_reboot") as reboot:
            outcome = dispatch_line(ctx, registry, "reboot")

        self.assertTrue(outcome.executed)
        self.assertFalse(ctx.exit_requested)
        reboot.assert_called_once_with()
        self.assertIn("System is rebooting...", output.getvalue())
        self.assertIn("Stopping services...", output.getvalue())
        self.assertIn("Restarting VVRP process...", output.getvalue())

    def test_process_reboot_execs_current_python_with_vvrp_module(self):
        from src.CCmd.process_reboot import CCMD_process_reboot

        with patch.dict(os.environ, {"VVRP_REBOOT_MODULE": "VVRP"}):
            with patch("src.CCmd.process_reboot.os.name", "posix"):
                with patch("src.CCmd.process_reboot.os.execv") as execv:
                    CCMD_process_reboot()

        self.assertEqual(sys.executable, execv.call_args.args[0])
        self.assertEqual([sys.executable, "-m", "VVRP"], execv.call_args.args[1])

    def test_process_reboot_waits_for_child_process_on_windows(self):
        from src.CCmd.process_reboot import CCMD_process_reboot

        with patch.dict(os.environ, {"VVRP_REBOOT_MODULE": "VVRP"}):
            with patch("src.CCmd.process_reboot.os.name", "nt"):
                with patch("src.CCmd.process_reboot.subprocess.call", return_value=7) as call:
                    with patch("src.CCmd.process_reboot.os._exit", side_effect=SystemExit) as exit_:
                        with self.assertRaises(SystemExit):
                            CCMD_process_reboot()

        call.assert_called_once_with([sys.executable, "-m", "VVRP"])
        exit_.assert_called_once_with(7)

    def test_reload_command_requests_context_reload_from_any_mode(self):
        registry = build_default_registry()
        ctx = CliContext(output=io.StringIO())
        ctx.push_mode("hidden")
        ctx.push_mode("interface", "NULL0")

        outcome = dispatch_line(ctx, registry, "reload")

        self.assertTrue(outcome.executed)
        self.assertTrue(ctx.reload_requested)
        self.assertFalse(ctx.exit_requested)

    def test_reload_context_returns_to_user_mode_and_loads_saved_configuration(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "saved-configuration"
            config_path.write_text("hostname R9\n", encoding="utf-8")
            registry = build_default_registry()
            output = io.StringIO()
            old_ctx = CliContext(hostname="Router", output=output)
            old_ctx.push_mode("hidden")

            new_ctx = _reload_context(
                registry,
                hostname="Router",
                output=old_ctx.output,
                saved_configuration_file=config_path,
            )

            self.assertEqual("user", new_ctx.mode)
            self.assertEqual("R9", new_ctx.hostname)
            self.assertFalse(new_ctx.reload_requested)
            self.assertTrue(output.getvalue().startswith("System is reloading...\n"))
            self.assertIn("Reload complete.", output.getvalue())

    def test_default_saved_configuration_path_is_runtime_root_relative(self):
        original_cwd = Path.cwd()
        try:
            os.chdir(Path.cwd() / "src")
            ctx = CliContext(output=io.StringIO())

            config_path = set_saved_configuration_path(ctx)

            self.assertEqual(default_saved_configuration_path(), config_path)
            self.assertEqual("saved-configuration", config_path.name)
            self.assertEqual(default_runtime_directory(), config_path.parent)
        finally:
            os.chdir(original_cwd)

    def test_runtime_directory_can_be_configured_by_environment(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.dict(os.environ, {"VVRP_RUNTIME_DIR": temp_dir}):
                ctx = CliContext(output=io.StringIO())

                config_path = set_saved_configuration_path(ctx)

                self.assertEqual(Path(temp_dir) / "saved-configuration", config_path)
                self.assertEqual(Path(temp_dir), default_runtime_directory())

    def test_hostname_command_updates_running_config_and_save_writes_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "saved-configuration"
            registry = build_default_registry()
            ctx = CliContext(output=io.StringIO())
            set_saved_configuration_path(ctx, config_path)
            ctx.push_mode("privileged")
            ctx.push_mode("config")

            outcome = dispatch_line(ctx, registry, "hostname R9")

            self.assertTrue(outcome.executed)
            self.assertFalse(config_path.exists())
            self.assertEqual("hostname R9\n", render_running_configuration(ctx))
            self.assertTrue(dispatch_line(ctx, registry, "save").executed)
            self.assertEqual("hostname R9\n", config_path.read_text(encoding="utf-8"))

    def test_running_and_saved_configuration_diverge_until_save(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "saved-configuration"
            registry = build_default_registry()
            output = io.StringIO()
            ctx = CliContext(output=output)
            set_saved_configuration_path(ctx, config_path)
            ctx.push_mode("privileged")
            ctx.push_mode("config")

            self.assertTrue(dispatch_line(ctx, registry, "hostname R9").executed)

            output.truncate(0)
            output.seek(0)
            self.assertTrue(dispatch_line(ctx, registry, "show running-configuration").executed)
            self.assertEqual("hostname R9\n", output.getvalue())

            output.truncate(0)
            output.seek(0)
            self.assertTrue(dispatch_line(ctx, registry, "show saved-configuration").executed)
            self.assertEqual("", output.getvalue())

            self.assertTrue(dispatch_line(ctx, registry, "save").executed)

            output.truncate(0)
            output.seek(0)
            self.assertTrue(dispatch_line(ctx, registry, "show saved-configuration").executed)
            self.assertEqual("hostname R9\n", output.getvalue())

    def test_show_configuration_commands_are_available_in_user_mode(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "saved-configuration"
            config_path.write_text("hostname R9\n", encoding="utf-8")
            registry = build_default_registry()
            output = io.StringIO()
            ctx = CliContext(output=output)
            set_saved_configuration_path(ctx, config_path)
            registry.initialize_context(ctx)

            self.assertTrue(dispatch_line(ctx, registry, "show saved-configuration").executed)
            self.assertEqual("hostname R9\n", output.getvalue())

            output.truncate(0)
            output.seek(0)
            self.assertTrue(dispatch_line(ctx, registry, "show running-configuration").executed)
            self.assertEqual("", output.getvalue())

    def test_interface_static_ipv4_updates_running_config_and_save_writes_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "saved-configuration"
            registry = build_default_registry(
                ifnet_provider=FakeInterfaceProvider(fake_interfaces()),
                ip_static_ipv4_provider=FakeStaticIpv4Provider(),
                enable_host_interface_config=True,
            )
            ctx = CliContext(output=io.StringIO())
            set_saved_configuration_path(ctx, config_path)
            ctx.push_mode("privileged")
            ctx.push_mode("config")
            ctx.push_mode("hidden")

            self.assertTrue(dispatch_line(ctx, registry, "host interface eth3").executed)
            self.assertTrue(dispatch_line(ctx, registry, "ip address 1.1.1.1 8").executed)

            self.assertFalse(config_path.exists())
            self.assertEqual(
                "host interface eth3\n ip address 1.1.1.1 8\n quit\n",
                render_running_configuration(ctx),
            )

            self.assertTrue(dispatch_line(ctx, registry, "save").executed)
            self.assertEqual(
                "host interface eth3\n ip address 1.1.1.1 8\n quit\n",
                config_path.read_text(encoding="utf-8"),
            )

    def test_no_ip_address_updates_running_config_and_save_writes_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "saved-configuration"
            registry = build_default_registry(
                ifnet_provider=FakeInterfaceProvider(fake_interfaces()),
                ip_static_ipv4_provider=FakeStaticIpv4Provider(),
                enable_host_interface_config=True,
            )
            ctx = CliContext(output=io.StringIO())
            set_saved_configuration_path(ctx, config_path)
            ctx.push_mode("privileged")
            ctx.push_mode("config")
            ctx.push_mode("hidden")
            dispatch_line(ctx, registry, "host interface eth3")
            dispatch_line(ctx, registry, "ip address 1.1.1.1 8")
            dispatch_line(ctx, registry, "ip address 1.1.1.2 8 sub")

            self.assertTrue(dispatch_line(ctx, registry, "no ip address 1.1.1.2 8 sub").executed)

            self.assertEqual(
                "host interface eth3\n ip address 1.1.1.1 8\n quit\n",
                render_running_configuration(ctx),
            )
            self.assertFalse(config_path.exists())

            self.assertTrue(dispatch_line(ctx, registry, "no ip address").executed)
            self.assertEqual("", render_running_configuration(ctx))
            self.assertTrue(dispatch_line(ctx, registry, "save").executed)
            self.assertEqual("", config_path.read_text(encoding="utf-8"))

    def test_host_dhcp_updates_running_config_and_save_writes_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "saved-configuration"
            registry = build_default_registry(
                ifnet_provider=FakeInterfaceProvider(fake_interfaces()),
                ip_dhcp_provider=FakeDhcpProvider(),
                ip_static_ipv4_provider=FakeStaticIpv4Provider(),
            )
            ctx = CliContext(output=io.StringIO())
            set_saved_configuration_path(ctx, config_path)
            ctx.push_mode("privileged")
            ctx.push_mode("config")
            ctx.push_mode("hidden")
            dispatch_line(ctx, registry, "host interface eth3")
            dispatch_line(ctx, registry, "ip address 1.1.1.1 8")

            self.assertTrue(dispatch_line(ctx, registry, "ip address dhcp-alloc").executed)

            self.assertEqual(
                "host interface eth3\n ip address dhcp-alloc\n quit\n",
                render_running_configuration(ctx),
            )
            self.assertFalse(config_path.exists())

            self.assertTrue(dispatch_line(ctx, registry, "no ip address dhcp-alloc").executed)
            self.assertEqual("", render_running_configuration(ctx))
            self.assertTrue(dispatch_line(ctx, registry, "save").executed)
            self.assertEqual("", config_path.read_text(encoding="utf-8"))

    def test_load_saved_configuration_executes_commands_and_restores_mode(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "saved-configuration"
            config_path.write_text(
                "\n".join(
                    (
                        "hostname R9",
                        "host interface eth3",
                        " ip address 1.1.1.1 8",
                        " ip address 1.1.1.2 8 sub",
                        " quit",
                        "",
                    )
                ),
                encoding="utf-8",
            )
            static_provider = FakeStaticIpv4Provider()
            registry = build_default_registry(
                ifnet_provider=FakeInterfaceProvider(fake_interfaces()),
                ip_static_ipv4_provider=static_provider,
                enable_host_interface_config=True,
            )
            ctx = CliContext(output=io.StringIO())
            registry.initialize_context(ctx)

            errors = load_saved_configuration(ctx, registry, config_path)

            self.assertEqual([], errors)
            self.assertEqual("R9", ctx.hostname)
            self.assertEqual("user", ctx.mode)
            self.assertEqual(
                [
                    ("set static ipv4", "eth3", IP_StaticIpv4Address("1.1.1.1", 8)),
                    ("set static ipv4", "eth3", IP_StaticIpv4Address("1.1.1.2", 8, secondary=True)),
                ],
                static_provider.calls,
            )
            self.assertEqual(
                "hostname R9\n"
                "host interface eth3\n"
                " ip address 1.1.1.1 8\n"
                " ip address 1.1.1.2 8 sub\n"
                " quit\n",
                render_running_configuration(ctx),
            )

    def test_load_saved_vvrp_interface_ipv4_restores_state_without_host_provider(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "saved-configuration"
            config_path.write_text(
                "\n".join(
                    (
                        "host interface eth3",
                        " import",
                        " quit",
                        "interface eth3",
                        " ip address 1.1.1.1 8",
                        " quit",
                        "",
                    )
                ),
                encoding="utf-8",
            )
            static_provider = FakeStaticIpv4Provider()
            registry = build_default_registry(
                ifnet_provider=FakeInterfaceProvider(fake_interfaces()),
                ip_static_ipv4_provider=static_provider,
                dplane_backend=FakeDPlaneBackend(
                    (
                        NpcapDevice(
                            name=r"\Device\NPF_{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}",
                            description="eth3",
                        ),
                    )
                ),
            )
            output = io.StringIO()
            ctx = CliContext(output=output)
            registry.initialize_context(ctx)

            errors = load_saved_configuration(ctx, registry, config_path)

            self.assertEqual([], errors)
            self.assertEqual([], static_provider.calls)
            self.assertEqual(
                "host interface eth3\n"
                " import\n"
                " quit\n"
                "interface eth3\n"
                " ip address 1.1.1.1 8\n"
                " quit\n",
                render_running_configuration(ctx),
            )

            ctx.push_mode("privileged")
            self.assertTrue(dispatch_line(ctx, registry, "show interfaces eth3").executed)
            self.assertIn("Internet Address is 1.1.1.1/8 Primary", output.getvalue())

    def test_load_saved_vvrp_interface_mtu_restores_state(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "saved-configuration"
            config_path.write_text(
                "\n".join(
                    (
                        "host interface eth3",
                        " import",
                        " quit",
                        "interface eth3",
                        " mtu 1600",
                        " quit",
                        "",
                    )
                ),
                encoding="utf-8",
            )
            registry = build_default_registry(
                ifnet_provider=FakeInterfaceProvider(fake_interfaces()),
                dplane_backend=FakeDPlaneBackend(
                    (
                        NpcapDevice(
                            name=r"\Device\NPF_{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}",
                            description="eth3",
                        ),
                    )
                ),
            )
            output = io.StringIO()
            ctx = CliContext(output=output)
            registry.initialize_context(ctx)

            errors = load_saved_configuration(ctx, registry, config_path)

            self.assertEqual([], errors)
            self.assertEqual(
                "host interface eth3\n"
                " import\n"
                " quit\n"
                "interface eth3\n"
                " mtu 1600\n"
                " quit\n",
                render_running_configuration(ctx),
            )

            ctx.push_mode("privileged")
            self.assertTrue(dispatch_line(ctx, registry, "show interfaces eth3").executed)
            self.assertIn("Route Port,The Maximum Transmit Unit is 1600", output.getvalue())

    def test_load_saved_configuration_skips_children_after_missing_interface(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "saved-configuration"
            config_path.write_text(
                "\n".join(
                    (
                        "interface loopback_0",
                        " ip address 10.10.10.1 32",
                        " quit",
                        "",
                    )
                ),
                encoding="utf-8",
            )
            static_provider = FakeStaticIpv4Provider()
            output = io.StringIO()
            registry = build_default_registry(
                ifnet_provider=FakeInterfaceProvider((fake_ethernet("eth3"),)),
                ip_static_ipv4_provider=static_provider,
                enable_host_interface_config=True,
            )
            ctx = CliContext(output=output)
            registry.initialize_context(ctx)

            errors = load_saved_configuration(ctx, registry, config_path)

            self.assertEqual(
                [f"{config_path}:1: % Invalid input: interface loopback_0"],
                errors,
            )
            self.assertEqual("", output.getvalue())
            self.assertEqual([], static_provider.calls)
            self.assertEqual("user", ctx.mode)


class PingTests(unittest.TestCase):
    def test_ping_target_classification_accepts_ip_and_names(self):
        self.assertEqual("ipv4", ICMP_classify_ping_target("192.168.1.1"))
        self.assertEqual("ipv6", ICMP_classify_ping_target("2001:db8::1"))
        self.assertEqual("ipv6", ICMP_classify_ping_target("::1"))
        self.assertEqual("hostname", ICMP_classify_ping_target("router"))
        self.assertEqual("hostname", ICMP_classify_ping_target("example.com"))

    def test_ping_target_classification_rejects_options_and_bad_names(self):
        with self.assertRaises(ValueError):
            ICMP_classify_ping_target("-n")
        with self.assertRaises(ValueError):
            ICMP_classify_ping_target("bad_name")

    def test_ping_argument_parser_accepts_huawei_style_options(self):
        self.assertEqual(
            ICMP_PingOptions(
                ICMP_target="192.0.2.10",
                ICMP_count=8,
                ICMP_packet_size=300,
                ICMP_timeout_seconds=3,
                ICMP_interval_seconds=0,
                ICMP_ttl=64,
                ICMP_brief=True,
            ),
            ICMP_parse_ping_arguments("ip -c 8 -s 300 -t 3 -m 0 -h 64 -brief 192.0.2.10"),
        )

    def test_ping_argument_parser_rejects_unsupported_source_address(self):
        with self.assertRaisesRegex(ValueError, "not supported"):
            ICMP_parse_ping_arguments("-a 1.1.1.1 192.0.2.10")

    def test_ping_packet_builder_creates_icmp_echo_request(self):
        packet = ICMP_build_echo_packet(0x1234, 7, b"abcd")

        self.assertEqual(12, len(packet))
        self.assertEqual(8, packet[0])
        self.assertEqual(0, packet[1])
        self.assertNotEqual(0, int.from_bytes(packet[2:4], "big"))
        self.assertEqual(0x1234, int.from_bytes(packet[4:6], "big"))
        self.assertEqual(7, int.from_bytes(packet[6:8], "big"))
        self.assertEqual(b"abcd", packet[8:])

    def test_ping_reply_and_statistics_format_match_vrp_style(self):
        self.assertEqual(
            "    Reply from 192.0.2.10: bytes=56 Sequence=2 ttl=255 time=3 ms",
            ICMP_format_ping_reply(
                ICMP_PingReply(
                    ICMP_ok=True,
                    ICMP_sequence=2,
                    ICMP_address="192.0.2.10",
                    ICMP_bytes_received=56,
                    ICMP_ttl=255,
                    ICMP_rtt_ms=3,
                )
            ),
        )
        self.assertEqual(
            ".",
            ICMP_format_ping_reply(
                ICMP_PingReply(ICMP_ok=False, ICMP_sequence=1),
                ICMP_brief=True,
            ),
        )
        self.assertIn(
            "round-trip min/avg/max = 1/2/4 ms",
            ICMP_format_ping_statistics("192.0.2.10", 3, 3, [1, 2, 4]),
        )

    def test_run_ping_streams_to_output_with_injected_pinger(self):
        class FakePinger:
            def ICMP_ping(self, options, resolved_address, output):
                output.write("    Reply from 192.0.2.10: bytes=56 Sequence=1 ttl=255 time=1 ms\n")
                output.flush()
                output.write(ICMP_format_ping_statistics(options.ICMP_target, 1, 1, [1]) + "\n")
                output.flush()
                return ICMP_PingResult(ICMP_ok=True)

        output = io.StringIO()
        with patch("src.IP.ICMP.ping.ICMP_resolve_ipv4_target", return_value="192.0.2.10"):
            result = ICMP_run_ping(
                "-c 1 192.0.2.10",
                ICMP_output=output,
                ICMP_pinger=FakePinger(),
            )

        self.assertTrue(result.ICMP_ok)
        text = output.getvalue()
        self.assertIn("PING 192.0.2.10: 56 data bytes", text)
        self.assertIn("Reply from 192.0.2.10", text)
        self.assertIn("1 packet(s) transmitted", text)

    def test_vvrp_packet_ping_waits_for_sock_fwd_without_dplane_access(self):
        ctx = CliContext(output=io.StringIO())
        ETHERNET_stage_device_install(ctx.state, "eth3")
        ETHERNET_commit_device_changes(ctx.state)
        IP_set_interface_addresses(
            ctx.state,
            "eth3",
            (InterfaceAddress(family="ipv4", address="192.0.2.10", prefix_length=24),),
        )
        set_interface_mac_address(ctx.state, "eth3", "02:00:00:00:00:01")
        provider = FakeInterfaceProvider((fake_ethernet("eth3"),))
        from src.FIB import FIB_sync_active_routes
        from src.RM import RMRoute
        from ipaddress import IPv4Network

        FIB_sync_active_routes(
            ctx.state,
            (
                RMRoute(
                    destination=IPv4Network("192.0.2.0/24"),
                    source="connected",
                    interface=replace(fake_ethernet("eth3"), mac_address="02:00:00:00:00:01"),
                    source_ip="192.0.2.10",
                ),
            ),
            (NpcapDevice(name=r"\Device\NPF_eth3", description="eth3"),),
        )
        pinger = ICMP_VvrpPacketPinger(
            ctx,
            ICMP_ifnet_provider=provider,
            ICMP_identifier=0x1234,
        )
        output = io.StringIO()

        result = ICMP_run_ping("-c 1 -m 0 192.0.2.1", ICMP_output=output, ICMP_pinger=pinger)

        self.assertFalse(result.ICMP_ok)
        self.assertIn("VVRP forwarder", output.getvalue())

    def test_vvrp_packet_ping_prints_echo_reply_from_dplane_input(self):
        from ipaddress import IPv4Network

        from src.FIB import FIB_sync_active_routes
        from src.RM import RMRoute
        from src.SOCK import SOCK_SendResult

        class ReplyingForwarder:
            def FWD_send_packet(self, SOCK_packet, SOCK_route):
                ICMP_ipv4 = ICMP_parse_ipv4_packet(SOCK_packet)
                ICMP_echo = ICMP_parse_echo(ICMP_ipv4.ICMP_payload)
                assert ICMP_echo is not None
                ICMP_record_echo_reply(
                    ctx.state,
                    ICMP_source=ICMP_ipv4.ICMP_destination,
                    ICMP_destination=ICMP_ipv4.ICMP_source,
                    ICMP_identifier=ICMP_echo.ICMP_identifier,
                    ICMP_sequence=ICMP_echo.ICMP_sequence,
                    ICMP_ttl=64,
                    ICMP_payload=ICMP_echo.ICMP_payload,
                )
                return SOCK_SendResult(SOCK_ok=True)

        ctx = CliContext(output=io.StringIO())
        ETHERNET_stage_device_install(ctx.state, "eth3")
        ETHERNET_commit_device_changes(ctx.state)
        IP_set_interface_addresses(
            ctx.state,
            "eth3",
            (InterfaceAddress(family="ipv4", address="192.0.2.10", prefix_length=24),),
        )
        set_interface_mac_address(ctx.state, "eth3", "02:00:00:00:00:01")
        provider = FakeInterfaceProvider((fake_ethernet("eth3"),))
        FIB_sync_active_routes(
            ctx.state,
            (
                RMRoute(
                    destination=IPv4Network("192.0.2.0/24"),
                    source="connected",
                    interface=replace(fake_ethernet("eth3"), mac_address="02:00:00:00:00:01"),
                    source_ip="192.0.2.10",
                ),
            ),
        )
        pinger = ICMP_VvrpPacketPinger(
            ctx,
            ICMP_ifnet_provider=provider,
            ICMP_socket_forwarder=ReplyingForwarder(),
            ICMP_identifier=0x1234,
        )
        output = io.StringIO()

        result = ICMP_run_ping("-c 1 -m 0 192.0.2.1", ICMP_output=output, ICMP_pinger=pinger)

        self.assertTrue(result.ICMP_ok)
        text = output.getvalue()
        self.assertIn("Reply from 192.0.2.1", text)
        self.assertIn("Sequence=1", text)
        self.assertIn("ttl=64", text)
        self.assertIn("1 packet(s) received", text)

    def test_ping_command_is_available_in_all_modes(self):
        registry = build_default_registry()
        parser = CommandParser(registry)

        for mode in ("user", "privileged", "config", "interface", "hidden"):
            result = parser.parse("ping example.com", mode=mode)
            self.assertTrue(result.executable, mode)

    def test_ping_dispatch_passes_arguments_and_output_to_runner(self):
        registry = build_default_registry()
        ctx = CliContext(output=io.StringIO())

        with patch(
            "src.IP.commands.ICMP_run_ping",
            return_value=ICMP_PingResult(ICMP_ok=True, ICMP_message="pong"),
        ) as run_ping_mock:
            outcome = dispatch_line(ctx, registry, "ping -c 1 192.0.2.10")

        self.assertTrue(outcome.executed)
        _, kwargs = run_ping_mock.call_args
        self.assertEqual("-c 1 192.0.2.10", run_ping_mock.call_args.args[0])
        self.assertIs(ctx.output, kwargs["ICMP_output"])
        self.assertIs(ctx, kwargs["ICMP_ctx"])
        self.assertIn("ICMP_ifnet_provider", kwargs)
        self.assertNotIn("ICMP_dplane_backend", kwargs)
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

        self.assertTrue(dispatch_line(ctx, registry, "_").executed)
        self.assertEqual("hidden", ctx.mode)
        self.assertEqual("R1(hidden)# ", ctx.prompt)

        self.assertTrue(dispatch_line(ctx, registry, "host interface eth3").executed)
        self.assertEqual("host-interface", ctx.mode)
        self.assertEqual("R1(host-if-eth3)# ", ctx.prompt)

        self.assertTrue(dispatch_line(ctx, registry, "_").executed)
        self.assertEqual("hidden", ctx.mode)
        self.assertEqual("R1(hidden)# ", ctx.prompt)

        self.assertTrue(dispatch_line(ctx, registry, "quit").executed)
        self.assertEqual("host-interface", ctx.mode)
        self.assertEqual("R1(host-if-eth3)# ", ctx.prompt)

        self.assertTrue(dispatch_line(ctx, registry, "quit").executed)
        self.assertEqual("hidden", ctx.mode)
        self.assertEqual("R1(hidden)# ", ctx.prompt)

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
        self.assertIn("interfaces", show_outcome.message)
        self.assertEqual(ParseStatus.INVALID, dispatch_line(ctx, registry, "show version").status)
        self.assertEqual(
            ParseStatus.INVALID,
            dispatch_line(ctx, registry, "show host interface eth3").status,
        )
        self.assertEqual(ParseStatus.INVALID, dispatch_line(ctx, registry, "shutdown").status)
        self.assertTrue(dispatch_line(ctx, registry, "_").executed)
        self.assertTrue(dispatch_line(ctx, registry, "host interface eth3").executed)
        self.assertTrue(CommandParser(registry).parse("import", mode=ctx.mode).executable)
        self.assertEqual(ParseStatus.INVALID, dispatch_line(ctx, registry, "shutdown").status)

    def test_unknown_interface_does_not_enter_interface_mode(self):
        registry = build_default_registry(ifnet_provider=FakeInterfaceProvider(fake_interfaces()))
        output = io.StringIO()
        ctx = CliContext(output=output)

        dispatch_line(ctx, registry, "enable")
        dispatch_line(ctx, registry, "config")
        dispatch_line(ctx, registry, "_")
        outcome = dispatch_line(ctx, registry, "host interface eth100")

        self.assertFalse(outcome.executed)
        self.assertEqual(ParseStatus.INVALID, outcome.status)
        self.assertEqual("% Invalid input", outcome.message)
        self.assertEqual("hidden", ctx.mode)
        self.assertEqual("Router(hidden)# ", ctx.prompt)
        self.assertIn("% Invalid input", output.getvalue())

    def test_interface_command_switches_interface_from_interface_mode(self):
        registry = build_default_registry(
            ifnet_provider=FakeInterfaceProvider((fake_ethernet("eth0"), fake_ethernet("eth4")))
        )
        ctx = CliContext(output=io.StringIO())

        dispatch_line(ctx, registry, "enable")
        dispatch_line(ctx, registry, "config")
        dispatch_line(ctx, registry, "_")
        self.assertTrue(dispatch_line(ctx, registry, "host interface eth4").executed)
        self.assertEqual("Router(host-if-eth4)# ", ctx.prompt)

        self.assertTrue(dispatch_line(ctx, registry, "quit").executed)
        self.assertEqual("hidden", ctx.mode)
        self.assertTrue(dispatch_line(ctx, registry, "host interface eth0").executed)

        self.assertEqual("host-interface", ctx.mode)
        self.assertEqual("eth0", ctx.mode_label)
        self.assertEqual("Router(host-if-eth0)# ", ctx.prompt)

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
        self.assertIn("ip", user_text)
        self.assertNotIn("hostname", user_text)

        output.truncate(0)
        output.seek(0)
        dispatch_line(ctx, registry, "enable")
        dispatch_line(ctx, registry, "config")
        dispatch_line(ctx, registry, "show")
        config_text = output.getvalue()
        self.assertIn("hostname", config_text)
        self.assertIn("interfaces", config_text)
        self.assertIn("ip", config_text)
        self.assertNotIn("version", config_text)

    def test_parser_filters_candidates_by_mode(self):
        registry = build_default_registry()
        parser = CommandParser(registry)

        user_result = parser.parse("s", mode="user")
        privileged_result = parser.parse("s", mode="privileged")
        config_result = parser.parse("s", mode="config")

        self.assertEqual(ParseStatus.VALID_UNIQUE, user_result.status)
        self.assertEqual("show", user_result.complete_command)
        self.assertEqual(ParseStatus.AMBIGUOUS, privileged_result.status)
        self.assertEqual(("save", "show"), privileged_result.candidates)
        self.assertEqual(ParseStatus.AMBIGUOUS, config_result.status)
        self.assertEqual(("save", "show"), config_result.candidates)


if __name__ == "__main__":
    unittest.main()


