from __future__ import annotations

import unittest
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory

from src.DPlane.Windows.npcap import NpcapDevice
from src.FIB import FIB_resolve_forwarding, FIB_sync_active_routes, FIB_table
from src.IFNET import InterfaceAddress, NetworkInterface
from src.RM.IM import (
    RM_IM_InterfaceAddressAdded,
    RM_IM_InterfaceChanged,
    RM_IM_InterfaceTable,
    RM_IM_interface_table,
    RM_IM_reconcile_from_ifnet,
    RM_IM_register_event_handlers,
)
from src.events import VVRP_EventBus
from src.IP.state import IP_set_interface_addresses
from src.RM import (
    RM_StaticRouteConfig,
    RM_RouteTable,
    RM_connected_routes,
    RM_connected_routes_from_im,
    RM_lookup_route,
    RM_register_commands,
    RM_register_route_event_handlers,
    RM_route_table,
    RM_route_table_from_im,
    RM_set_static_route_config,
    RM_static_route_configs,
)
from src.RM.commands import RM_refresh_connected_routes_from_interfaces
from src.CMD import CliContext, CommandRegistry, dispatch_line
from src.CMD.parser import CommandParser
from src.CMD.running_config import (
    load_saved_configuration,
    render_running_configuration,
    set_saved_configuration_path,
    write_saved_configuration,
)


class RoutingModuleTests(unittest.TestCase):
    def test_rm_im_table_persists_in_state_and_reconciles_snapshots(self):
        RM_state = {}
        RM_interface = routing_ethernet("eth4", "192.168.211.100", 24)

        RM_first = RM_IM_reconcile_from_ifnet(RM_state, (RM_interface,))
        RM_second = RM_IM_reconcile_from_ifnet(RM_state, (RM_interface,))

        self.assertIs(RM_first.RM_IM_table, RM_second.RM_IM_table)
        self.assertIs(RM_first.RM_IM_table, RM_IM_interface_table(RM_state))
        self.assertEqual(("eth4",), tuple(RM_item.name for RM_item in RM_first.RM_IM_changed))
        self.assertEqual((), RM_second.RM_IM_changed)
        self.assertEqual((), RM_second.RM_IM_deleted)

    def test_rm_incremental_refresh_keeps_unchanged_interface_routes(self):
        RM_interfaces = [
            routing_ethernet("eth4", "192.168.211.100", 24),
            routing_ethernet("eth5", "192.168.212.100", 24),
        ]
        RM_ctx = CliContext(output=__import__("io").StringIO())

        RM_table = RM_refresh_connected_routes_from_interfaces(
            RM_ctx,
            lambda RM_current_ctx: tuple(RM_interfaces),
        )
        RM_im_table = RM_IM_interface_table(RM_ctx.state)
        RM_eth5_before = RM_table.RM_routes_for_interface("eth5")

        RM_interfaces[0] = replace(RM_interfaces[0], is_up=False)
        RM_refreshed_table = RM_refresh_connected_routes_from_interfaces(
            RM_ctx,
            lambda RM_current_ctx: tuple(RM_interfaces),
        )
        RM_eth5_after = RM_refreshed_table.RM_routes_for_interface("eth5")

        self.assertIs(RM_table, RM_refreshed_table)
        self.assertIs(RM_im_table, RM_IM_interface_table(RM_ctx.state))
        self.assertEqual(len(RM_eth5_before), len(RM_eth5_after))
        self.assertTrue(
            all(
                RM_before is RM_after
                for RM_before, RM_after in zip(RM_eth5_before, RM_eth5_after)
            )
        )
        self.assertTrue(
            all(
                not RM_route.eligible
                for RM_route in RM_table.RM_routes_for_interface("eth4")
            )
        )

    def test_rm_incremental_refresh_deletes_removed_interface_and_routes(self):
        RM_interfaces = [
            routing_ethernet("eth4", "192.168.211.100", 24),
            routing_ethernet("eth5", "192.168.212.100", 24),
        ]
        RM_ctx = CliContext(output=__import__("io").StringIO())
        RM_table = RM_refresh_connected_routes_from_interfaces(
            RM_ctx,
            lambda RM_current_ctx: tuple(RM_interfaces),
        )

        RM_interfaces.pop(0)
        RM_refresh_connected_routes_from_interfaces(
            RM_ctx,
            lambda RM_current_ctx: tuple(RM_interfaces),
        )

        self.assertIsNone(RM_IM_interface_table(RM_ctx.state).RM_IM_get("eth4"))
        self.assertEqual((), RM_table.RM_routes_for_interface("eth4"))
        self.assertIsNone(RM_table.RM_lookup("192.168.211.1"))
        self.assertIsNotNone(RM_table.RM_lookup("192.168.212.1"))

    def test_rm_show_interface_does_not_consume_pending_reconcile_change(self):
        RM_interfaces = [routing_ethernet("eth4", "192.168.211.100", 24)]
        RM_registry = CommandRegistry()
        RM_register_commands(
            RM_registry,
            RM_interfaces_provider=lambda RM_ctx: tuple(RM_interfaces),
        )
        RM_ctx = CliContext(output=__import__("io").StringIO())
        RM_ctx.push_mode("hidden")
        RM_registry.initialize_context(RM_ctx)
        RM_table = RM_refresh_connected_routes_from_interfaces(
            RM_ctx,
            lambda RM_current_ctx: tuple(RM_interfaces),
        )
        RM_interfaces[0] = replace(RM_interfaces[0], is_up=False)

        dispatch_line(RM_ctx, RM_registry, "show rm interface")

        self.assertTrue(RM_IM_interface_table(RM_ctx.state).RM_IM_get("eth4").is_up)
        RM_refresh_connected_routes_from_interfaces(
            RM_ctx,
            lambda RM_current_ctx: tuple(RM_interfaces),
        )
        self.assertFalse(RM_IM_interface_table(RM_ctx.state).RM_IM_get("eth4").is_up)
        self.assertTrue(
            all(
                not RM_route.eligible
                for RM_route in RM_table.RM_routes_for_interface("eth4")
            )
        )

    def test_rm_builds_connected_routes_from_ifnet_interfaces_without_import_state(self):
        RM_state = {}
        IP_set_interface_addresses(
            RM_state,
            "eth4",
            (InterfaceAddress(family="ipv4", address="192.168.211.100", prefix_length=24),),
        )

        RM_routes = RM_connected_routes(RM_state, (routing_ethernet("eth4"),))

        self.assertEqual(2, len(RM_routes))
        self.assertEqual("192.168.211.0/24", str(RM_routes[0].destination))
        self.assertEqual("connected", RM_routes[0].source)
        self.assertEqual("eth4", RM_routes[0].interface.name)
        self.assertEqual("192.168.211.100", RM_routes[0].source_ip)
        self.assertEqual("192.168.211.100/32", str(RM_routes[1].destination))
        self.assertEqual("127.0.0.1", RM_routes[1].next_hop)
        self.assertEqual("eth4", RM_routes[1].interface.name)

    def test_rm_builds_loopback_network_and_host_routes(self):
        RM_routes = RM_connected_routes_from_im(
            {},
            (routing_loopback("InLoopBack0", "127.0.0.1", 8),),
        )

        self.assertEqual(
            ("127.0.0.0/8", "127.0.0.1/32"),
            tuple(str(RM_route.destination) for RM_route in RM_routes),
        )
        self.assertEqual(("InLoopBack0", "InLoopBack0"), tuple(RM_route.interface.name for RM_route in RM_routes))
        self.assertEqual("127.0.0.1", RM_routes[1].next_hop)

    def test_rm_does_not_duplicate_connected_route_for_32_bit_interface_address(self):
        RM_routes = RM_connected_routes_from_im(
            {},
            (routing_loopback("LoopBack1", "192.0.2.1", 32),),
        )

        self.assertEqual(1, len(RM_routes))
        self.assertEqual("192.0.2.1/32", str(RM_routes[0].destination))
        self.assertEqual("127.0.0.1", RM_routes[0].next_hop)

    def test_rm_lookup_route_uses_longest_prefix_match(self):
        RM_state = {}
        IP_set_interface_addresses(
            RM_state,
            "eth4",
            (InterfaceAddress(family="ipv4", address="192.168.211.100", prefix_length=24),),
        )
        IP_set_interface_addresses(
            RM_state,
            "eth5",
            (InterfaceAddress(family="ipv4", address="192.168.211.129", prefix_length=25),),
        )

        RM_route = RM_lookup_route(
            RM_state,
            (
                routing_ethernet("eth4", "192.168.211.100", 24),
                routing_ethernet("eth5", "192.168.211.129", 25),
            ),
            "192.168.211.130",
        )

        self.assertIsNotNone(RM_route)
        self.assertEqual("eth5", RM_route.interface.name)
        self.assertEqual("192.168.211.128/25", str(RM_route.destination))

    def test_rm_route_table_uses_radix_tree_for_active_longest_prefix_match(self):
        RM_route_table = RM_RouteTable()
        RM_route_table.RM_add_routes(
            (
                routing_route("eth4", "192.168.211.0/24", "192.168.211.100"),
                routing_route("eth5", "192.168.211.128/25", "192.168.211.129"),
                routing_route("eth6", "0.0.0.0/0", "10.0.0.1", preference=60),
            )
        )

        RM_route = RM_route_table.RM_lookup("192.168.211.130")
        RM_default = RM_route_table.RM_lookup("198.51.100.10")

        self.assertIsNotNone(RM_route)
        self.assertEqual("eth5", RM_route.interface.name)
        self.assertEqual("192.168.211.128/25", str(RM_route.destination))
        self.assertIsNotNone(RM_default)
        self.assertEqual("eth6", RM_default.interface.name)

    def test_rm_route_table_selects_active_route_per_prefix(self):
        RM_route_table = RM_RouteTable()
        RM_route_table.RM_add_routes(
            (
                routing_route("eth4", "192.168.211.0/24", "192.168.211.100", preference=60),
                routing_route("eth5", "192.168.211.0/24", "192.168.211.129", source="static", preference=5),
            )
        )

        RM_route = RM_route_table.RM_lookup("192.168.211.10")

        self.assertIsNotNone(RM_route)
        self.assertEqual("static", RM_route.source)
        self.assertEqual("eth5", RM_route.interface.name)
        self.assertEqual(2, len(RM_route_table.RM_routes_for_prefix(RM_route.destination)))
        self.assertEqual(1, len(RM_route_table.RM_active_routes()))

    def test_rm_route_table_indexes_routes_by_source_and_interface(self):
        RM_route_table = RM_RouteTable()
        RM_route_table.RM_add_routes(
            (
                routing_route("eth4", "192.168.211.0/24", "192.168.211.100"),
                routing_route("eth5", "192.168.212.0/24", "192.168.212.100", source="static", preference=60),
            )
        )

        self.assertEqual(("192.168.211.0/24",), tuple(str(route.destination) for route in RM_route_table.RM_routes_for_interface("eth4")))
        self.assertEqual(("192.168.212.0/24",), tuple(str(route.destination) for route in RM_route_table.RM_routes_for_source("static")))

    def test_fib_resolves_route_to_npcap_device(self):
        FIB_state = {}
        RM_table = RM_RouteTable()
        RM_table.RM_add_route(
            routing_route("eth4", "192.168.211.0/24", "192.168.211.100")
        )
        FIB_sync_active_routes(
            FIB_state,
            RM_table.RM_active_routes(),
            (NpcapDevice(name=r"\Device\NPF_eth4", description="eth4"),),
        )

        FIB_entry = FIB_resolve_forwarding(
            FIB_state,
            (),
            (NpcapDevice(name=r"\Device\NPF_eth4", description="eth4"),),
            "192.168.211.1",
        )

        self.assertIsNotNone(FIB_entry)
        self.assertEqual("eth4", FIB_entry.out_if_name)
        self.assertEqual("192.168.211.100", FIB_entry.source_ip)
        self.assertEqual("00:E0:4C:11:22:33", FIB_entry.source_mac)
        self.assertEqual("192.168.211.1", FIB_entry.next_hop_ip)

    def test_rm_im_synchronous_event_bus_updates_route_interface_view(self):
        RM_IM_bus = VVRP_EventBus()
        RM_IM_table = RM_IM_InterfaceTable()
        RM_IM_register_event_handlers(RM_IM_bus, RM_IM_table)

        RM_IM_bus.VVRP_publish(RM_IM_InterfaceChanged(routing_ethernet("eth4", address="0.0.0.0")))
        RM_IM_bus.VVRP_publish(
            RM_IM_InterfaceAddressAdded(
                "eth4",
                InterfaceAddress(family="ipv4", address="192.168.211.100", prefix_length=24),
            )
        )

        RM_routes = RM_connected_routes_from_im({}, RM_IM_table.RM_IM_list())

        self.assertEqual(2, len(RM_routes))
        self.assertEqual("192.168.211.0/24", str(RM_routes[0].destination))
        self.assertEqual("eth4", RM_routes[0].interface.name)
        self.assertEqual("192.168.211.100/32", str(RM_routes[1].destination))
        self.assertEqual("127.0.0.1", RM_routes[1].next_hop)

    def test_ip_address_event_creates_connected_active_route_without_fib_sync(self):
        RM_state = {}
        RM_IM_bus = VVRP_EventBus()
        RM_IM_table = RM_IM_InterfaceTable()
        RM_IM_register_event_handlers(RM_IM_bus, RM_IM_table)
        RM_table = RM_register_route_event_handlers(
            RM_IM_bus,
            RM_state,
            RM_IM_table,
        )

        RM_IM_bus.VVRP_publish(RM_IM_InterfaceChanged(routing_ethernet("eth4", address="0.0.0.0")))
        self.assertEqual((), RM_table.RM_active_routes())

        RM_IM_bus.VVRP_publish(
            RM_IM_InterfaceAddressAdded(
                "eth4",
                InterfaceAddress(family="ipv4", address="192.168.211.100", prefix_length=24),
            )
        )

        RM_active_routes = RM_table.RM_active_routes()
        self.assertEqual(2, len(RM_active_routes))
        self.assertEqual(
            ("192.168.211.0/24", "192.168.211.100/32"),
            tuple(str(RM_route.destination) for RM_route in RM_active_routes),
        )
        self.assertTrue(all(RM_route.source == "connected" for RM_route in RM_active_routes))
        self.assertIs(RM_table, RM_route_table(RM_state))

        self.assertEqual(0, len(FIB_table(RM_state).FIB_entries()))

    def test_fib_sync_installs_only_active_routes(self):
        FIB_state = {}
        RM_table = RM_RouteTable()
        RM_table.RM_add_routes(
            (
                routing_route("eth4", "192.168.211.0/24", "192.168.211.100", preference=60),
                routing_route(
                    "eth5",
                    "192.168.211.0/24",
                    "192.168.211.129",
                    source="static",
                    preference=5,
                ),
            )
        )

        FIB_sync_active_routes(
            FIB_state,
            RM_table.RM_active_routes(),
            (NpcapDevice(name=r"\Device\NPF_eth5", description="eth5"),),
        )

        FIB_entries = FIB_table(FIB_state).FIB_entries()
        self.assertEqual(1, len(FIB_entries))
        self.assertEqual("eth5", FIB_entries[0].out_if_name)
        self.assertEqual("192.168.211.129", FIB_entries[0].source_ip)

    def test_show_fib_displays_installed_forwarding_entries(self):
        RM_registry = CommandRegistry()
        from src.FIB import FIB_register_commands

        FIB_register_commands(RM_registry)
        RM_output = __import__("io").StringIO()
        RM_ctx = CliContext(output=RM_output)
        FIB_sync_active_routes(
            RM_ctx.state,
            (routing_route("eth4", "192.168.211.0/24", "192.168.211.100"),),
            (NpcapDevice(name=r"\Device\NPF_eth4", description="eth4"),),
        )
        RM_registry.initialize_context(RM_ctx)

        RM_outcome = dispatch_line(RM_ctx, RM_registry, "show fib")

        self.assertTrue(RM_outcome.executed)
        RM_text = RM_output.getvalue()
        self.assertIn("Route Flags: G - Gateway Route, H - Host Route", RM_text)
        self.assertIn("FIB Table:", RM_text)
        self.assertIn("Total number of Routes : 1", RM_text)
        self.assertIn("Destination/Mask", RM_text)
        self.assertIn("192.168.211.0/24", RM_text)
        self.assertIn("192.168.211.100", RM_text)
        self.assertIn("U", RM_text)
        self.assertRegex(RM_text, r"t\[\d+\]")
        self.assertIn("eth4", RM_text)

    def test_show_fib_ip_uses_fib_longest_prefix_match(self):
        RM_registry = CommandRegistry()
        from src.FIB import FIB_register_commands

        FIB_register_commands(RM_registry)
        RM_output = __import__("io").StringIO()
        RM_ctx = CliContext(output=RM_output)
        FIB_sync_active_routes(
            RM_ctx.state,
            (
                routing_route("eth4", "192.168.211.0/24", "192.168.211.100"),
                routing_route("eth5", "192.168.211.128/25", "192.168.211.129"),
            ),
            (
                NpcapDevice(name=r"\Device\NPF_eth4", description="eth4"),
                NpcapDevice(name=r"\Device\NPF_eth5", description="eth5"),
            ),
        )
        RM_registry.initialize_context(RM_ctx)

        RM_outcome = dispatch_line(RM_ctx, RM_registry, "show fib 192.168.211.130")

        self.assertTrue(RM_outcome.executed)
        RM_text = RM_output.getvalue()
        self.assertIn("192.168.211.128/25", RM_text)
        self.assertIn("eth5", RM_text)
        self.assertNotIn("192.168.211.0/24", RM_text)

    def test_rm_route_table_builds_from_im_interface_view(self):
        RM_route_table = RM_route_table_from_im(
            {},
            (routing_ethernet("eth4", "192.168.211.100", 24),),
        )

        RM_route = RM_route_table.RM_lookup("192.168.211.1")

        self.assertIsNotNone(RM_route)
        self.assertEqual("eth4", RM_route.interface.name)

    def test_show_ip_routing_table_displays_active_routes(self):
        RM_registry = CommandRegistry()
        RM_register_commands(
            RM_registry,
            RM_interfaces_provider=lambda RM_ctx: (
                routing_ethernet("eth4", "192.168.211.100", 24),
            ),
        )
        RM_output = __import__("io").StringIO()
        RM_ctx = CliContext(output=RM_output)
        RM_registry.initialize_context(RM_ctx)

        RM_outcome = dispatch_line(RM_ctx, RM_registry, "show ip routing-table")

        self.assertTrue(RM_outcome.executed)
        self.assertIn(
            "Destination/Mask    Proto   Pre  Cost        Flags NextHop         Interface\n\n",
            RM_outcome.message,
        )
        self.assertTrue(RM_outcome.message.endswith("\n"))
        RM_text = RM_output.getvalue()
        self.assertIn("Route Flags: R - relay, D - download to fib", RM_text)
        self.assertIn("Routing Tables: Public", RM_text)
        self.assertIn("Destination/Mask", RM_text)
        self.assertIn("192.168.211.0/24", RM_text)
        self.assertIn("192.168.211.100/32", RM_text)
        self.assertIn("Direct", RM_text)
        self.assertIn("192.168.211.100", RM_text)
        self.assertIn("127.0.0.1", RM_text)
        self.assertIn("eth4", RM_text)
        self.assertEqual(0, len(FIB_table(RM_ctx.state).FIB_entries()))

    def test_show_ip_routing_table_does_not_install_active_routes_into_fib(self):
        RM_registry = CommandRegistry()
        RM_register_commands(
            RM_registry,
            RM_interfaces_provider=lambda RM_ctx: (
                routing_ethernet("eth4", "192.168.211.100", 24),
            ),
        )
        from src.FIB import FIB_register_commands

        FIB_register_commands(RM_registry)
        RM_output = __import__("io").StringIO()
        RM_ctx = CliContext(output=RM_output)
        RM_registry.initialize_context(RM_ctx)

        self.assertTrue(dispatch_line(RM_ctx, RM_registry, "show ip routing-table").executed)
        RM_output.truncate(0)
        RM_output.seek(0)
        self.assertTrue(dispatch_line(RM_ctx, RM_registry, "show fib").executed)

        RM_text = RM_output.getvalue()
        self.assertIn("No FIB entries found", RM_text)
        self.assertNotIn("192.168.211.0/24", RM_text)

    def test_explicit_fib_sync_installs_routes_after_rm_table_refresh(self):
        RM_registry = CommandRegistry()
        RM_register_commands(
            RM_registry,
            RM_interfaces_provider=lambda RM_ctx: (
                routing_ethernet("eth4", "1.1.1.1", 24),
            ),
        )
        from src.FIB import FIB_register_commands

        FIB_register_commands(RM_registry)
        RM_output = __import__("io").StringIO()
        RM_ctx = CliContext(output=RM_output)
        RM_registry.initialize_context(RM_ctx)

        self.assertTrue(dispatch_line(RM_ctx, RM_registry, "show ip routing-table").executed)
        FIB_sync_active_routes(RM_ctx.state, RM_route_table(RM_ctx.state).RM_active_routes())
        RM_output.truncate(0)
        RM_output.seek(0)
        self.assertTrue(dispatch_line(RM_ctx, RM_registry, "show fib").executed)

        RM_text = RM_output.getvalue()
        FIB_entries = {
            str(FIB_entry.destination): FIB_entry
            for FIB_entry in FIB_table(RM_ctx.state).FIB_entries()
        }
        self.assertEqual(2, len(FIB_entries))
        self.assertEqual("U", FIB_entries["1.1.1.0/24"].flags)
        self.assertEqual("HU", FIB_entries["1.1.1.1/32"].flags)
        self.assertEqual("InLoopBack0", FIB_entries["1.1.1.1/32"].out_if_name)
        self.assertEqual("127.0.0.1", FIB_entries["1.1.1.1/32"].next_hop_ip)
        self.assertIn("Total number of Routes : 2", RM_text)
        self.assertIn("1.1.1.0/24", RM_text)
        self.assertIn("1.1.1.1/32", RM_text)
        self.assertIn("127.0.0.1", RM_text)
        self.assertIn("HU", RM_text)
        self.assertIn("InLoopBack0", RM_text)
        self.assertIn("eth4", RM_text)

    def test_fib_sync_preserves_timestamp_for_unchanged_entry(self):
        FIB_state = {}
        RM_route = routing_route(
            "eth4",
            "192.168.211.0/24",
            "192.168.211.100",
        )

        FIB_sync_active_routes(FIB_state, (RM_route,))
        FIB_first = FIB_table(FIB_state).FIB_entries()[0]
        FIB_sync_active_routes(FIB_state, (RM_route,))
        FIB_second = FIB_table(FIB_state).FIB_entries()[0]

        self.assertEqual(FIB_first.installed_at, FIB_second.installed_at)

    def test_show_ip_routing_table_protocol_filters_routes(self):
        RM_registry = CommandRegistry()
        RM_register_commands(RM_registry)
        RM_output = __import__("io").StringIO()
        RM_ctx = CliContext(output=RM_output)
        RM_table = RM_route_table(RM_ctx.state)
        RM_table.RM_add_routes(
            (
                routing_route("eth4", "192.168.211.0/24", "192.168.211.100"),
                routing_route(
                    "eth5",
                    "203.0.113.0/24",
                    "192.168.212.100",
                    source="static",
                    preference=60,
                ),
            )
        )
        from ipaddress import IPv4Network

        RM_set_static_route_config(
            RM_ctx.state,
            RM_StaticRouteConfig(
                destination=IPv4Network("203.0.113.0/24"),
                interface_name="eth5",
            ),
        )
        RM_registry.initialize_context(RM_ctx)

        RM_outcome = dispatch_line(RM_ctx, RM_registry, "show ip routing-table protocol static")

        self.assertTrue(RM_outcome.executed)
        RM_text = RM_output.getvalue()
        self.assertIn("203.0.113.0/24", RM_text)
        self.assertIn("Static", RM_text)
        self.assertNotIn("192.168.211.0/24", RM_text)

    def test_show_ip_routing_table_protocol_direct_maps_connected_routes(self):
        RM_registry = CommandRegistry()
        RM_register_commands(RM_registry)
        RM_output = __import__("io").StringIO()
        RM_ctx = CliContext(output=RM_output)
        RM_table = RM_route_table(RM_ctx.state)
        RM_table.RM_add_route(routing_route("eth4", "192.168.211.0/24", "192.168.211.100"))
        RM_registry.initialize_context(RM_ctx)

        RM_outcome = dispatch_line(RM_ctx, RM_registry, "show ip routing-table protocol direct")

        self.assertTrue(RM_outcome.executed)
        RM_text = RM_output.getvalue()
        self.assertIn("Public routing table : Direct", RM_text)
        self.assertIn("Destinations : 1        Routes : 1", RM_text)
        self.assertIn("Direct routing table status : <Active>", RM_text)
        self.assertIn("192.168.211.0/24", RM_text)
        self.assertIn("Direct routing table status : <Inactive>", RM_text)
        self.assertIn("Destinations : 0        Routes : 0", RM_text)

    def test_inactive_direct_routes_remain_visible_but_do_not_enter_fib(self):
        RM_registry = CommandRegistry()
        RM_interfaces = (
            replace(
                routing_ethernet("eth4", "192.168.211.100", 24),
                is_up=False,
            ),
        )
        RM_register_commands(
            RM_registry,
            RM_interfaces_provider=lambda RM_ctx: RM_interfaces,
        )
        RM_output = __import__("io").StringIO()
        RM_ctx = CliContext(output=RM_output)
        RM_ctx.push_mode("hidden")
        RM_registry.initialize_context(RM_ctx)
        RM_table = RM_refresh_connected_routes_from_interfaces(
            RM_ctx,
            lambda RM_current_ctx: RM_interfaces,
        )
        FIB_sync_active_routes(RM_ctx.state, RM_table.RM_active_routes())

        dispatch_line(RM_ctx, RM_registry, "show ip routing-table protocol direct")

        RM_routes = RM_table.RM_routes_for_source("connected")
        self.assertEqual(2, len(RM_routes))
        self.assertTrue(all(not RM_route.eligible for RM_route in RM_routes))
        self.assertIsNone(RM_table.RM_lookup("192.168.211.1"))
        self.assertIsNone(FIB_table(RM_ctx.state).FIB_lookup("192.168.211.1"))
        RM_text = RM_output.getvalue()
        self.assertIn("Direct routing table status : <Active>", RM_text)
        self.assertIn("Destinations : 0        Routes : 0", RM_text)
        self.assertIn("Direct routing table status : <Inactive>", RM_text)
        self.assertIn("Destinations : 2        Routes : 2", RM_text)
        self.assertIn("192.168.211.0/24", RM_text)
        self.assertIn("192.168.211.100/32", RM_text)

    def test_direct_route_age_survives_control_plane_refresh(self):
        RM_interfaces = (routing_ethernet("eth4", "192.168.211.100", 24),)
        RM_ctx = CliContext(output=__import__("io").StringIO())

        RM_first_table = RM_refresh_connected_routes_from_interfaces(
            RM_ctx,
            lambda RM_current_ctx: RM_interfaces,
        )
        RM_first_ages = {
            str(RM_route.destination): RM_route.created_at
            for RM_route in RM_first_table.RM_routes_for_source("connected")
        }
        RM_second_table = RM_refresh_connected_routes_from_interfaces(
            RM_ctx,
            lambda RM_current_ctx: RM_interfaces,
        )
        RM_second_ages = {
            str(RM_route.destination): RM_route.created_at
            for RM_route in RM_second_table.RM_routes_for_source("connected")
        }

        self.assertEqual(RM_first_ages, RM_second_ages)

    def test_show_rm_interface_displays_detail_in_hidden_mode(self):
        RM_registry = CommandRegistry()
        RM_register_commands(
            RM_registry,
            RM_interfaces_provider=lambda RM_ctx: (
                routing_ethernet("eth4", "192.168.211.100", 24),
            ),
        )
        RM_output = __import__("io").StringIO()
        RM_ctx = CliContext(output=RM_output)
        RM_ctx.push_mode("hidden")
        RM_registry.initialize_context(RM_ctx)

        RM_outcome = dispatch_line(RM_ctx, RM_registry, "show rm interface")

        self.assertTrue(RM_outcome.executed)
        RM_text = RM_output.getvalue()
        self.assertIn("Name: eth4", RM_text)
        self.assertIn("Physical IF Info:", RM_text)
        self.assertIn(" IfnetIndex: 0x0", RM_text)
        self.assertIn(" State: UP", RM_text)
        self.assertIn(" Slot: \n", RM_text)
        self.assertIn(" IntType: , PriLog: , MTU: 1500, Reference Count ", RM_text)
        self.assertIn(" Bandwidth: , ", RM_text)
        self.assertIn(" LDP-ISIS sync capability: disabled", RM_text)
        self.assertIn(" InstanceID: 0, Instance Name: Public", RM_text)
        self.assertIn("Logical IF Info:", RM_text)
        self.assertIn("eth4", RM_text)
        self.assertIn(" Dest: 192.168.211.100, Mask: 255.255.255.0", RM_text)
        self.assertIn(" Reference Count ", RM_text)

    def test_show_rm_interface_detail_uses_zero_slot_for_loopback(self):
        RM_registry = CommandRegistry()
        RM_register_commands(
            RM_registry,
            RM_interfaces_provider=lambda RM_ctx: (
                routing_loopback("loopback_0", "10.10.10.1", 32),
            ),
        )
        RM_output = __import__("io").StringIO()
        RM_ctx = CliContext(output=RM_output)
        RM_ctx.push_mode("hidden")
        RM_registry.initialize_context(RM_ctx)

        RM_outcome = dispatch_line(RM_ctx, RM_registry, "show rm interface")

        self.assertTrue(RM_outcome.executed)
        RM_text = RM_output.getvalue()
        self.assertIn("Name: loopback_0", RM_text)
        self.assertIn(" Slot: 0(Logic Slot: 0)", RM_text)
        self.assertIn(" State: UP LOOP MULT", RM_text)
        self.assertIn(" IntType: 26, PriLog: 1, MTU: 1500, Reference Count ", RM_text)
        self.assertIn(" Dest: 10.10.10.1, Mask: 255.255.255.255", RM_text)
        self.assertIn(" State: UP LOOP PRM MULT , Reference Count ", RM_text)

    def test_show_rm_interface_brief_displays_list_in_hidden_mode(self):
        RM_registry = CommandRegistry()
        RM_register_commands(
            RM_registry,
            RM_interfaces_provider=lambda RM_ctx: (
                routing_ethernet("eth4", "192.168.211.100", 24),
            ),
        )
        RM_output = __import__("io").StringIO()
        RM_ctx = CliContext(output=RM_output)
        RM_ctx.push_mode("hidden")
        RM_registry.initialize_context(RM_ctx)

        RM_outcome = dispatch_line(RM_ctx, RM_registry, "show rm interface brief")

        self.assertTrue(RM_outcome.executed)
        RM_text = RM_output.getvalue()
        self.assertIn("Interface", RM_text)
        self.assertIn("IfIndex", RM_text)
        self.assertIn("eth4", RM_text)
        self.assertIn("192.168.211.100/24", RM_text)

    def test_show_rm_interface_name_filters_route_management_interface_view(self):
        RM_registry = CommandRegistry()
        RM_register_commands(
            RM_registry,
            RM_interfaces_provider=lambda RM_ctx: (
                routing_ethernet("eth4", "192.168.211.100", 24),
                routing_ethernet("eth5", "192.168.212.100", 24),
            ),
        )
        RM_output = __import__("io").StringIO()
        RM_ctx = CliContext(output=RM_output)
        RM_ctx.push_mode("hidden")
        RM_registry.initialize_context(RM_ctx)

        RM_outcome = dispatch_line(RM_ctx, RM_registry, "show rm interface eth5")

        self.assertTrue(RM_outcome.executed)
        RM_text = RM_output.getvalue()
        self.assertIn("eth5", RM_text)
        self.assertNotIn("eth4", RM_text)

    def test_show_rm_interface_is_hidden_only_and_show_rm_is_incomplete(self):
        RM_registry = CommandRegistry()
        RM_register_commands(
            RM_registry,
            RM_interfaces_provider=lambda RM_ctx: (
                routing_ethernet("eth4", "192.168.211.100", 24),
            ),
        )
        RM_user_ctx = CliContext(output=__import__("io").StringIO())
        RM_registry.initialize_context(RM_user_ctx)

        RM_user_outcome = dispatch_line(RM_user_ctx, RM_registry, "show rm interface")
        self.assertFalse(RM_user_outcome.executed)

        RM_hidden_ctx = CliContext(output=__import__("io").StringIO())
        RM_hidden_ctx.push_mode("hidden")
        RM_registry.initialize_context(RM_hidden_ctx)
        RM_incomplete = dispatch_line(RM_hidden_ctx, RM_registry, "show rm")
        self.assertFalse(RM_incomplete.executed)
        self.assertEqual("% Incomplete command", RM_incomplete.message)

    def test_rm_configures_displays_and_removes_router_id(self):
        RM_registry = CommandRegistry()
        RM_register_commands(RM_registry)
        RM_output = __import__("io").StringIO()
        RM_ctx = CliContext(output=RM_output)
        RM_ctx.push_mode("config")
        RM_registry.initialize_context(RM_ctx)

        RM_configure = dispatch_line(RM_ctx, RM_registry, "router id 1.1.1.1")
        RM_show = dispatch_line(RM_ctx, RM_registry, "show router id")

        self.assertTrue(RM_configure.executed)
        self.assertTrue(RM_show.executed)
        self.assertEqual("RouterID:1.1.1.1\n", RM_output.getvalue())
        self.assertIn("router id 1.1.1.1", render_running_configuration(RM_ctx))

        RM_remove = dispatch_line(RM_ctx, RM_registry, "no router id")
        RM_output.seek(0)
        RM_output.truncate(0)
        RM_show_unconfigured = dispatch_line(RM_ctx, RM_registry, "show router id")

        self.assertTrue(RM_remove.executed)
        self.assertTrue(RM_show_unconfigured.executed)
        self.assertEqual("RouterID:0.0.0.0\n", RM_output.getvalue())
        self.assertNotIn("router id", render_running_configuration(RM_ctx))

    def test_rm_rejects_invalid_router_id(self):
        RM_registry = CommandRegistry()
        RM_register_commands(RM_registry)
        RM_output = __import__("io").StringIO()
        RM_ctx = CliContext(output=RM_output)
        RM_ctx.push_mode("config")
        RM_registry.initialize_context(RM_ctx)

        RM_outcome = dispatch_line(RM_ctx, RM_registry, "router id 300.1.1.1")

        self.assertTrue(RM_outcome.executed)
        self.assertEqual("% Invalid router ID", RM_outcome.message)
        self.assertNotIn("router id", render_running_configuration(RM_ctx))

    def test_rm_router_id_command_groups_are_incomplete(self):
        RM_registry = CommandRegistry()
        RM_register_commands(RM_registry)
        RM_ctx = CliContext(output=__import__("io").StringIO())
        RM_ctx.push_mode("config")
        RM_registry.initialize_context(RM_ctx)

        RM_router = dispatch_line(RM_ctx, RM_registry, "router")
        RM_show_router = dispatch_line(RM_ctx, RM_registry, "show router")

        self.assertFalse(RM_router.executed)
        self.assertEqual("% Incomplete command", RM_router.message)
        self.assertFalse(RM_show_router.executed)
        self.assertEqual("% Incomplete command", RM_show_router.message)

    def test_rm_router_id_is_configurable_in_hidden_mode(self):
        RM_registry = CommandRegistry()
        RM_register_commands(RM_registry)
        RM_output = __import__("io").StringIO()
        RM_ctx = CliContext(output=RM_output)
        RM_ctx.push_mode("hidden")
        RM_registry.initialize_context(RM_ctx)

        RM_configure = dispatch_line(RM_ctx, RM_registry, "router id 1.1.1.1")
        RM_show = dispatch_line(RM_ctx, RM_registry, "show router id")
        RM_remove = dispatch_line(RM_ctx, RM_registry, "no router id")

        self.assertTrue(RM_configure.executed)
        self.assertTrue(RM_show.executed)
        self.assertTrue(RM_remove.executed)
        self.assertEqual("RouterID:1.1.1.1\n", RM_output.getvalue())

    def test_static_route_command_installs_rib_and_fib_entry(self):
        RM_registry = CommandRegistry()
        RM_interfaces = (routing_ethernet("eth4", "192.168.211.100", 24),)

        def RM_refresh(RM_ctx):
            RM_table = RM_refresh_connected_routes_from_interfaces(
                RM_ctx,
                lambda RM_current_ctx: RM_interfaces,
            )
            FIB_sync_active_routes(RM_ctx.state, RM_table.RM_active_routes())

        RM_register_commands(
            RM_registry,
            RM_interfaces_provider=lambda RM_ctx: RM_interfaces,
            RM_after_route_change=RM_refresh,
        )
        RM_output = __import__("io").StringIO()
        RM_ctx = CliContext(output=RM_output)
        RM_ctx.push_mode("hidden")
        RM_registry.initialize_context(RM_ctx)

        RM_outcome = dispatch_line(
            RM_ctx,
            RM_registry,
            "ip route-static 10.0.0.0 8 192.168.211.1 preference 80 tag 123 "
            "description branch network",
        )

        self.assertTrue(RM_outcome.executed)
        RM_routes = RM_route_table(RM_ctx.state).RM_routes_for_source("static")
        self.assertEqual(1, len(RM_routes))
        self.assertEqual("10.0.0.0/8", str(RM_routes[0].destination))
        self.assertEqual("192.168.211.1", RM_routes[0].next_hop)
        self.assertEqual("eth4", RM_routes[0].interface.name)
        self.assertEqual(80, RM_routes[0].preference)
        self.assertEqual(123, RM_routes[0].tag)
        self.assertEqual("branch network", RM_routes[0].description)
        RM_fib_entry = FIB_table(RM_ctx.state).FIB_lookup("10.1.2.3")
        self.assertIsNotNone(RM_fib_entry)
        self.assertEqual("192.168.211.1", RM_fib_entry.next_hop_ip)
        self.assertEqual("eth4", RM_fib_entry.out_if_name)
        self.assertEqual("GS", RM_fib_entry.flags)
        self.assertIn(
            "ip route-static 10.0.0.0 8 192.168.211.1 preference 80 tag 123 "
            "description branch network",
            render_running_configuration(RM_ctx),
        )

    def test_show_static_routes_separates_active_and_inactive_configurations(self):
        RM_registry = CommandRegistry()
        RM_interfaces = (routing_ethernet("eth4", "192.168.211.100", 24),)

        def RM_refresh(RM_ctx):
            RM_table = RM_refresh_connected_routes_from_interfaces(
                RM_ctx,
                lambda RM_current_ctx: RM_interfaces,
            )
            FIB_sync_active_routes(RM_ctx.state, RM_table.RM_active_routes())

        RM_register_commands(
            RM_registry,
            RM_interfaces_provider=lambda RM_ctx: RM_interfaces,
            RM_after_route_change=RM_refresh,
        )
        RM_output = __import__("io").StringIO()
        RM_ctx = CliContext(output=RM_output)
        RM_ctx.push_mode("hidden")
        RM_registry.initialize_context(RM_ctx)
        dispatch_line(RM_ctx, RM_registry, "ip route-static 3.3.3.0 24 192.168.211.1")
        dispatch_line(RM_ctx, RM_registry, "ip route-static 2.2.2.0 24 8.8.8.8")

        dispatch_line(RM_ctx, RM_registry, "show ip routing-table protocol static")

        RM_text = RM_output.getvalue()
        self.assertIn("Public routing table : Static", RM_text)
        self.assertIn("Destinations : 2        Routes : 2        Configured Routes : 2", RM_text)
        self.assertIn("Static routing table status : <Active>", RM_text)
        self.assertIn("Static routing table status : <Inactive>", RM_text)
        self.assertIn("3.3.3.0/24", RM_text)
        self.assertIn("192.168.211.1", RM_text)
        self.assertIn("RD", RM_text)
        self.assertIn("2.2.2.0/24", RM_text)
        self.assertIn("8.8.8.8", RM_text)
        self.assertIn("Unknown", RM_text)

    def test_show_static_inactive_and_verbose_match_vrp_sections(self):
        RM_registry = CommandRegistry()
        RM_interfaces = (routing_ethernet("eth4", "192.168.211.100", 24),)

        def RM_refresh(RM_ctx):
            RM_table = RM_refresh_connected_routes_from_interfaces(
                RM_ctx,
                lambda RM_current_ctx: RM_interfaces,
            )
            FIB_sync_active_routes(RM_ctx.state, RM_table.RM_active_routes())

        RM_register_commands(
            RM_registry,
            RM_interfaces_provider=lambda RM_ctx: RM_interfaces,
            RM_after_route_change=RM_refresh,
        )
        RM_output = __import__("io").StringIO()
        RM_ctx = CliContext(output=RM_output)
        RM_ctx.push_mode("hidden")
        RM_registry.initialize_context(RM_ctx)
        dispatch_line(RM_ctx, RM_registry, "ip route-static 3.3.3.0 24 192.168.211.1")
        dispatch_line(RM_ctx, RM_registry, "ip route-static 2.2.2.0 24 8.8.8.8 tag 9")

        dispatch_line(RM_ctx, RM_registry, "show ip routing-table protocol static inactive")
        RM_inactive_text = RM_output.getvalue()
        self.assertIn("Static routing table", RM_inactive_text)
        self.assertIn("Destinations : 1        Routes : 1        Configured Routes : 2", RM_inactive_text)
        self.assertIn("2.2.2.0/24", RM_inactive_text)
        self.assertNotIn("3.3.3.0/24", RM_inactive_text)

        RM_output.seek(0)
        RM_output.truncate(0)
        dispatch_line(RM_ctx, RM_registry, "show ip routing-table protocol static verbose")
        RM_verbose_text = RM_output.getvalue()
        self.assertIn("Destination: 2.2.2.0/24", RM_verbose_text)
        self.assertIn("State: Invalid Adv", RM_verbose_text)
        self.assertIn("Interface: Unknown", RM_verbose_text)
        self.assertIn("Tag: 9", RM_verbose_text)
        self.assertIn("Destination: 3.3.3.0/24", RM_verbose_text)
        self.assertIn("State: Active Adv Relied", RM_verbose_text)
        self.assertIn("Interface: eth4", RM_verbose_text)
        self.assertRegex(RM_verbose_text, r"Age: \d{2}h\d{2}m\d{2}s")

    def test_show_ip_routing_table_verbose_combines_direct_and_static_status(self):
        RM_registry = CommandRegistry()
        RM_interfaces = (routing_ethernet("eth4", "192.168.211.100", 24),)

        def RM_refresh(RM_ctx):
            RM_table = RM_refresh_connected_routes_from_interfaces(
                RM_ctx,
                lambda RM_current_ctx: RM_interfaces,
            )
            FIB_sync_active_routes(RM_ctx.state, RM_table.RM_active_routes())

        RM_register_commands(
            RM_registry,
            RM_interfaces_provider=lambda RM_ctx: RM_interfaces,
            RM_after_route_change=RM_refresh,
        )
        RM_output = __import__("io").StringIO()
        RM_ctx = CliContext(output=RM_output)
        RM_ctx.push_mode("hidden")
        RM_registry.initialize_context(RM_ctx)
        RM_refresh(RM_ctx)
        dispatch_line(RM_ctx, RM_registry, "ip route-static 3.3.3.0 24 192.168.211.1")
        dispatch_line(RM_ctx, RM_registry, "ip route-static 2.2.2.0 24 8.8.8.8")

        dispatch_line(RM_ctx, RM_registry, "show ip routing-table verbose")

        RM_text = RM_output.getvalue()
        self.assertIn("Routing Tables: Public", RM_text)
        self.assertIn("Destinations : 4        Routes : 4", RM_text)
        self.assertIn("Destination: 192.168.211.0/24", RM_text)
        self.assertIn("Protocol: Direct", RM_text)
        self.assertIn("State: Active Adv", RM_text)
        self.assertIn("Priority: high", RM_text)
        self.assertIn("Destination: 192.168.211.100/32", RM_text)
        self.assertIn("State: Active NoAdv", RM_text)
        self.assertIn("Destination: 3.3.3.0/24", RM_text)
        self.assertIn("State: Active Adv Relied", RM_text)
        self.assertIn("Destination: 2.2.2.0/24", RM_text)
        self.assertIn("State: Invalid Adv", RM_text)
        self.assertIn("Interface: Unknown", RM_text)

    def test_show_ip_routing_table_verbose_displays_inactive_direct_route(self):
        RM_registry = CommandRegistry()
        RM_interfaces = (
            replace(
                routing_ethernet("eth4", "192.168.211.100", 24),
                is_up=False,
            ),
        )
        RM_register_commands(
            RM_registry,
            RM_interfaces_provider=lambda RM_ctx: RM_interfaces,
        )
        RM_output = __import__("io").StringIO()
        RM_ctx = CliContext(output=RM_output)
        RM_ctx.push_mode("interface", "eth4")
        RM_registry.initialize_context(RM_ctx)

        dispatch_line(RM_ctx, RM_registry, "show ip routing-table verbose")

        RM_text = RM_output.getvalue()
        self.assertIn("Destination: 192.168.211.0/24", RM_text)
        self.assertIn("State: Inactive Adv", RM_text)
        self.assertIn("Destination: 192.168.211.100/32", RM_text)
        self.assertIn("State: Inactive NoAdv", RM_text)
        self.assertNotIn("Flags:  D", RM_text)

    def test_show_routing_table_protocol_help_uses_literal_static_subcommands(self):
        RM_registry = CommandRegistry()
        RM_register_commands(RM_registry)
        RM_ctx = CliContext(output=__import__("io").StringIO())
        RM_ctx.push_mode("hidden")
        RM_registry.initialize_context(RM_ctx)
        RM_parser = CommandParser(RM_registry)

        RM_protocol = RM_parser.help_candidates(
            "show ip routing-table protocol ",
            mode="hidden",
            ctx=RM_ctx,
        )
        RM_static = RM_parser.help_candidates(
            "show ip routing-table protocol static ",
            mode="hidden",
            ctx=RM_ctx,
        )

        self.assertEqual(("direct", "static"), tuple(RM_item.display for RM_item in RM_protocol))
        self.assertEqual(
            ("inactive", "verbose", "<cr>"),
            tuple(RM_item.display for RM_item in RM_static),
        )
        RM_routing_table = RM_parser.help_candidates(
            "show ip routing-table ",
            mode="hidden",
            ctx=RM_ctx,
        )
        self.assertEqual(
            ("protocol", "verbose", "<cr>"),
            tuple(RM_item.display for RM_item in RM_routing_table),
        )

    def test_show_ip_routing_table_family_is_available_in_interface_mode(self):
        RM_registry = CommandRegistry()
        RM_register_commands(RM_registry)
        RM_ctx = CliContext(output=__import__("io").StringIO())
        RM_ctx.push_mode("interface", "eth0")
        RM_registry.initialize_context(RM_ctx)

        for RM_command in (
            "show ip routing-table",
            "show ip routing-table verbose",
            "show ip routing-table protocol direct",
            "show ip routing-table protocol static",
            "show ip routing-table protocol static inactive",
            "show ip routing-table protocol static verbose",
        ):
            with self.subTest(RM_command=RM_command):
                self.assertTrue(
                    dispatch_line(RM_ctx, RM_registry, RM_command).executed,
                    RM_command,
                )

    def test_static_route_preference_selects_active_candidate(self):
        RM_registry = CommandRegistry()
        RM_interfaces = (routing_ethernet("eth4", "192.168.211.100", 24),)

        def RM_refresh(RM_ctx):
            RM_table = RM_refresh_connected_routes_from_interfaces(
                RM_ctx,
                lambda RM_current_ctx: RM_interfaces,
            )
            FIB_sync_active_routes(RM_ctx.state, RM_table.RM_active_routes())

        RM_register_commands(
            RM_registry,
            RM_interfaces_provider=lambda RM_ctx: RM_interfaces,
            RM_after_route_change=RM_refresh,
        )
        RM_ctx = CliContext(output=__import__("io").StringIO())
        RM_ctx.push_mode("hidden")
        RM_registry.initialize_context(RM_ctx)

        self.assertTrue(
            dispatch_line(
                RM_ctx,
                RM_registry,
                "ip route-static 10.0.0.0 8 192.168.211.1 preference 100",
            ).executed
        )
        self.assertTrue(
            dispatch_line(
                RM_ctx,
                RM_registry,
                "ip route-static 10.0.0.0 8 192.168.211.2 preference 50",
            ).executed
        )

        RM_table = RM_route_table(RM_ctx.state)
        self.assertEqual(2, len(RM_table.RM_routes_for_source("static")))
        self.assertEqual("192.168.211.2", RM_table.RM_lookup("10.1.1.1").next_hop)
        self.assertEqual(
            "192.168.211.2",
            FIB_table(RM_ctx.state).FIB_lookup("10.1.1.1").next_hop_ip,
        )

    def test_equal_preference_static_routes_are_active_ecmp_entries(self):
        RM_registry = CommandRegistry()
        RM_interfaces = (routing_ethernet("eth4", "192.168.211.100", 24),)

        def RM_refresh(RM_ctx):
            RM_table = RM_refresh_connected_routes_from_interfaces(
                RM_ctx,
                lambda RM_current_ctx: RM_interfaces,
            )
            FIB_sync_active_routes(RM_ctx.state, RM_table.RM_active_routes())

        RM_register_commands(
            RM_registry,
            RM_interfaces_provider=lambda RM_ctx: RM_interfaces,
            RM_after_route_change=RM_refresh,
        )
        RM_ctx = CliContext(output=__import__("io").StringIO())
        RM_ctx.push_mode("hidden")
        RM_registry.initialize_context(RM_ctx)

        dispatch_line(RM_ctx, RM_registry, "ip route-static 10.0.0.0 8 192.168.211.1")
        dispatch_line(RM_ctx, RM_registry, "ip route-static 10.0.0.0 8 192.168.211.2")

        RM_active = tuple(
            RM_route
            for RM_route in RM_route_table(RM_ctx.state).RM_active_routes()
            if str(RM_route.destination) == "10.0.0.0/8"
        )
        RM_fib_entries = tuple(
            RM_entry
            for RM_entry in FIB_table(RM_ctx.state).FIB_entries()
            if str(RM_entry.destination) == "10.0.0.0/8"
        )
        self.assertEqual(
            {"192.168.211.1", "192.168.211.2"},
            {RM_route.next_hop for RM_route in RM_active},
        )
        self.assertEqual(
            {"192.168.211.1", "192.168.211.2"},
            {RM_entry.next_hop_ip for RM_entry in RM_fib_entries},
        )
        self.assertEqual(
            {"192.168.211.1", "192.168.211.2"},
            {
                FIB_table(RM_ctx.state).FIB_lookup(f"10.0.0.{RM_host}").next_hop_ip
                for RM_host in (1, 2)
            },
        )

    def test_static_default_route_accepts_dotted_mask_and_can_be_removed(self):
        RM_registry = CommandRegistry()
        RM_interfaces = (routing_ethernet("eth4", "192.168.211.100", 24),)

        def RM_refresh(RM_ctx):
            RM_table = RM_refresh_connected_routes_from_interfaces(
                RM_ctx,
                lambda RM_current_ctx: RM_interfaces,
            )
            FIB_sync_active_routes(RM_ctx.state, RM_table.RM_active_routes())

        RM_register_commands(
            RM_registry,
            RM_interfaces_provider=lambda RM_ctx: RM_interfaces,
            RM_after_route_change=RM_refresh,
        )
        RM_ctx = CliContext(output=__import__("io").StringIO())
        RM_ctx.push_mode("hidden")
        RM_registry.initialize_context(RM_ctx)

        RM_add = dispatch_line(
            RM_ctx,
            RM_registry,
            "ip route-static 0.0.0.0 0.0.0.0 192.168.211.1",
        )
        RM_remove = dispatch_line(
            RM_ctx,
            RM_registry,
            "no ip route-static 0.0.0.0 0 192.168.211.1",
        )

        self.assertTrue(RM_add.executed)
        self.assertTrue(RM_remove.executed)
        self.assertEqual((), RM_static_route_configs(RM_ctx.state))
        self.assertIsNone(RM_route_table(RM_ctx.state).RM_lookup("203.0.113.1"))
        self.assertNotIn("ip route-static", render_running_configuration(RM_ctx))

    def test_static_ethernet_route_requires_next_hop(self):
        RM_registry = CommandRegistry()
        RM_interfaces = (routing_ethernet("eth4", "192.168.211.100", 24),)
        RM_register_commands(
            RM_registry,
            RM_interfaces_provider=lambda RM_ctx: RM_interfaces,
        )
        RM_ctx = CliContext(output=__import__("io").StringIO())
        RM_ctx.push_mode("hidden")
        RM_registry.initialize_context(RM_ctx)

        RM_outcome = dispatch_line(
            RM_ctx,
            RM_registry,
            "ip route-static 10.0.0.0 8 eth4",
        )

        self.assertTrue(RM_outcome.executed)
        self.assertEqual(
            "% An Ethernet static route requires a next-hop address",
            RM_outcome.message,
        )
        self.assertEqual((), RM_static_route_configs(RM_ctx.state))

    def test_static_route_accepts_split_interface_type_and_number(self):
        RM_registry = CommandRegistry()
        RM_interfaces = (routing_ethernet("eth4", "192.168.211.100", 24),)
        RM_register_commands(
            RM_registry,
            RM_interfaces_provider=lambda RM_ctx: RM_interfaces,
            RM_after_route_change=lambda RM_ctx: RM_refresh_connected_routes_from_interfaces(
                RM_ctx,
                lambda RM_current_ctx: RM_interfaces,
            ),
        )
        RM_ctx = CliContext(output=__import__("io").StringIO())
        RM_ctx.push_mode("hidden")
        RM_registry.initialize_context(RM_ctx)

        RM_outcome = dispatch_line(
            RM_ctx,
            RM_registry,
            "ip route-static 10.0.0.0 8 eth 4 192.168.211.1",
        )

        self.assertTrue(RM_outcome.executed)
        RM_config = RM_static_route_configs(RM_ctx.state)[0]
        self.assertEqual("eth4", RM_config.interface_name)
        self.assertEqual("192.168.211.1", RM_config.next_hop)

    def test_static_null0_route_installs_black_hole_fib_entry(self):
        RM_registry = CommandRegistry()
        RM_interfaces = (
            NetworkInterface(
                name="NULL0",
                ifnet_index=0xFFFF,
                index=None,
                kind="null",
                is_up=True,
                mac_address="",
                mtu=1500,
                speed_mbps=None,
            ),
        )

        def RM_refresh(RM_ctx):
            RM_table = RM_refresh_connected_routes_from_interfaces(
                RM_ctx,
                lambda RM_current_ctx: RM_interfaces,
            )
            FIB_sync_active_routes(RM_ctx.state, RM_table.RM_active_routes())

        RM_register_commands(
            RM_registry,
            RM_interfaces_provider=lambda RM_ctx: RM_interfaces,
            RM_after_route_change=RM_refresh,
        )
        RM_ctx = CliContext(output=__import__("io").StringIO())
        RM_ctx.push_mode("hidden")
        RM_registry.initialize_context(RM_ctx)

        RM_outcome = dispatch_line(
            RM_ctx,
            RM_registry,
            "ip route-static 198.51.100.0 24 null0 no-advertise description discard",
        )

        self.assertTrue(RM_outcome.executed)
        RM_route = RM_route_table(RM_ctx.state).RM_lookup("198.51.100.1")
        self.assertIsNotNone(RM_route)
        self.assertEqual("NULL0", RM_route.interface.name)
        self.assertTrue(RM_route.no_advertise)
        RM_fib_entry = FIB_table(RM_ctx.state).FIB_lookup("198.51.100.1")
        self.assertIsNotNone(RM_fib_entry)
        self.assertEqual("B", RM_fib_entry.flags)

    def test_unresolved_static_route_keeps_configuration_without_entering_rib(self):
        RM_registry = CommandRegistry()
        RM_interfaces = (routing_ethernet("eth4", "192.168.211.100", 24),)
        RM_register_commands(
            RM_registry,
            RM_interfaces_provider=lambda RM_ctx: RM_interfaces,
            RM_after_route_change=lambda RM_ctx: RM_refresh_connected_routes_from_interfaces(
                RM_ctx,
                lambda RM_current_ctx: RM_interfaces,
            ),
        )
        RM_ctx = CliContext(output=__import__("io").StringIO())
        RM_ctx.push_mode("hidden")
        RM_registry.initialize_context(RM_ctx)

        RM_outcome = dispatch_line(
            RM_ctx,
            RM_registry,
            "ip route-static 10.0.0.0 8 203.0.113.1 permanent",
        )

        self.assertTrue(RM_outcome.executed)
        self.assertEqual(1, len(RM_static_route_configs(RM_ctx.state)))
        self.assertEqual((), RM_route_table(RM_ctx.state).RM_routes_for_source("static"))
        self.assertIn("permanent", render_running_configuration(RM_ctx))

    def test_saved_static_route_configuration_reloads_into_rm_state(self):
        RM_interfaces = (routing_ethernet("eth4", "192.168.211.100", 24),)
        RM_registry = CommandRegistry()
        RM_register_commands(
            RM_registry,
            RM_interfaces_provider=lambda RM_ctx: RM_interfaces,
            RM_after_route_change=lambda RM_ctx: RM_refresh_connected_routes_from_interfaces(
                RM_ctx,
                lambda RM_current_ctx: RM_interfaces,
            ),
        )

        with TemporaryDirectory() as RM_temp_dir:
            RM_path = Path(RM_temp_dir) / "saved-configuration"
            RM_ctx = CliContext(output=__import__("io").StringIO())
            RM_ctx.push_mode("hidden")
            RM_registry.initialize_context(RM_ctx)
            set_saved_configuration_path(RM_ctx, RM_path)
            dispatch_line(
                RM_ctx,
                RM_registry,
                "ip route-static 10.0.0.0 8 192.168.211.1 tag 88 description restored",
            )
            write_saved_configuration(RM_ctx)

            RM_reloaded_ctx = CliContext(output=__import__("io").StringIO())
            RM_registry.initialize_context(RM_reloaded_ctx)
            RM_errors = load_saved_configuration(RM_reloaded_ctx, RM_registry, RM_path)

        self.assertEqual([], RM_errors)
        RM_config = RM_static_route_configs(RM_reloaded_ctx.state)[0]
        self.assertEqual("10.0.0.0/8", str(RM_config.destination))
        self.assertEqual("192.168.211.1", RM_config.next_hop)
        self.assertEqual(88, RM_config.tag)
        self.assertEqual("restored", RM_config.description)

    def test_permanent_static_route_keeps_last_resolution_when_interface_fails(self):
        RM_registry = CommandRegistry()
        RM_interfaces = [routing_ethernet("eth4", "192.168.211.100", 24)]

        def RM_refresh(RM_ctx):
            RM_table = RM_refresh_connected_routes_from_interfaces(
                RM_ctx,
                lambda RM_current_ctx: tuple(RM_interfaces),
            )
            FIB_sync_active_routes(RM_ctx.state, RM_table.RM_active_routes())

        RM_register_commands(
            RM_registry,
            RM_interfaces_provider=lambda RM_ctx: tuple(RM_interfaces),
            RM_after_route_change=RM_refresh,
        )
        RM_ctx = CliContext(output=__import__("io").StringIO())
        RM_ctx.push_mode("hidden")
        RM_registry.initialize_context(RM_ctx)
        self.assertTrue(
            dispatch_line(
                RM_ctx,
                RM_registry,
                "ip route-static 10.0.0.0 8 192.168.211.1 permanent",
            ).executed
        )

        RM_interfaces[0] = replace(RM_interfaces[0], is_up=False)
        RM_refresh(RM_ctx)

        RM_route = RM_route_table(RM_ctx.state).RM_lookup("10.1.1.1")
        self.assertIsNotNone(RM_route)
        self.assertTrue(RM_route.permanent)
        self.assertIsNotNone(FIB_table(RM_ctx.state).FIB_lookup("10.1.1.1"))


def routing_ethernet(
    name: str,
    address: str = "192.168.211.100",
    prefix_length: int = 24,
) -> NetworkInterface:
    return NetworkInterface(
        name=name,
        ifnet_index=0,
        index=7,
        kind="ethernet",
        is_up=True,
        mac_address="00:E0:4C:11:22:33",
        mtu=1500,
        speed_mbps=1000,
        addresses=(InterfaceAddress(family="ipv4", address=address, prefix_length=prefix_length),),
    )


def routing_route(
    interface_name: str,
    destination: str,
    source_ip: str,
    *,
    source: str = "connected",
    preference: int = 0,
):
    from ipaddress import IPv4Network
    from src.RM import RMRoute

    return RMRoute(
        destination=IPv4Network(destination),
        source=source,
        interface=routing_ethernet(interface_name, source_ip),
        source_ip=source_ip,
        preference=preference,
    )


def routing_loopback(
    name: str,
    address: str = "10.10.10.1",
    prefix_length: int = 32,
) -> NetworkInterface:
    return NetworkInterface(
        name=name,
        ifnet_index=0,
        index=None,
        kind="loopback",
        is_up=True,
        mac_address="",
        mtu=1500,
        speed_mbps=None,
        addresses=(InterfaceAddress(family="ipv4", address=address, prefix_length=prefix_length),),
    )


if __name__ == "__main__":
    unittest.main()
