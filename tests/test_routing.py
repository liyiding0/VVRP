from __future__ import annotations

import unittest

from src.DPlane.Windows.npcap import NpcapDevice
from src.FIB import FIB_resolve_forwarding, FIB_sync_active_routes, FIB_table
from src.IFNET import InterfaceAddress, NetworkInterface
from src.RM.IM import (
    RM_IM_InterfaceAddressAdded,
    RM_IM_InterfaceChanged,
    RM_IM_InterfaceTable,
    RM_IM_register_event_handlers,
)
from src.events import VVRP_EventBus
from src.IP.state import IP_set_interface_addresses
from src.RM import (
    RM_RouteTable,
    RM_connected_routes,
    RM_connected_routes_from_im,
    RM_lookup_route,
    RM_register_commands,
    RM_register_route_event_handlers,
    RM_route_table,
    RM_route_table_from_im,
)
from src.CCmd import CliContext, CommandRegistry, dispatch_line


class RoutingModuleTests(unittest.TestCase):
    def test_rm_builds_connected_routes_from_ifnet_interfaces_without_import_state(self):
        RM_state = {}
        IP_set_interface_addresses(
            RM_state,
            "eth4",
            (InterfaceAddress(family="ipv4", address="192.168.211.100", prefix_length=24),),
        )

        RM_routes = RM_connected_routes(RM_state, (routing_ethernet("eth4"),))

        self.assertEqual(1, len(RM_routes))
        self.assertEqual("192.168.211.0/24", str(RM_routes[0].destination))
        self.assertEqual("connected", RM_routes[0].source)
        self.assertEqual("eth4", RM_routes[0].interface.name)
        self.assertEqual("192.168.211.100", RM_routes[0].source_ip)

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

        self.assertEqual(1, len(RM_routes))
        self.assertEqual("192.168.211.0/24", str(RM_routes[0].destination))
        self.assertEqual("eth4", RM_routes[0].interface.name)

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
        self.assertEqual(1, len(RM_active_routes))
        self.assertEqual("connected", RM_active_routes[0].source)
        self.assertEqual("192.168.211.0/24", str(RM_active_routes[0].destination))
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
        self.assertIn("Destination/Mask", RM_text)
        self.assertIn("192.168.211.0/24", RM_text)
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
        RM_text = RM_output.getvalue()
        self.assertIn("Route Flags: R - relay, D - download to fib", RM_text)
        self.assertIn("Routing Tables: Public", RM_text)
        self.assertIn("Destination/Mask", RM_text)
        self.assertIn("192.168.211.0/24", RM_text)
        self.assertIn("Direct", RM_text)
        self.assertIn("192.168.211.100", RM_text)
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
        self.assertIn("1.1.1.0/24", RM_text)
        self.assertIn("eth4", RM_text)

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
        self.assertIn("192.168.211.0/24", RM_output.getvalue())

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
