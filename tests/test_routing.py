from __future__ import annotations

import unittest

from src.DPlane.Windows.npcap import NpcapDevice
from src.FIB import FIB_resolve_forwarding
from src.IFNET import InterfaceAddress, NetworkInterface
from src.RM.IM import (
    RM_IM_InterfaceAddressAdded,
    RM_IM_InterfaceChanged,
    RM_IM_InterfaceTable,
    RM_IM_register_event_handlers,
)
from src.events import VVRP_EventBus
from src.IFNET.state import set_interface_addresses
from src.RM import RM_connected_routes, RM_connected_routes_from_im, RM_lookup_route, RM_register_commands
from src.CCmd import CliContext, CommandRegistry, dispatch_line


class RoutingModuleTests(unittest.TestCase):
    def test_rm_builds_connected_routes_from_ifnet_interfaces_without_import_state(self):
        RM_state = {}
        set_interface_addresses(
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

    def test_rm_lookup_route_uses_longest_prefix_match(self):
        RM_state = {}
        set_interface_addresses(
            RM_state,
            "eth4",
            (InterfaceAddress(family="ipv4", address="192.168.211.100", prefix_length=24),),
        )
        set_interface_addresses(
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

    def test_fib_resolves_route_to_npcap_device(self):
        FIB_state = {}
        set_interface_addresses(
            FIB_state,
            "eth4",
            (InterfaceAddress(family="ipv4", address="192.168.211.100", prefix_length=24),),
        )

        FIB_entry = FIB_resolve_forwarding(
            FIB_state,
            (routing_ethernet("eth4"),),
            (NpcapDevice(name=r"\Device\NPF_eth4", description="eth4"),),
            "192.168.211.1",
        )

        self.assertIsNotNone(FIB_entry)
        self.assertEqual("eth4", FIB_entry.interface.name)
        self.assertEqual("192.168.211.100", FIB_entry.source_ip)
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
        os_id=name,
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
        os_id=name,
    )


if __name__ == "__main__":
    unittest.main()
