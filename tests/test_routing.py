from __future__ import annotations

import unittest

from src.DPlane.Windows.npcap import NpcapDevice
from src.FIB import FIB_resolve_forwarding
from src.IFNET import InterfaceAddress, NetworkInterface
from src.IFNET.imports import commit_imports, stage_import_interface
from src.IFNET.state import set_interface_addresses
from src.RM import RM_connected_routes, RM_lookup_route


class RoutingModuleTests(unittest.TestCase):
    def test_rm_builds_connected_routes_from_imported_interfaces(self):
        RM_state = {}
        stage_import_interface(RM_state, "eth4")
        commit_imports(RM_state)
        set_interface_addresses(
            RM_state,
            "eth4",
            (InterfaceAddress(family="ipv4", address="192.168.211.100", prefix_length=24),),
        )

        RM_routes = RM_connected_routes(RM_state, (routing_ethernet("eth4"), routing_ethernet("eth5"),))

        self.assertEqual(1, len(RM_routes))
        self.assertEqual("192.168.211.0/24", str(RM_routes[0].destination))
        self.assertEqual("connected", RM_routes[0].source)
        self.assertEqual("eth4", RM_routes[0].interface.name)
        self.assertEqual("192.168.211.100", RM_routes[0].source_ip)

    def test_rm_lookup_route_uses_longest_prefix_match(self):
        RM_state = {}
        stage_import_interface(RM_state, "eth4")
        stage_import_interface(RM_state, "eth5")
        commit_imports(RM_state)
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
        stage_import_interface(FIB_state, "eth4")
        commit_imports(FIB_state)
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


if __name__ == "__main__":
    unittest.main()
