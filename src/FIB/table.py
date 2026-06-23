from __future__ import annotations

from dataclasses import dataclass, field, replace
from ipaddress import IPv4Address

from src.DPlane import DPlane_Backend, DPlane_ForwardingEntry, DPlane_PacketDevice
from src.IFNET.models import NetworkInterface

from .models import FIBEntry, FIB_InstallRequest


g_FIB_TABLE_STATE_KEY = "fib.table"


@dataclass
class FIB_Table:
    _FIB_entries: dict[str, FIBEntry] = field(default_factory=dict)

    def FIB_install(self, FIB_entry: FIBEntry) -> None:
        self._FIB_entries[FIB_entry_key(FIB_entry)] = FIB_entry

    def FIB_delete(self, FIB_destination) -> None:
        self._FIB_entries.pop(str(FIB_destination), None)

    def FIB_entries(self) -> tuple[FIBEntry, ...]:
        return tuple(
            self._FIB_entries[FIB_key]
            for FIB_key in sorted(
                self._FIB_entries,
                key=lambda FIB_key: (
                    int(self._FIB_entries[FIB_key].destination.network_address),
                    self._FIB_entries[FIB_key].destination.prefixlen,
                ),
            )
        )

    def FIB_lookup(self, FIB_destination_ip: str) -> FIBEntry | None:
        FIB_destination = IPv4Address(FIB_destination_ip)
        FIB_candidates = (
            FIB_entry
            for FIB_entry in self._FIB_entries.values()
            if FIB_destination in FIB_entry.destination
        )
        return max(FIB_candidates, key=lambda FIB_entry: FIB_entry.destination.prefixlen, default=None)


def FIB_table(FIB_state: dict) -> FIB_Table:
    FIB_existing = FIB_state.get(g_FIB_TABLE_STATE_KEY)
    if isinstance(FIB_existing, FIB_Table):
        return FIB_existing
    FIB_existing = FIB_Table()
    FIB_state[g_FIB_TABLE_STATE_KEY] = FIB_existing
    return FIB_existing


def FIB_entry_key(FIB_entry: FIBEntry) -> str:
    return str(FIB_entry.destination)


def FIB_entry_from_request(
    FIB_request: FIB_InstallRequest,
    FIB_devices: tuple[DPlane_PacketDevice, ...],
    FIB_device_resolver=None,
) -> FIBEntry | None:
    FIB_device = None
    if FIB_device_resolver is not None:
        FIB_device = FIB_device_resolver(FIB_request)
    if FIB_device is None:
        FIB_device = FIB_find_device_for_request(FIB_request, FIB_devices)
    if FIB_device is None:
        return None
    return FIBEntry(
        destination=FIB_request.destination,
        out_if_name=FIB_request.out_if_name,
        out_if_index=FIB_request.out_if_index,
        source_ip=FIB_request.source_ip,
        source_mac=FIB_request.source_mac,
        next_hop_ip=FIB_request.next_hop_ip,
        mtu=FIB_request.mtu,
        flags=FIB_request.flags,
        device=FIB_device,
    )


def FIB_install_request(
    FIB_state: dict,
    FIB_request: FIB_InstallRequest,
    FIB_devices: tuple[DPlane_PacketDevice, ...],
    FIB_backend: DPlane_Backend | None = None,
    FIB_device_resolver=None,
) -> FIBEntry | None:
    FIB_entry = FIB_entry_from_request(FIB_request, FIB_devices, FIB_device_resolver)
    if FIB_entry is None:
        return None
    FIB_table(FIB_state).FIB_install(FIB_entry)
    if FIB_backend is not None:
        FIB_backend.DPlane_install_forwarding_entry(FIB_dplane_entry(FIB_entry))
    return FIB_entry


def FIB_sync_active_routes(
    FIB_state: dict,
    FIB_routes: tuple,
    FIB_devices: tuple[DPlane_PacketDevice, ...],
    FIB_backend: DPlane_Backend | None = None,
    FIB_device_resolver=None,
) -> FIB_Table:
    FIB_active_table = FIB_table(FIB_state)
    for FIB_existing in FIB_active_table.FIB_entries():
        if FIB_backend is not None:
            FIB_backend.DPlane_delete_forwarding_entry(FIB_dplane_entry(FIB_existing))
    FIB_state[g_FIB_TABLE_STATE_KEY] = FIB_Table()
    FIB_active_table = FIB_table(FIB_state)
    for FIB_route in FIB_routes:
        FIB_install_request(
            FIB_state,
            FIB_install_request_from_route(FIB_route),
            FIB_devices,
            FIB_backend,
            FIB_device_resolver,
        )
    return FIB_active_table


def FIB_resolve_forwarding(
    FIB_state: dict,
    FIB_host_interfaces: tuple[NetworkInterface, ...],
    FIB_packet_devices: tuple[DPlane_PacketDevice, ...],
    FIB_destination_ip: str,
) -> FIBEntry | None:
    FIB_entry = FIB_table(FIB_state).FIB_lookup(FIB_destination_ip)
    if FIB_entry is None or FIB_entry.next_hop_ip:
        return FIB_entry
    return replace(FIB_entry, next_hop_ip=FIB_destination_ip)


def FIB_dplane_entry(FIB_entry: FIBEntry) -> DPlane_ForwardingEntry:
    return DPlane_ForwardingEntry(
        destination=FIB_entry.destination,
        interface_name=FIB_entry.out_if_name,
        source_ip=FIB_entry.source_ip,
        next_hop_ip=FIB_entry.next_hop_ip,
        device_name=FIB_entry.device.name,
    )


def FIB_install_request_from_route(FIB_route) -> FIB_InstallRequest:
    return FIB_InstallRequest(
        destination=FIB_route.destination,
        out_if_name=FIB_route.interface.name,
        out_if_index=getattr(FIB_route.interface, "ifnet_index", None),
        source_ip=FIB_route.source_ip,
        source_mac=FIB_route.interface.mac_address,
        next_hop_ip=FIB_route.next_hop or "",
        mtu=FIB_route.interface.mtu,
        flags="D",
    )


def FIB_find_device_for_request(
    FIB_request: FIB_InstallRequest,
    FIB_devices: tuple[DPlane_PacketDevice, ...],
) -> DPlane_PacketDevice | None:
    FIB_names = {FIB_request.out_if_name.lower()}
    for FIB_device in FIB_devices:
        FIB_device_names = {
            FIB_device.name.lower(),
            FIB_device.description.lower(),
        }
        FIB_device_names.add(FIB_device.name.lower().removeprefix(r"\device\npf_"))
        if FIB_names & FIB_device_names:
            return FIB_device
    return None
