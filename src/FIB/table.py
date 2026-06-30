from __future__ import annotations

from dataclasses import dataclass, field, replace
from ipaddress import IPv4Address

from src.IFNET.models import NetworkInterface

from .models import FIBEntry, FIB_InstallRequest


g_FIB_TABLE_STATE_KEY = "fib.table"


@dataclass
class FIB_Table:
    _FIB_entries: dict[str, FIBEntry] = field(default_factory=dict)

    def FIB_install(self, FIB_entry: FIBEntry) -> None:
        self._FIB_entries[FIB_entry_key(FIB_entry)] = FIB_entry

    def FIB_delete(self, FIB_destination) -> None:
        for FIB_key, FIB_entry in tuple(self._FIB_entries.items()):
            if str(FIB_entry.destination) == str(FIB_destination):
                self._FIB_entries.pop(FIB_key, None)

    def FIB_entries(self) -> tuple[FIBEntry, ...]:
        return tuple(
            self._FIB_entries[FIB_key]
            for FIB_key in sorted(
                self._FIB_entries,
                key=lambda FIB_key: (
                    int(self._FIB_entries[FIB_key].destination.network_address),
                    self._FIB_entries[FIB_key].destination.prefixlen,
                    self._FIB_entries[FIB_key].next_hop_ip,
                    self._FIB_entries[FIB_key].out_if_name,
                ),
            )
        )

    def FIB_lookup(self, FIB_destination_ip: str) -> FIBEntry | None:
        FIB_destination = IPv4Address(FIB_destination_ip)
        FIB_candidates = tuple(
            FIB_entry
            for FIB_entry in self._FIB_entries.values()
            if FIB_destination in FIB_entry.destination
        )
        if not FIB_candidates:
            return None
        FIB_prefix_length = max(FIB_entry.destination.prefixlen for FIB_entry in FIB_candidates)
        FIB_best = tuple(sorted(
            (
                FIB_entry
                for FIB_entry in FIB_candidates
                if FIB_entry.destination.prefixlen == FIB_prefix_length
            ),
            key=lambda FIB_entry: (
                FIB_entry.next_hop_ip,
                FIB_entry.out_if_name,
                FIB_entry.out_if_index if FIB_entry.out_if_index is not None else -1,
            ),
        ))
        return FIB_best[int(FIB_destination) % len(FIB_best)]


def FIB_table(FIB_state: dict) -> FIB_Table:
    FIB_existing = FIB_state.get(g_FIB_TABLE_STATE_KEY)
    if isinstance(FIB_existing, FIB_Table):
        return FIB_existing
    FIB_existing = FIB_Table()
    FIB_state[g_FIB_TABLE_STATE_KEY] = FIB_existing
    return FIB_existing


def FIB_entry_key(FIB_entry: FIBEntry) -> str:
    return (
        f"{FIB_entry.destination}|{FIB_entry.next_hop_ip}|"
        f"{FIB_entry.out_if_name}|{FIB_entry.out_if_index}"
    )


def FIB_request_key(FIB_request: FIB_InstallRequest) -> str:
    return (
        f"{FIB_request.destination}|{FIB_request.next_hop_ip}|"
        f"{FIB_request.out_if_name}|{FIB_request.out_if_index}"
    )


def FIB_entry_from_request(
    FIB_request: FIB_InstallRequest,
    *,
    FIB_installed_at: float | None = None,
) -> FIBEntry | None:
    FIB_values = dict(
        destination=FIB_request.destination,
        out_if_name=FIB_request.out_if_name,
        out_if_index=FIB_request.out_if_index,
        source_ip=FIB_request.source_ip,
        source_mac=FIB_request.source_mac,
        next_hop_ip=FIB_request.next_hop_ip,
        mtu=FIB_request.mtu,
        flags=FIB_request.flags,
    )
    if FIB_installed_at is not None:
        FIB_values["installed_at"] = FIB_installed_at
    return FIBEntry(**FIB_values)


def FIB_install_request(
    FIB_state: dict,
    FIB_request: FIB_InstallRequest,
    *,
    FIB_installed_at: float | None = None,
) -> FIBEntry | None:
    FIB_entry = FIB_entry_from_request(
        FIB_request,
        FIB_installed_at=FIB_installed_at,
    )
    if FIB_entry is None:
        return None
    FIB_table(FIB_state).FIB_install(FIB_entry)
    return FIB_entry


def FIB_sync_active_routes(
    FIB_state: dict,
    FIB_routes: tuple,
    *FIB_ignored_legacy_args,
) -> FIB_Table:
    FIB_previous_entries = {
        FIB_entry_key(FIB_entry): FIB_entry
        for FIB_entry in FIB_table(FIB_state).FIB_entries()
    }
    FIB_active_table = FIB_Table()
    FIB_state[g_FIB_TABLE_STATE_KEY] = FIB_active_table
    for FIB_route in FIB_routes:
        FIB_request = FIB_install_request_from_route(FIB_route)
        FIB_previous = FIB_previous_entries.get(FIB_request_key(FIB_request))
        FIB_installed_at = None
        if FIB_previous is not None and _FIB_request_matches_entry(FIB_request, FIB_previous):
            FIB_installed_at = FIB_previous.installed_at
        FIB_install_request(
            FIB_state,
            FIB_request,
            FIB_installed_at=FIB_installed_at,
        )
    return FIB_active_table


def FIB_resolve_forwarding(
    FIB_state: dict,
    FIB_host_interfaces: tuple[NetworkInterface, ...],
    FIB_packet_devices: tuple,
    FIB_destination_ip: str,
) -> FIBEntry | None:
    FIB_entry = FIB_table(FIB_state).FIB_lookup(FIB_destination_ip)
    if FIB_entry is None or FIB_entry.next_hop_ip:
        return FIB_entry
    return replace(FIB_entry, next_hop_ip=FIB_destination_ip)


def FIB_install_request_from_route(FIB_route) -> FIB_InstallRequest:
    FIB_is_local_host = (
        FIB_route.destination.prefixlen == 32
        and FIB_route.next_hop == "127.0.0.1"
    )
    FIB_out_if_name = "InLoopBack0" if FIB_is_local_host else FIB_route.interface.name
    FIB_out_if_index = (
        0
        if FIB_is_local_host
        else getattr(FIB_route.interface, "ifnet_index", None)
    )
    return FIB_InstallRequest(
        destination=FIB_route.destination,
        out_if_name=FIB_out_if_name,
        out_if_index=FIB_out_if_index,
        source_ip=FIB_route.source_ip,
        source_mac="" if FIB_is_local_host else FIB_route.interface.mac_address,
        next_hop_ip=FIB_route.next_hop or "",
        mtu=FIB_route.interface.mtu,
        flags=_FIB_route_flags(FIB_route, FIB_is_local_host),
    )


def _FIB_route_flags(FIB_route, FIB_is_local_host: bool) -> str:
    if FIB_is_local_host:
        return "HU"
    if getattr(FIB_route.interface, "kind", "") == "null":
        return "B"
    if FIB_route.source == "connected":
        return "U"
    FIB_flags = "G" if FIB_route.next_hop else ""
    if FIB_route.source == "static":
        FIB_flags += "S"
    elif FIB_route.source == "dynamic":
        FIB_flags += "D"
    return FIB_flags or "U"


def _FIB_request_matches_entry(
    FIB_request: FIB_InstallRequest,
    FIB_entry: FIBEntry,
) -> bool:
    return (
        FIB_request.destination == FIB_entry.destination
        and FIB_request.out_if_name == FIB_entry.out_if_name
        and FIB_request.out_if_index == FIB_entry.out_if_index
        and FIB_request.source_ip == FIB_entry.source_ip
        and FIB_request.source_mac == FIB_entry.source_mac
        and FIB_request.next_hop_ip == FIB_entry.next_hop_ip
        and FIB_request.mtu == FIB_entry.mtu
        and FIB_request.flags == FIB_entry.flags
    )
