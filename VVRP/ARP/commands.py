from __future__ import annotations

import ipaddress
import time
from collections.abc import Sequence

from VVRP.CCmd.models import CommandResult
from VVRP.CCmd.registry import CommandRegistry

from .table import ArpEntry, ArpTable


ARP_TABLE_STATE_KEY = "arp.table"
ARP_SHOW_MODES = ("user", "privileged", "config", "hidden", "interface", "host-interface")
IPV4_ADDRESS_PATTERN = r"\d{1,3}(?:\.\d{1,3}){3}"
INTERFACE_NAME_PATTERN = r".+"


def register_arp_commands(
    registry: CommandRegistry,
    table: ArpTable | None = None,
    modes: Sequence[str] = ARP_SHOW_MODES,
) -> None:
    @registry.command(
        "show arp",
        help_text="Show ARP mapping table",
        modes=tuple(modes),
    )
    def show_arp(ctx, args):
        return CommandResult(message=_format_arp_entries(_arp_table(ctx, table).entries()))

    @registry.command(
        "show arp dynamic",
        help_text="Show dynamic ARP entries",
        modes=tuple(modes),
    )
    def show_arp_dynamic(ctx, args):
        entries = tuple(entry for entry in _arp_table(ctx, table).entries() if entry.entry_type == "dynamic")
        return CommandResult(message=_format_arp_entries(entries))

    @registry.command(
        "show arp static",
        help_text="Show static ARP entries",
        modes=tuple(modes),
    )
    def show_arp_static(ctx, args):
        entries = tuple(entry for entry in _arp_table(ctx, table).entries() if entry.entry_type == "static")
        return CommandResult(message=_format_arp_entries(entries))

    @registry.command(
        f"show arp interface <name:{INTERFACE_NAME_PATTERN}>",
        help_text="Show ARP entries for an interface",
        modes=tuple(modes),
    )
    def show_arp_interface(ctx, args):
        name = args["name"]
        entries = tuple(entry for entry in _arp_table(ctx, table).entries() if entry.interface_name == name)
        return CommandResult(message=_format_arp_entries(entries))

    @registry.command(
        f"show arp <ip_address:{IPV4_ADDRESS_PATTERN}>",
        help_text="Show ARP entries for an IPv4 address",
        modes=tuple(modes),
    )
    def show_arp_ip(ctx, args):
        ip_address = _normalize_ipv4_address(args["ip_address"])
        if ip_address is None:
            return CommandResult(ok=False, message=f"% Invalid IPv4 address: {args['ip_address']}")
        entries = tuple(entry for entry in _arp_table(ctx, table).entries() if entry.ip_address == ip_address)
        return CommandResult(message=_format_arp_entries(entries))

    @registry.context_initializer
    def initialize_arp(ctx):
        _arp_table(ctx, table)


def get_arp_table(state: dict, table: ArpTable | None = None) -> ArpTable:
    if table is not None:
        return table
    value = state.get(ARP_TABLE_STATE_KEY)
    if isinstance(value, ArpTable):
        return value
    value = ArpTable()
    state[ARP_TABLE_STATE_KEY] = value
    return value


def _arp_table(ctx, table: ArpTable | None) -> ArpTable:
    return get_arp_table(ctx.state, table)


def _format_arp_entries(entries: tuple[ArpEntry, ...]) -> str:
    if not entries:
        return "ARP entry not found"

    now = time.time()
    lines = [
        "IP ADDRESS      MAC ADDRESS        EXPIRE(M) TYPE        INTERFACE",
    ]
    for entry in entries:
        lines.append(
            f"{entry.ip_address:<15} "
            f"{entry.mac_address:<18} "
            f"{_display_expire_minutes(entry, now):>9} "
            f"{entry.entry_type:<11} "
            f"{entry.interface_name}"
        )
    return "\n".join(lines)


def _display_expire_minutes(entry: ArpEntry, now: float) -> str:
    if entry.entry_type == "static":
        return "-"
    remaining = max(0, int((entry.updated_at + entry.age_seconds - now) / 60))
    return str(remaining)


def _normalize_ipv4_address(value: str) -> str | None:
    try:
        return str(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError:
        return None
