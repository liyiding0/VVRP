from __future__ import annotations

import time

from src.CMD.models import CommandResult
from src.CMD.registry import CommandRegistry

from .models import FIBEntry
from .table import FIB_table


g_FIB_IPV4_ADDRESS_PATTERN = r"(?:\d{1,3}\.){3}\d{1,3}"
g_FIB_SHOW_MODES = ("user", "privileged", "config", "interface", "host-interface", "hidden")


def FIB_register_commands(
    FIB_registry: CommandRegistry,
    FIB_modes=g_FIB_SHOW_MODES,
) -> None:
    @FIB_registry.command(
        "show fib",
        help_text="Show IPv4 FIB entries",
        modes=tuple(FIB_modes),
    )
    def FIB_show_fib(FIB_ctx, FIB_args):
        return CommandResult(message=FIB_format_entries(FIB_table(FIB_ctx.state).FIB_entries()))

    @FIB_registry.command(
        f"show fib <ip:{g_FIB_IPV4_ADDRESS_PATTERN}>",
        help_text="Show IPv4 FIB entry for a destination",
        modes=tuple(FIB_modes),
    )
    def FIB_show_fib_ip(FIB_ctx, FIB_args):
        FIB_entry = FIB_table(FIB_ctx.state).FIB_lookup(FIB_args["ip"])
        if FIB_entry is None:
            return CommandResult(message="% FIB entry not found")
        return CommandResult(message=FIB_format_entries((FIB_entry,)))


def FIB_format_entries(FIB_entries: tuple[FIBEntry, ...]) -> str:
    FIB_lines = [
        "Route Flags: G - Gateway Route, H - Host Route,    U - Up Route",
        "             S - Static Route,  D - Dynamic Route, B - Black Hole Route",
        "--------------------------------------------------------------------------------",
        " FIB Table:",
        f" Total number of Routes : {len(FIB_entries)} ",
        "",
        f"{'Destination/Mask':<18} {'Nexthop':<15} {'Flag':<5} {'TimeStamp':<13} {'Interface':<14} TunnelID",
    ]
    if not FIB_entries:
        FIB_lines.append("No FIB entries found")
        return "\n".join(FIB_lines)
    FIB_now = time.monotonic()
    for FIB_entry in sorted(
        FIB_entries,
        key=lambda FIB_entry: (
            int(FIB_entry.destination.network_address),
            FIB_entry.destination.prefixlen,
            FIB_entry.out_if_name,
        ),
    ):
        FIB_lines.append(
            f"{str(FIB_entry.destination):<18} "
            f"{_FIB_display_next_hop(FIB_entry):<15} "
            f"{FIB_entry.flags:<5} "
            f"{_FIB_display_timestamp(FIB_entry, FIB_now):<13} "
            f"{_FIB_display_interface(FIB_entry.out_if_name):<14} "
            "0x0"
        )
    return "\n".join(FIB_lines)


def _FIB_display_next_hop(FIB_entry: FIBEntry) -> str:
    return FIB_entry.next_hop_ip or FIB_entry.source_ip


def _FIB_display_timestamp(FIB_entry: FIBEntry, FIB_now: float) -> str:
    return f"t[{max(0, int(FIB_now - FIB_entry.installed_at))}]"


def _FIB_display_interface(FIB_interface_name: str) -> str:
    if FIB_interface_name.startswith("Ethernet"):
        return f"Eth{FIB_interface_name[len('Ethernet'):]}"
    return FIB_interface_name
