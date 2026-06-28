from __future__ import annotations

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
        "Route Flags: G - gateway route, H - host route,    U - up route",
        "             S - static route,  D - dynamic route, B - black hole route",
        "------------------------------------------------------------------------------",
        f"{'Destination/Mask':<19} {'Nexthop':<15} {'Flag':<5} {'TimeStamp':<10} {'Interface':<16} TunnelID",
    ]
    if not FIB_entries:
        FIB_lines.append("No FIB entries found")
        return "\n".join(FIB_lines)
    for FIB_entry in sorted(
        FIB_entries,
        key=lambda FIB_entry: (
            int(FIB_entry.destination.network_address),
            FIB_entry.destination.prefixlen,
            FIB_entry.out_if_name,
        ),
    ):
        FIB_lines.append(
            f"{str(FIB_entry.destination):<19} "
            f"{FIB_entry.next_hop_ip:<15} "
            f"{FIB_entry.flags:<5} "
            f"{'0':<10} "
            f"{FIB_entry.out_if_name:<16} "
            "0x0"
        )
    return "\n".join(FIB_lines)
