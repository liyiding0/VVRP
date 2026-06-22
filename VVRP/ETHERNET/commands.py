from __future__ import annotations

from collections.abc import Sequence

from VVRP.CCmd.models import CommandResult
from VVRP.CCmd.registry import CommandRegistry

from .debug import is_ethernet_frame_brief_debug_enabled, set_ethernet_frame_brief_debug


ETHERNET_DEBUG_MODES = ("privileged", "config", "hidden", "interface", "host-interface")


def register_ethernet_commands(
    registry: CommandRegistry,
    modes: Sequence[str] = ETHERNET_DEBUG_MODES,
) -> None:
    @registry.command(
        "debugging ethernet frame brief",
        help_text="Enable brief Ethernet frame debugging",
        modes=tuple(modes),
    )
    def debugging_ethernet_frame_brief(ctx, args):
        set_ethernet_frame_brief_debug(ctx, True)
        return CommandResult(message="Ethernet frame brief debugging is on")

    @registry.command(
        "no debugging ethernet frame brief",
        help_text="Disable brief Ethernet frame debugging",
        modes=tuple(modes),
    )
    def no_debugging_ethernet_frame_brief(ctx, args):
        set_ethernet_frame_brief_debug(ctx, False)
        return CommandResult(message="Ethernet frame brief debugging is off")

    @registry.command(
        "show debugging ethernet",
        help_text="Show Ethernet debugging switches",
        modes=tuple(modes),
    )
    def show_debugging_ethernet(ctx, args):
        state = "on" if is_ethernet_frame_brief_debug_enabled(ctx) else "off"
        return CommandResult(message=f"Ethernet frame brief debugging is {state}")
