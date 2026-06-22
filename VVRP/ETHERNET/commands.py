from __future__ import annotations

from collections.abc import Callable, Sequence

from VVRP.CCmd.models import CliContext, CommandResult
from VVRP.CCmd.registry import CommandRegistry

from .debug import is_ethernet_frame_brief_debug_enabled, set_ethernet_frame_brief_debug


ETHERNET_DEBUG_MODES = ("privileged", "config", "hidden", "interface", "host-interface")


def register_ethernet_commands(
    registry: CommandRegistry,
    modes: Sequence[str] = ETHERNET_DEBUG_MODES,
    frame_debug_start: Callable[[CliContext], str] | None = None,
    frame_debug_stop: Callable[[], str] | None = None,
    frame_debug_status: Callable[[], str] | None = None,
) -> None:
    @registry.command(
        "debugging ethernet frame brief",
        help_text="Enable brief Ethernet frame debugging",
        modes=tuple(modes),
    )
    def debugging_ethernet_frame_brief(ctx, args):
        set_ethernet_frame_brief_debug(ctx, True)
        detail = _call_frame_debug_start(ctx, frame_debug_start)
        if detail:
            return CommandResult(message=f"Ethernet frame brief debugging is on ({detail})")
        return CommandResult(message="Ethernet frame brief debugging is on")

    @registry.command(
        "no debugging ethernet frame brief",
        help_text="Disable brief Ethernet frame debugging",
        modes=tuple(modes),
    )
    def no_debugging_ethernet_frame_brief(ctx, args):
        set_ethernet_frame_brief_debug(ctx, False)
        detail = _call_frame_debug_stop(frame_debug_stop)
        if detail:
            return CommandResult(message=f"Ethernet frame brief debugging is off ({detail})")
        return CommandResult(message="Ethernet frame brief debugging is off")

    @registry.command(
        "show debugging ethernet",
        help_text="Show Ethernet debugging switches",
        modes=tuple(modes),
    )
    def show_debugging_ethernet(ctx, args):
        state = "on" if is_ethernet_frame_brief_debug_enabled(ctx) else "off"
        detail = frame_debug_status() if frame_debug_status is not None else ""
        if detail:
            return CommandResult(message=f"Ethernet frame brief debugging is {state} ({detail})")
        return CommandResult(message=f"Ethernet frame brief debugging is {state}")


def _call_frame_debug_start(ctx: CliContext, callback: Callable[[CliContext], str] | None) -> str:
    if callback is None:
        return ""
    try:
        return callback(ctx)
    except RuntimeError as exc:
        return f"listener start failed: {exc}"


def _call_frame_debug_stop(callback: Callable[[], str] | None) -> str:
    if callback is None:
        return ""
    return callback()
