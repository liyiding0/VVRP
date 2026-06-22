from __future__ import annotations

from typing import Literal

from VVRP.CCmd.models import CliContext

from .frame import ETHERTYPE_ARP, ETHERTYPE_IPV4, ETHERTYPE_IPV6, EthernetFrame


ETHERNET_FRAME_BRIEF_DEBUG_STATE_KEY = "ethernet.debug.frame_brief"
EthernetFrameDirection = Literal["rx", "tx"]


def is_ethernet_frame_brief_debug_enabled(ctx: CliContext) -> bool:
    return bool(ctx.state.get(ETHERNET_FRAME_BRIEF_DEBUG_STATE_KEY))


def set_ethernet_frame_brief_debug(ctx: CliContext, enabled: bool) -> None:
    ctx.state[ETHERNET_FRAME_BRIEF_DEBUG_STATE_KEY] = bool(enabled)


def debug_ethernet_frame(
    ctx: CliContext,
    interface_name: str,
    direction: EthernetFrameDirection,
    frame: EthernetFrame,
) -> None:
    if not is_ethernet_frame_brief_debug_enabled(ctx):
        return
    ctx.write(format_ethernet_frame_brief(interface_name, direction, frame))


def format_ethernet_frame_brief(
    interface_name: str,
    direction: EthernetFrameDirection,
    frame: EthernetFrame,
) -> str:
    return (
        "ETHERNET/FRAME: "
        f"{interface_name} "
        f"{direction.upper()} "
        f"dst={frame.destination} "
        f"src={frame.source} "
        f"type={_display_ethertype(frame.ethertype)} "
        f"len={len(frame.to_bytes())}"
    )


def _display_ethertype(ethertype: int) -> str:
    names = {
        ETHERTYPE_IPV4: "IPv4",
        ETHERTYPE_ARP: "ARP",
        ETHERTYPE_IPV6: "IPv6",
    }
    name = names.get(ethertype)
    if name is None:
        return f"0x{ethertype:04x}"
    return f"{name}(0x{ethertype:04x})"
