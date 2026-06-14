from __future__ import annotations

from collections.abc import Sequence

from VVRP.CCmd.models import CommandResult
from VVRP.CCmd.registry import CommandRegistry

from .ping import PING_TARGET_PATTERN, run_ping


DEFAULT_IP_COMMAND_MODES = ("user", "privileged", "config", "interface", "hidden")


def register_ip_commands(
    registry: CommandRegistry,
    modes: Sequence[str] = DEFAULT_IP_COMMAND_MODES,
) -> None:
    @registry.command(
        f"ping <target:{PING_TARGET_PATTERN}>",
        help_text="Ping an IPv4, IPv6, hostname, or domain",
        modes=tuple(modes),
    )
    def ping(ctx, args):
        result = run_ping(args["target"])
        return CommandResult(ok=result.ok, message=result.message)
