from __future__ import annotations

from VVRP.IFNET import register_ifnet_commands
from VVRP.IFNET.commands import INTERFACE_NAME_PATTERN
from VVRP.IP import register_ip_commands

from .models import CommandResult
from .parser import CommandParser
from .registry import CommandRegistry


USER_MODES = ("user", "privileged")
SHOW_MODES = ("user", "privileged", "config")
ALL_MODES = ("user", "privileged", "config", "interface", "hidden")
HIDDEN_ENTRY_MODES = ("user", "privileged", "config", "interface")


def build_default_registry() -> CommandRegistry:
    registry = CommandRegistry()

    @registry.command("show", help_text="Show command group", modes=SHOW_MODES)
    def show(ctx, args):
        candidates = CommandParser(registry).help_candidates("show ", mode=ctx.mode)
        if not candidates:
            return CommandResult(message="No show commands available")

        lines = ["Available show commands:"]
        for candidate in candidates:
            lines.append(f"  {candidate.display:<16} {candidate.help_text}".rstrip())
        return CommandResult(message="\n".join(lines))

    @registry.command("show version", help_text="Show software version", modes=USER_MODES)
    def show_version(ctx, args):
        return CommandResult(message="VVRP CCmd version 0.1.0")

    register_ifnet_commands(registry, modes=ALL_MODES)
    register_ip_commands(registry, modes=ALL_MODES)

    @registry.command(
        "show hostname",
        help_text="Show current hostname",
        modes=("privileged", "config"),
    )
    def show_hostname(ctx, args):
        return CommandResult(message=ctx.hostname)

    @registry.command("enable", help_text="Enter privileged mode", modes=("user",))
    def enable(ctx, args):
        ctx.push_mode("privileged")
        return CommandResult()

    @registry.command("config", help_text="Enter global configuration mode", modes=("privileged",))
    def config(ctx, args):
        ctx.push_mode("config")
        return CommandResult()

    @registry.command(
        "hostname <name:[A-Za-z][A-Za-z0-9_-]{0,62}>",
        help_text="Set device hostname",
        modes=("config",),
    )
    def hostname(ctx, args):
        ctx.hostname = args["name"]
        return CommandResult()

    @registry.command(
        f"interface <name:{INTERFACE_NAME_PATTERN}>",
        help_text="Enter interface configuration mode",
        modes=("config",),
    )
    def interface(ctx, args):
        ctx.push_mode("interface", args["name"])
        return CommandResult()

    @registry.command(
        "_",
        help_text="Enter hidden mode",
        modes=HIDDEN_ENTRY_MODES,
        hidden=True,
    )
    def hidden(ctx, args):
        ctx.push_mode("hidden")
        return CommandResult()

    @registry.command("help", help_text="Show available commands", modes=ALL_MODES)
    def help_command(ctx, args):
        lines = [f"Available commands in {ctx.mode} mode:"]
        for command in registry.commands_for_mode(ctx.mode):
            lines.append(f"  {command.canonical:<36} {command.help_text}")
        return CommandResult(message="\n".join(lines))

    @registry.command(
        "quit",
        help_text="Return to previous mode",
        modes=("privileged", "config", "interface", "hidden"),
    )
    def quit_command(ctx, args):
        ctx.quit_mode()
        return CommandResult()

    @registry.command("exit", help_text="Exit CLI", modes=ALL_MODES)
    def exit_command(ctx, args):
        return CommandResult(message="Bye.", exit_requested=True)

    return registry
