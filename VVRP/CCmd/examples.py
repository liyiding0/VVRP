from __future__ import annotations

from VVRP.DPlane import register_dplane_commands
from VVRP.DPlane.Windows.npcap import NpcapLibrary
from VVRP.IFNET import register_ifnet_commands
from VVRP.IFNET.admin import InterfaceAdminProvider
from VVRP.IFNET.discovery import InterfaceProvider
from VVRP.IP import register_ip_commands
from VVRP.IP.dhcp import DhcpClientProvider
from VVRP.IP.static import StaticIpv4Provider

from .models import CommandResult
from .parser import CommandParser
from .registry import CommandRegistry
from .running_config import (
    read_saved_configuration,
    render_running_configuration,
    set_global_config_command,
    write_saved_configuration,
)


USER_MODES = ("user", "privileged")
SHOW_MODES = ("user", "privileged", "config", "hidden", "host-interface")
ALL_MODES = ("user", "privileged", "config", "interface", "hidden", "host-interface")
HIDDEN_ENTRY_MODES = ("user", "privileged", "config", "interface", "host-interface")


def build_default_registry(
    ifnet_provider: InterfaceProvider | None = None,
    ifnet_admin_provider: InterfaceAdminProvider | None = None,
    ip_dhcp_provider: DhcpClientProvider | None = None,
    ip_static_ipv4_provider: StaticIpv4Provider | None = None,
    dplane_npcap_library: NpcapLibrary | None = None,
    enable_host_interface_config: bool = False,
) -> CommandRegistry:
    registry = CommandRegistry()

    @registry.command("show", help_text="Show command group", modes=SHOW_MODES)
    def show(ctx, args):
        candidates = CommandParser(registry).help_candidates("show ", mode=ctx.mode, ctx=ctx)
        if not candidates:
            return CommandResult(message="No show commands available")

        lines = ["Available show commands:"]
        for candidate in candidates:
            lines.append(f"  {candidate.display:<16} {candidate.help_text}".rstrip())
        return CommandResult(message="\n".join(lines))

    @registry.command("show version", help_text="Show software version", modes=USER_MODES)
    def show_version(ctx, args):
        return CommandResult(message="VVRP CCmd version 0.1.0")

    @registry.command(
        "show running-configuration",
        help_text="Show current running configuration",
        modes=("privileged", "config", "interface", "host-interface", "hidden"),
    )
    def show_running_configuration(ctx, args):
        return CommandResult(message=render_running_configuration(ctx).rstrip())

    @registry.command(
        "show saved-configuration",
        help_text="Show saved configuration",
        modes=("privileged", "config", "interface", "host-interface", "hidden"),
    )
    def show_saved_configuration(ctx, args):
        return CommandResult(message=read_saved_configuration(ctx).rstrip())

    register_ifnet_commands(
        registry,
        provider=ifnet_provider,
        admin_provider=ifnet_admin_provider,
        modes=("hidden", "interface", "host-interface"),
        register_interface_config_command=enable_host_interface_config,
    )
    register_dplane_commands(
        registry,
        ifnet_provider=ifnet_provider,
        ifnet_admin_provider=ifnet_admin_provider,
        npcap_library=dplane_npcap_library,
        modes=("hidden", "host-interface"),
    )
    register_ip_commands(
        registry,
        modes=ALL_MODES,
        ifnet_provider=ifnet_provider,
        ifnet_admin_provider=ifnet_admin_provider,
        dhcp_provider=ip_dhcp_provider,
        static_ipv4_provider=ip_static_ipv4_provider,
    )

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
        message = set_global_config_command(ctx, "hostname", f"hostname {args['name']}")
        return CommandResult(ok=not message, message=message)

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
        modes=("privileged", "config", "interface", "hidden", "host-interface"),
    )
    def quit_command(ctx, args):
        ctx.quit_mode()
        return CommandResult()

    @registry.command(
        "save",
        help_text="Save current configuration",
        modes=("config", "interface", "host-interface"),
    )
    def save_command(ctx, args):
        try:
            write_saved_configuration(ctx)
        except OSError as exc:
            return CommandResult(ok=False, message=f"% saved-configuration write failed: {exc}")
        return CommandResult(message="Configuration saved.")

    @registry.command("exit", help_text="Exit CLI", modes=ALL_MODES)
    def exit_command(ctx, args):
        return CommandResult(message="Bye.", exit_requested=True)

    return registry
