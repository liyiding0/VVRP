from __future__ import annotations

from src.ARP import ArpTable, register_arp_commands
from src.DPlane import register_dplane_commands
from src.DPlane.frame_debug import DplaneEthernetFrameDebugService
from src.DPlane.input import DPlane_PacketInputService
from src.DPlane.Windows.npcap import NpcapLibrary
from src.ETHERNET import register_ethernet_commands
from src.FIB import FIB_register_commands
from src.IFNET import register_ifnet_commands
from src.IFNET.admin import InterfaceAdminProvider
from src.IFNET.discovery import InterfaceProvider
from src.IP import IP_register_commands
from src.IP.dhcp import IP_DhcpClientProvider
from src.IP.static import IP_StaticIpv4Provider
from src.RM import RM_register_commands

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
SHOW_MODES = ("user", "privileged", "config", "hidden", "interface", "host-interface")
ALL_MODES = ("user", "privileged", "config", "interface", "hidden", "host-interface")
HIDDEN_ENTRY_MODES = ("user", "privileged", "config", "interface", "host-interface")


def build_default_registry(
    ifnet_provider: InterfaceProvider | None = None,
    ifnet_admin_provider: InterfaceAdminProvider | None = None,
    ip_dhcp_provider: IP_DhcpClientProvider | None = None,
    ip_static_ipv4_provider: IP_StaticIpv4Provider | None = None,
    arp_table: ArpTable | None = None,
    dplane_npcap_library: NpcapLibrary | None = None,
    enable_host_interface_config: bool = False,
) -> CommandRegistry:
    registry = CommandRegistry()
    ethernet_frame_debug = DplaneEthernetFrameDebugService(
        ifnet_provider=ifnet_provider,
        ifnet_admin_provider=ifnet_admin_provider,
        npcap_library=dplane_npcap_library,
    )
    dplane_packet_input = DPlane_PacketInputService(
        DPlane_ifnet_provider=ifnet_provider,
        DPlane_ifnet_admin_provider=ifnet_admin_provider,
        DPlane_npcap_library=dplane_npcap_library,
    )
    active_npcap_library = dplane_npcap_library or NpcapLibrary()

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
        register_interface_config_command=False,
    )
    RM_register_commands(
        registry,
        RM_interfaces_provider=lambda ctx: _list_vvrp_interfaces_for_rm(
            ctx,
            ifnet_provider,
            ifnet_admin_provider,
        ),
        RM_fib_devices_provider=lambda ctx: active_npcap_library.list_devices(),
        RM_modes=("hidden",),
    )
    FIB_register_commands(registry, FIB_modes=SHOW_MODES)
    register_dplane_commands(
        registry,
        ifnet_provider=ifnet_provider,
        ifnet_admin_provider=ifnet_admin_provider,
        npcap_library=dplane_npcap_library,
        modes=("hidden", "host-interface"),
        after_import_commit=dplane_packet_input.DPlane_refresh,
    )
    IP_register_commands(
        registry,
        modes=ALL_MODES,
        ifnet_provider=ifnet_provider,
        ifnet_admin_provider=ifnet_admin_provider,
        npcap_library=dplane_npcap_library,
        dhcp_provider=ip_dhcp_provider,
        static_ipv4_provider=ip_static_ipv4_provider,
        after_vvrp_ipv4_change=dplane_packet_input.DPlane_refresh,
    )
    register_arp_commands(
        registry,
        table=arp_table,
        modes=SHOW_MODES,
    )
    register_ethernet_commands(
        registry,
        modes=("privileged", "config", "hidden"),
        ifnet_provider=ifnet_provider,
        ifnet_admin_provider=ifnet_admin_provider,
        frame_debug_start=ethernet_frame_debug.start,
        frame_debug_stop=ethernet_frame_debug.stop,
        frame_debug_status=ethernet_frame_debug.status,
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


def _list_vvrp_interfaces_for_rm(
    ctx,
    ifnet_provider: InterfaceProvider | None,
    ifnet_admin_provider: InterfaceAdminProvider | None,
):
    from src.IFNET.imports import imported_interfaces
    from src.IFNET.inventory import get_ifnet_manager

    interfaces = get_ifnet_manager(
        ctx.state,
        provider=ifnet_provider,
        admin_provider=ifnet_admin_provider,
    ).list_interfaces()
    return imported_interfaces(ctx.state, interfaces)

