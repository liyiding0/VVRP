from __future__ import annotations

from collections.abc import Callable, Sequence
from ipaddress import IPv4Network

from src.CCmd.models import CommandResult
from src.CCmd.registry import CommandRegistry
from src.IFNET.models import InterfaceAddress
from src.IFNET.models import NetworkInterface

from .IM import RM_IM_Interface, RM_IM_interface_table_from_ifnet


RM_INTERFACE_NAME_PATTERN = r".+"
RM_SHOW_MODES = ("hidden",)


def RM_register_commands(
    RM_registry: CommandRegistry,
    RM_interfaces_provider: Callable | None = None,
    RM_modes: Sequence[str] = RM_SHOW_MODES,
) -> None:
    @RM_registry.command(
        "show rm interface",
        help_text="Show RM interface information",
        modes=tuple(RM_modes),
    )
    def RM_show_rm_interface(RM_ctx, RM_args):
        RM_interfaces = RM_get_im_interfaces(RM_ctx, RM_interfaces_provider)
        if isinstance(RM_interfaces, CommandResult):
            return RM_interfaces
        return CommandResult(message=RM_format_rm_interfaces_detail(RM_interfaces))

    @RM_registry.command(
        "show rm interface brief",
        help_text="Show brief RM interface information",
        modes=tuple(RM_modes),
    )
    def RM_show_rm_interface_brief(RM_ctx, RM_args):
        RM_interfaces = RM_get_im_interfaces(RM_ctx, RM_interfaces_provider)
        if isinstance(RM_interfaces, CommandResult):
            return RM_interfaces
        return CommandResult(message=RM_format_rm_interfaces_brief(RM_interfaces))

    @RM_registry.command(
        f"show rm interface <name:{RM_INTERFACE_NAME_PATTERN}>",
        help_text="Show RM interface information for an interface",
        modes=tuple(RM_modes),
    )
    def RM_show_rm_interface_name(RM_ctx, RM_args):
        RM_interfaces = RM_get_im_interfaces(RM_ctx, RM_interfaces_provider)
        if isinstance(RM_interfaces, CommandResult):
            return RM_interfaces
        RM_name = RM_args["name"]
        for RM_interface in RM_interfaces:
            if RM_interface.name == RM_name:
                return CommandResult(message=RM_format_rm_interfaces_detail((RM_interface,)))
        return CommandResult(ok=False, message=f"% RM interface not found: {RM_name}")

    def RM_interface_name_values(RM_ctx):
        RM_interfaces = RM_get_im_interfaces(RM_ctx, RM_interfaces_provider)
        if isinstance(RM_interfaces, CommandResult):
            return ()
        return tuple(RM_interface.name for RM_interface in RM_interfaces)

    RM_registry.parameter_values(("show", "rm", "interface"), "name", RM_interface_name_values)


def RM_get_im_interfaces(
    RM_ctx,
    RM_interfaces_provider: Callable | None,
) -> tuple[RM_IM_Interface, ...] | CommandResult:
    if RM_interfaces_provider is None:
        return ()
    try:
        RM_interfaces = RM_interfaces_provider(RM_ctx)
    except Exception as RM_exc:
        return CommandResult(ok=False, message=f"% RM interface discovery failed: {RM_exc}")
    if isinstance(RM_interfaces, CommandResult):
        return RM_interfaces
    return RM_IM_interface_table_from_ifnet(tuple(RM_interfaces)).RM_IM_list()


def RM_format_rm_interfaces_brief(RM_interfaces: tuple[RM_IM_Interface, ...]) -> str:
    if not RM_interfaces:
        return "No RM interfaces found"

    RM_lines = [
        f"{'Interface':<28} {'IfIndex':<10} {'Phy':<6} {'Protocol':<8} {'IPv4 Address':<24} {'MTU':<8}",
    ]
    for RM_interface in RM_interfaces:
        RM_lines.append(
            f"{RM_interface.name:<28} "
            f"{RM_display_ifnet_index(RM_interface.ifnet_index):<10} "
            f"{RM_display_state(RM_interface):<6} "
            f"{RM_display_protocol(RM_interface):<8} "
            f"{RM_display_ipv4_addresses(RM_interface):<24} "
            f"{RM_display_mtu(RM_interface.mtu):<8}"
        )
    return "\n".join(RM_lines)


def RM_format_rm_interfaces_detail(RM_interfaces: tuple[RM_IM_Interface, ...]) -> str:
    if not RM_interfaces:
        return "No RM interfaces found"
    return "\n\n".join(RM_format_rm_interface_detail(RM_interface) for RM_interface in RM_interfaces)


def RM_format_rm_interface_detail(RM_interface: RM_IM_Interface) -> str:
    RM_ipv4_addresses = RM_interface.RM_IM_addresses_by_family("ipv4")
    RM_lines = [
        f"Name: {RM_interface.name}",
        "Physical IF Info:",
        f" IfnetIndex: {RM_display_ifnet_index(RM_interface.ifnet_index)}",
        f" State: {RM_display_rm_state_flags(RM_interface)}",
        f" Slot: {RM_display_slot(RM_interface)}",
        (
            f" IntType: {RM_display_int_type(RM_interface)}, PriLog: {RM_display_prilog(RM_interface)}, "
            f"MTU: {RM_display_mtu(RM_interface.mtu)}, Reference Count {RM_display_blank()}"
        ),
        " Bandwidth: , ",
        " Baudrate: , ",
        " Delay: , Reliability: , Load: ",
        " LDP-ISIS sync capability: disabled",
        " LDP-OSPF sync capability: disabled",
        " InstanceID: 0, Instance Name: Public",
        " Age: sec",
        "Logical IF Info:",
        (
            f" IfnetIndex: {RM_display_ifnet_index(RM_interface.ifnet_index)}, "
            f"PhyIndex: {RM_display_phy_index(RM_interface)} "
            f"Logical Index : {RM_display_logical_index(RM_interface)},"
        ),
    ]
    if RM_ipv4_addresses:
        for RM_address in RM_ipv4_addresses:
            RM_lines.append(
                f" Dest: {RM_address.address}, Mask: {RM_display_ipv4_mask(RM_address)}"
            )
    else:
        RM_lines.append(" Dest: , Mask: ")
    RM_lines.extend(
        [
            f" State: {RM_display_rm_logical_state_flags(RM_interface)} , Reference Count ",
            " Age: sec",
        ]
    )
    return "\n".join(RM_lines)


def RM_display_ifnet_index(RM_ifnet_index: int) -> str:
    return f"0x{RM_ifnet_index:x}"


def RM_display_state(RM_interface: RM_IM_Interface) -> str:
    return "up" if RM_interface.is_up else "down"


def RM_display_protocol(RM_interface: RM_IM_Interface) -> str:
    if RM_interface.kind == "loopback" and RM_interface.is_up:
        return "up(s)"
    return RM_display_state(RM_interface)


def RM_display_slot(RM_interface: RM_IM_Interface) -> str:
    if RM_interface.kind == "loopback":
        return "0(Logic Slot: 0)"
    return ""


def RM_display_ipv4_addresses(RM_interface: RM_IM_Interface) -> str:
    RM_addresses = RM_interface.RM_IM_addresses_by_family("ipv4")
    if not RM_addresses:
        return "-"
    return ",".join(RM_address.display for RM_address in RM_addresses)


def RM_display_mtu(RM_mtu: int | None) -> str:
    if RM_mtu is None:
        return ""
    return str(RM_mtu)


def RM_display_value(RM_value: object) -> str:
    if RM_value is None or RM_value == "":
        return "-"
    return str(RM_value)


def RM_display_blank() -> str:
    return ""


def RM_display_int_type(RM_interface: RM_IM_Interface) -> str:
    if RM_interface.kind == "loopback":
        return "26"
    if RM_interface.kind == "ethernet":
        return ""
    return ""


def RM_display_prilog(RM_interface: RM_IM_Interface) -> str:
    if RM_interface.kind == "loopback":
        return "1"
    return ""


def RM_display_phy_index(RM_interface: RM_IM_Interface) -> str:
    if RM_interface.kind == "loopback":
        return str(max(RM_interface.ifnet_index, 1))
    return ""


def RM_display_logical_index(RM_interface: RM_IM_Interface) -> str:
    if RM_interface.kind == "loopback":
        return str(max(RM_interface.ifnet_index, 1))
    return ""


def RM_display_rm_state_flags(RM_interface: RM_IM_Interface) -> str:
    RM_flags = ["UP" if RM_interface.is_up else "DOWN"]
    if RM_interface.kind == "loopback":
        RM_flags.extend(("LOOP", "MULT"))
    return " ".join(RM_flags)


def RM_display_rm_logical_state_flags(RM_interface: RM_IM_Interface) -> str:
    RM_flags = ["UP" if RM_interface.is_up else "DOWN"]
    if RM_interface.kind == "loopback":
        RM_flags.extend(("LOOP", "PRM", "MULT"))
    return " ".join(RM_flags)


def RM_display_ipv4_mask(RM_address: InterfaceAddress) -> str:
    if RM_address.prefix_length is None:
        return ""
    return str(IPv4Network(f"0.0.0.0/{RM_address.prefix_length}").netmask)
