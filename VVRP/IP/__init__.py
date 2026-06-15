"""IP services and command registrations for VVRP."""

from .commands import register_ip_commands
from .dhcp import DhcpClientProvider, DhcpClientResult, OsDhcpClientProvider
from .ping import (
    PING_ARGUMENT_PATTERN,
    IcmpSocketPinger,
    PingOptions,
    PingReply,
    PingResult,
    build_icmp_echo_packet,
    classify_ping_target,
    format_ping_reply,
    format_ping_statistics,
    parse_ping_arguments,
    run_ping,
)
from .static import (
    OsStaticIpv4Provider,
    StaticIpv4Address,
    StaticIpv4Provider,
    StaticIpv4Result,
    StaticIpv4ValidationError,
    parse_ipv4_mask,
    parse_static_ipv4_address,
)

__all__ = [
    "DhcpClientProvider",
    "DhcpClientResult",
    "PING_ARGUMENT_PATTERN",
    "IcmpSocketPinger",
    "OsDhcpClientProvider",
    "OsStaticIpv4Provider",
    "PingOptions",
    "PingReply",
    "PingResult",
    "StaticIpv4Address",
    "StaticIpv4Provider",
    "StaticIpv4Result",
    "StaticIpv4ValidationError",
    "build_icmp_echo_packet",
    "classify_ping_target",
    "format_ping_reply",
    "format_ping_statistics",
    "parse_ping_arguments",
    "parse_ipv4_mask",
    "parse_static_ipv4_address",
    "register_ip_commands",
    "run_ping",
]
