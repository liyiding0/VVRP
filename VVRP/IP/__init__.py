"""IP services and command registrations for VVRP."""

from .commands import register_ip_commands
from .dhcp import DhcpClientProvider, DhcpClientResult, OsDhcpClientProvider
from .ping import (
    PING_TARGET_PATTERN,
    PingResult,
    build_ping_command,
    classify_ping_target,
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
    "PING_TARGET_PATTERN",
    "OsDhcpClientProvider",
    "OsStaticIpv4Provider",
    "PingResult",
    "StaticIpv4Address",
    "StaticIpv4Provider",
    "StaticIpv4Result",
    "StaticIpv4ValidationError",
    "build_ping_command",
    "classify_ping_target",
    "parse_ipv4_mask",
    "parse_static_ipv4_address",
    "register_ip_commands",
    "run_ping",
]
