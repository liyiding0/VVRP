from __future__ import annotations

import ipaddress
import random
import re
import select
import socket
import struct
import time
from dataclasses import dataclass
from typing import Callable, TextIO

from src.ARP import ArpPacketError, ArpProtocol, arp_packet_from_ethernet, get_arp_table
from src.CCmd.models import CliContext
from src.DPlane import DPlane_Backend, DPlane_PacketDevice, DPlane_create_backend
from src.ETHERNET import (
    ETHERTYPE_ARP,
    ETHERTYPE_IPV4,
    EthernetFrame,
    debug_ethernet_frame,
    parse_ethernet_ii_frame,
)
from src.ETHERNET.frame import EthernetFrameError
from src.FIB import FIBEntry, FIB_resolve_forwarding
from src.IFNET.admin import InterfaceAdminProvider
from src.IFNET.discovery import InterfaceDiscoveryError, InterfaceProvider
from src.IFNET.inventory import get_ifnet_manager
from src.IFNET.models import InterfaceAddress, NetworkInterface
from src.IP.ICMP.packet import (
    ICMP_build_echo_request,
    ICMP_checksum,
    ICMP_parse_echo,
)


g_ICMP_PING_ARGUMENT_PATTERN = r".+"
g_ICMP_DEFAULT_PING_COUNT = 5
g_ICMP_DEFAULT_PACKET_SIZE = 56
g_ICMP_DEFAULT_TIMEOUT_SECONDS = 2
g_ICMP_DEFAULT_INTERVAL_SECONDS = 1
g_ICMP_DEFAULT_TTL = 255
g_ICMP_IPV4_HEADER_LENGTH = 20
g_ICMP_IPV4_PROTOCOL_ICMP = 1
g_ICMP_src_PING_FILTER = "ether proto 0x0806 or ether proto 0x0800"
g_ICMP_HOST_LABEL_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)


@dataclass(frozen=True)
class ICMP_PingOptions:
    ICMP_target: str
    ICMP_count: int = g_ICMP_DEFAULT_PING_COUNT
    ICMP_packet_size: int = g_ICMP_DEFAULT_PACKET_SIZE
    ICMP_timeout_seconds: int = g_ICMP_DEFAULT_TIMEOUT_SECONDS
    ICMP_interval_seconds: int = g_ICMP_DEFAULT_INTERVAL_SECONDS
    ICMP_ttl: int = g_ICMP_DEFAULT_TTL
    ICMP_brief: bool = False


@dataclass(frozen=True)
class ICMP_PingReply:
    ICMP_ok: bool
    ICMP_sequence: int
    ICMP_address: str = ""
    ICMP_bytes_received: int = 0
    ICMP_ttl: int | None = None
    ICMP_rtt_ms: int | None = None
    ICMP_message: str = ""


@dataclass(frozen=True)
class ICMP_PingResult:
    ICMP_ok: bool
    ICMP_message: str = ""


@dataclass(frozen=True)
class _ICMP_Ipv4Packet:
    ICMP_source: str
    ICMP_destination: str
    ICMP_protocol: int
    ICMP_ttl: int
    ICMP_payload: bytes
    ICMP_raw: bytes


class ICMP_SocketPinger:
    def __init__(
        self,
        *,
        ICMP_socket_factory: Callable[..., socket.socket] = socket.socket,
        ICMP_monotonic: Callable[[], float] = time.monotonic,
        ICMP_sleep: Callable[[float], None] = time.sleep,
        ICMP_selector: Callable[
            [list[socket.socket], list, list, float],
            tuple[list, list, list],
        ] = select.select,
        ICMP_identifier: int | None = None,
    ) -> None:
        self.ICMP_socket_factory = ICMP_socket_factory
        self.ICMP_monotonic = ICMP_monotonic
        self.ICMP_sleep = ICMP_sleep
        self.ICMP_selector = ICMP_selector
        self.ICMP_identifier = (
            ICMP_identifier if ICMP_identifier is not None else random.randint(0, 0xFFFF)
        )

    def ICMP_ping(
        self,
        ICMP_options: ICMP_PingOptions,
        ICMP_resolved_address: str,
        ICMP_output: TextIO,
    ) -> ICMP_PingResult:
        ICMP_sent = 0
        ICMP_received = 0
        ICMP_rtts: list[int] = []

        try:
            with self.ICMP_socket_factory(
                socket.AF_INET,
                socket.SOCK_RAW,
                socket.IPPROTO_ICMP,
            ) as ICMP_sock:
                ICMP_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ICMP_options.ICMP_ttl)
                ICMP_sock.settimeout(ICMP_options.ICMP_timeout_seconds)
                if ICMP_options.ICMP_brief:
                    ICMP_output.write("    ")
                    ICMP_output.flush()
                for ICMP_sequence in range(1, ICMP_options.ICMP_count + 1):
                    ICMP_sent += 1
                    try:
                        ICMP_reply = self._ICMP_send_one(
                            ICMP_sock,
                            ICMP_options,
                            ICMP_resolved_address,
                            ICMP_sequence,
                        )
                    except TimeoutError:
                        ICMP_reply = ICMP_PingReply(
                            ICMP_ok=False,
                            ICMP_sequence=ICMP_sequence,
                            ICMP_message="Request time out",
                        )

                    if ICMP_reply.ICMP_ok:
                        ICMP_received += 1
                        if ICMP_reply.ICMP_rtt_ms is not None:
                            ICMP_rtts.append(ICMP_reply.ICMP_rtt_ms)
                    if ICMP_options.ICMP_brief:
                        ICMP_output.write(ICMP_format_ping_reply(ICMP_reply, ICMP_brief=True))
                    else:
                        ICMP_output.write(ICMP_format_ping_reply(ICMP_reply) + "\n")
                    ICMP_output.flush()
                    if ICMP_sequence < ICMP_options.ICMP_count and ICMP_options.ICMP_interval_seconds > 0:
                        self.ICMP_sleep(ICMP_options.ICMP_interval_seconds)
                if ICMP_options.ICMP_brief:
                    ICMP_output.write("\n")
                    ICMP_output.flush()
        except PermissionError:
            return ICMP_PingResult(
                ICMP_ok=False,
                ICMP_message="% ICMP socket permission denied: run VVRP with Administrator/root privileges",
            )
        except OSError as ICMP_exc:
            return ICMP_PingResult(
                ICMP_ok=False,
                ICMP_message=f"% ICMP socket error: {ICMP_exc}",
            )

        ICMP_output.write(
            ICMP_format_ping_statistics(
                ICMP_options.ICMP_target,
                ICMP_sent,
                ICMP_received,
                ICMP_rtts,
            )
            + "\n"
        )
        ICMP_output.flush()
        return ICMP_PingResult(ICMP_ok=ICMP_received > 0)

    def _ICMP_send_one(
        self,
        ICMP_sock: socket.socket,
        ICMP_options: ICMP_PingOptions,
        ICMP_resolved_address: str,
        ICMP_sequence: int,
    ) -> ICMP_PingReply:
        ICMP_payload = _ICMP_payload(ICMP_options.ICMP_packet_size)
        ICMP_packet = ICMP_build_echo_packet(self.ICMP_identifier, ICMP_sequence, ICMP_payload)
        ICMP_started = self.ICMP_monotonic()
        ICMP_sock.sendto(ICMP_packet, (ICMP_resolved_address, 0))
        ICMP_deadline = ICMP_started + ICMP_options.ICMP_timeout_seconds

        while True:
            ICMP_remaining = ICMP_deadline - self.ICMP_monotonic()
            if ICMP_remaining <= 0:
                raise TimeoutError

            ICMP_ready, _, _ = self.ICMP_selector([ICMP_sock], [], [], ICMP_remaining)
            if not ICMP_ready:
                raise TimeoutError

            ICMP_received_at = self.ICMP_monotonic()
            ICMP_data, ICMP_address = ICMP_sock.recvfrom(65535)
            ICMP_reply = ICMP_parse_reply(ICMP_data, self.ICMP_identifier, ICMP_sequence)
            if ICMP_reply is None:
                continue

            ICMP_ttl = ICMP_data[8] if len(ICMP_data) >= 9 else None
            ICMP_ip_header_length = (ICMP_data[0] & 0x0F) * 4 if ICMP_data else 20
            ICMP_bytes_received = max(0, len(ICMP_data) - ICMP_ip_header_length - 8)
            ICMP_rtt_ms = max(0, int(round((ICMP_received_at - ICMP_started) * 1000)))
            return ICMP_PingReply(
                ICMP_ok=True,
                ICMP_sequence=ICMP_sequence,
                ICMP_address=ICMP_address[0],
                ICMP_bytes_received=ICMP_bytes_received,
                ICMP_ttl=ICMP_ttl,
                ICMP_rtt_ms=ICMP_rtt_ms,
            )


class ICMP_VvrpPacketPinger:
    def __init__(
        self,
        ICMP_ctx: CliContext,
        *,
        ICMP_ifnet_provider: InterfaceProvider | None = None,
        ICMP_ifnet_admin_provider: InterfaceAdminProvider | None = None,
        ICMP_dplane_backend: DPlane_Backend | None = None,
        ICMP_port_factory: Callable[[DPlane_PacketDevice], object] | None = None,
        ICMP_monotonic: Callable[[], float] = time.monotonic,
        ICMP_sleep: Callable[[float], None] = time.sleep,
        ICMP_identifier: int | None = None,
    ) -> None:
        self.ICMP_ctx = ICMP_ctx
        self.ICMP_ifnet_provider = ICMP_ifnet_provider
        self.ICMP_ifnet_admin_provider = ICMP_ifnet_admin_provider
        self.ICMP_dplane_backend = ICMP_dplane_backend or DPlane_create_backend(
            DPlane_ifnet_provider=ICMP_ifnet_provider,
            DPlane_admin_provider=ICMP_ifnet_admin_provider,
        )
        self.ICMP_port_factory = ICMP_port_factory or self._ICMP_default_port_factory
        self.ICMP_monotonic = ICMP_monotonic
        self.ICMP_sleep = ICMP_sleep
        self.ICMP_identifier = (
            ICMP_identifier if ICMP_identifier is not None else random.randint(0, 0xFFFF)
        )

    def ICMP_ping(
        self,
        ICMP_options: ICMP_PingOptions,
        ICMP_resolved_address: str,
        ICMP_output: TextIO,
    ) -> ICMP_PingResult:
        try:
            ICMP_route = self._ICMP_resolve_forwarding(ICMP_resolved_address)
        except ValueError as ICMP_exc:
            return ICMP_PingResult(ICMP_ok=False, ICMP_message=f"% {ICMP_exc}")
        except (InterfaceDiscoveryError, RuntimeError) as ICMP_exc:
            return ICMP_PingResult(ICMP_ok=False, ICMP_message=f"% DPlane ping failed: {ICMP_exc}")

        if (
            ICMP_route.mtu is not None
            and ICMP_options.ICMP_packet_size + g_ICMP_IPV4_HEADER_LENGTH + 8 > ICMP_route.mtu
        ):
            return ICMP_PingResult(
                ICMP_ok=False,
                ICMP_message=f"% Packet size exceeds interface MTU: {ICMP_route.out_if_name}",
            )

        ICMP_sent = 0
        ICMP_received = 0
        ICMP_rtts: list[int] = []
        ICMP_arp_protocol = ArpProtocol(get_arp_table(self.ICMP_ctx.state))

        try:
            with self.ICMP_port_factory(ICMP_route.device) as ICMP_port:
                ICMP_port.set_filter(g_ICMP_src_PING_FILTER)
                if ICMP_options.ICMP_brief:
                    ICMP_output.write("    ")
                    ICMP_output.flush()
                for ICMP_sequence in range(1, ICMP_options.ICMP_count + 1):
                    ICMP_sent += 1
                    ICMP_reply = self._ICMP_send_one(
                        ICMP_port,
                        ICMP_route,
                        ICMP_arp_protocol,
                        ICMP_options,
                        ICMP_resolved_address,
                        ICMP_sequence,
                    )
                    if ICMP_reply.ICMP_ok:
                        ICMP_received += 1
                        if ICMP_reply.ICMP_rtt_ms is not None:
                            ICMP_rtts.append(ICMP_reply.ICMP_rtt_ms)
                    if ICMP_options.ICMP_brief:
                        ICMP_output.write(ICMP_format_ping_reply(ICMP_reply, ICMP_brief=True))
                    else:
                        ICMP_output.write(ICMP_format_ping_reply(ICMP_reply) + "\n")
                    ICMP_output.flush()
                    if ICMP_sequence < ICMP_options.ICMP_count and ICMP_options.ICMP_interval_seconds > 0:
                        self.ICMP_sleep(ICMP_options.ICMP_interval_seconds)
                if ICMP_options.ICMP_brief:
                    ICMP_output.write("\n")
                    ICMP_output.flush()
        except (OSError, RuntimeError) as ICMP_exc:
            return ICMP_PingResult(ICMP_ok=False, ICMP_message=f"% DPlane ping failed: {ICMP_exc}")

        ICMP_output.write(
            ICMP_format_ping_statistics(
                ICMP_options.ICMP_target,
                ICMP_sent,
                ICMP_received,
                ICMP_rtts,
            )
            + "\n"
        )
        ICMP_output.flush()
        return ICMP_PingResult(ICMP_ok=ICMP_received > 0)

    def _ICMP_resolve_forwarding(self, ICMP_target_ip: str) -> FIBEntry:
        ICMP_interfaces = get_ifnet_manager(
            self.ICMP_ctx.state,
            provider=self.ICMP_ifnet_provider,
            admin_provider=self.ICMP_ifnet_admin_provider,
        ).list_interfaces()
        ICMP_devices = self.ICMP_dplane_backend.DPlane_list_packet_devices()
        ICMP_fib_entry = FIB_resolve_forwarding(
            self.ICMP_ctx.state,
            ICMP_interfaces,
            ICMP_devices,
            ICMP_target_ip,
        )
        if ICMP_fib_entry is None:
            raise ValueError(f"No VVRP route to host: {ICMP_target_ip}")
        return ICMP_fib_entry

    def _ICMP_send_one(
        self,
        ICMP_port,
        ICMP_route: FIBEntry,
        ICMP_arp_protocol: ArpProtocol,
        ICMP_options: ICMP_PingOptions,
        ICMP_resolved_address: str,
        ICMP_sequence: int,
    ) -> ICMP_PingReply:
        ICMP_started = self.ICMP_monotonic()
        ICMP_interface = _ICMP_interface_from_fib_entry(ICMP_route)
        ICMP_target_mac = self._ICMP_resolve_mac(
            ICMP_port,
            ICMP_route,
            ICMP_interface,
            ICMP_arp_protocol,
            ICMP_resolved_address,
            ICMP_deadline=ICMP_started + ICMP_options.ICMP_timeout_seconds,
        )
        if ICMP_target_mac is None:
            return ICMP_PingReply(
                ICMP_ok=False,
                ICMP_sequence=ICMP_sequence,
                ICMP_message="Request time out",
            )

        ICMP_payload = _ICMP_payload(ICMP_options.ICMP_packet_size)
        ICMP_icmp_payload = ICMP_build_echo_packet(
            self.ICMP_identifier,
            ICMP_sequence,
            ICMP_payload,
        )
        ICMP_ipv4_payload = ICMP_build_ipv4_packet(
            ICMP_route.source_ip,
            ICMP_resolved_address,
            g_ICMP_IPV4_PROTOCOL_ICMP,
            ICMP_icmp_payload,
            ICMP_ttl=ICMP_options.ICMP_ttl,
            ICMP_identification=self.ICMP_identifier,
        )
        ICMP_frame = EthernetFrame(
            destination=ICMP_target_mac,
            source=ICMP_route.source_mac,
            ethertype=ETHERTYPE_IPV4,
            payload=ICMP_ipv4_payload,
        )
        debug_ethernet_frame(self.ICMP_ctx, ICMP_route.out_if_name, "tx", ICMP_frame)
        ICMP_port.send_frame(ICMP_frame.to_bytes(pad=True))

        ICMP_deadline = ICMP_started + ICMP_options.ICMP_timeout_seconds
        while self.ICMP_monotonic() < ICMP_deadline:
            ICMP_frame = self._ICMP_recv_vvrp_frame(
                ICMP_port,
                ICMP_interface,
                ICMP_deadline,
            )
            if ICMP_frame is None:
                continue
            if ICMP_frame.ethertype == ETHERTYPE_ARP:
                self._ICMP_handle_arp_frame(
                    ICMP_port,
                    ICMP_route,
                    ICMP_interface,
                    ICMP_arp_protocol,
                    ICMP_frame,
                )
                continue
            if ICMP_frame.ethertype != ETHERTYPE_IPV4:
                continue
            ICMP_packet = ICMP_parse_ipv4_packet(ICMP_frame.payload)
            if (
                ICMP_packet.ICMP_protocol != g_ICMP_IPV4_PROTOCOL_ICMP
                or ICMP_packet.ICMP_source != ICMP_resolved_address
                or ICMP_packet.ICMP_destination != ICMP_route.source_ip
            ):
                continue
            if ICMP_parse_reply(ICMP_packet.ICMP_raw, self.ICMP_identifier, ICMP_sequence) is None:
                continue
            ICMP_rtt_ms = max(0, int(round((self.ICMP_monotonic() - ICMP_started) * 1000)))
            ICMP_bytes_received = max(0, len(ICMP_packet.ICMP_payload) - 8)
            return ICMP_PingReply(
                ICMP_ok=True,
                ICMP_sequence=ICMP_sequence,
                ICMP_address=ICMP_packet.ICMP_source,
                ICMP_bytes_received=ICMP_bytes_received,
                ICMP_ttl=ICMP_packet.ICMP_ttl,
                ICMP_rtt_ms=ICMP_rtt_ms,
            )

        return ICMP_PingReply(
            ICMP_ok=False,
            ICMP_sequence=ICMP_sequence,
            ICMP_message="Request time out",
        )

    def _ICMP_resolve_mac(
        self,
        ICMP_port,
        ICMP_route: FIBEntry,
        ICMP_interface: NetworkInterface,
        ICMP_arp_protocol: ArpProtocol,
        ICMP_target_ip: str,
        *,
        ICMP_deadline: float,
    ) -> str | None:
        ICMP_entry = ICMP_arp_protocol.table.lookup(ICMP_target_ip, ICMP_route.out_if_name)
        if ICMP_entry is not None:
            return ICMP_entry.mac_address

        ICMP_request = ICMP_arp_protocol.build_request(
            ICMP_interface,
            ICMP_target_ip,
            sender_ip=ICMP_route.source_ip,
        )
        debug_ethernet_frame(self.ICMP_ctx, ICMP_route.out_if_name, "tx", ICMP_request)
        ICMP_port.send_frame(ICMP_request.to_bytes(pad=True))

        while self.ICMP_monotonic() < ICMP_deadline:
            ICMP_frame = self._ICMP_recv_vvrp_frame(
                ICMP_port,
                ICMP_interface,
                ICMP_deadline,
            )
            if ICMP_frame is None:
                continue
            if ICMP_frame.ethertype != ETHERTYPE_ARP:
                continue
            ICMP_packet = self._ICMP_handle_arp_frame(
                ICMP_port,
                ICMP_route,
                ICMP_interface,
                ICMP_arp_protocol,
                ICMP_frame,
            )
            if (
                ICMP_packet is not None
                and ICMP_packet.is_reply
                and ICMP_packet.sender_ip == ICMP_target_ip
                and ICMP_packet.target_ip == ICMP_route.source_ip
            ):
                return ICMP_packet.sender_mac
        return None

    def _ICMP_recv_vvrp_frame(
        self,
        ICMP_port,
        ICMP_interface: NetworkInterface,
        ICMP_deadline: float,
    ) -> EthernetFrame | None:
        while self.ICMP_monotonic() < ICMP_deadline:
            ICMP_raw = ICMP_port.recv_frame()
            if ICMP_raw is None:
                continue
            try:
                ICMP_frame = parse_ethernet_ii_frame(ICMP_raw)
            except EthernetFrameError:
                continue
            if not _ICMP_frame_belongs_to_interface(ICMP_frame, ICMP_interface):
                continue
            debug_ethernet_frame(self.ICMP_ctx, ICMP_interface.name, "rx", ICMP_frame)
            return ICMP_frame
        return None

    def _ICMP_handle_arp_frame(
        self,
        ICMP_port,
        ICMP_route: FIBEntry,
        ICMP_interface: NetworkInterface,
        ICMP_arp_protocol: ArpProtocol,
        ICMP_frame: EthernetFrame,
    ):
        try:
            ICMP_packet = arp_packet_from_ethernet(ICMP_frame)
            ICMP_reply = ICMP_arp_protocol.handle_frame(ICMP_interface, ICMP_frame)
        except (ArpPacketError, EthernetFrameError, ValueError):
            return None
        if ICMP_reply is not None:
            debug_ethernet_frame(self.ICMP_ctx, ICMP_route.out_if_name, "tx", ICMP_reply)
            ICMP_port.send_frame(ICMP_reply.to_bytes(pad=True))
        return ICMP_packet

    def _ICMP_default_port_factory(self, ICMP_device: DPlane_PacketDevice):
        return self.ICMP_dplane_backend.DPlane_open_packet_port(ICMP_device)


def ICMP_run_ping(
    ICMP_arguments: str,
    ICMP_output: TextIO | None = None,
    ICMP_ctx: CliContext | None = None,
    ICMP_ifnet_provider: InterfaceProvider | None = None,
    ICMP_ifnet_admin_provider: InterfaceAdminProvider | None = None,
    ICMP_dplane_backend: DPlane_Backend | None = None,
    ICMP_pinger: ICMP_SocketPinger | ICMP_VvrpPacketPinger | None = None,
) -> ICMP_PingResult:
    try:
        ICMP_options = ICMP_parse_ping_arguments(ICMP_arguments)
        ICMP_target_kind = ICMP_classify_ping_target(ICMP_options.ICMP_target)
        if ICMP_target_kind == "ipv6":
            return ICMP_PingResult(ICMP_ok=False, ICMP_message="% IPv6 ping is not supported yet")
        if ICMP_target_kind == "hostname":
            return ICMP_PingResult(
                ICMP_ok=False,
                ICMP_message="% Hostname ping is not supported by VVRP data-plane ping yet",
            )
        ICMP_resolved_address = str(ipaddress.IPv4Address(ICMP_options.ICMP_target))
    except ValueError as ICMP_exc:
        return ICMP_PingResult(ICMP_ok=False, ICMP_message=f"% Invalid ping command: {ICMP_exc}")

    ICMP_active_output = ICMP_output or _ICMP_NullOutput()
    ICMP_print_ping_header(ICMP_options, ICMP_resolved_address, ICMP_active_output)
    if ICMP_pinger is not None:
        ICMP_active_pinger = ICMP_pinger
    else:
        if ICMP_ctx is None:
            return ICMP_PingResult(ICMP_ok=False, ICMP_message="% VVRP ping requires a CLI context")
        ICMP_active_pinger = ICMP_VvrpPacketPinger(
            ICMP_ctx,
            ICMP_ifnet_provider=ICMP_ifnet_provider,
            ICMP_ifnet_admin_provider=ICMP_ifnet_admin_provider,
            ICMP_dplane_backend=ICMP_dplane_backend,
        )
    return ICMP_active_pinger.ICMP_ping(
        ICMP_options,
        ICMP_resolved_address,
        ICMP_active_output,
    )


def ICMP_parse_ping_arguments(ICMP_arguments: str) -> ICMP_PingOptions:
    ICMP_tokens = ICMP_arguments.split()
    if ICMP_tokens and ICMP_tokens[0] == "ip":
        ICMP_tokens = ICMP_tokens[1:]
    if not ICMP_tokens:
        raise ValueError("missing destination host")

    ICMP_options: dict[str, object] = {
        "ICMP_count": g_ICMP_DEFAULT_PING_COUNT,
        "ICMP_packet_size": g_ICMP_DEFAULT_PACKET_SIZE,
        "ICMP_timeout_seconds": g_ICMP_DEFAULT_TIMEOUT_SECONDS,
        "ICMP_interval_seconds": g_ICMP_DEFAULT_INTERVAL_SECONDS,
        "ICMP_ttl": g_ICMP_DEFAULT_TTL,
        "ICMP_brief": False,
    }
    ICMP_target: str | None = None
    ICMP_index = 0
    while ICMP_index < len(ICMP_tokens):
        ICMP_token = ICMP_tokens[ICMP_index]
        if ICMP_token == "-brief":
            ICMP_options["ICMP_brief"] = True
            ICMP_index += 1
            continue
        if ICMP_token in {"-c", "-s", "-t", "-m", "-h"}:
            if ICMP_index + 1 >= len(ICMP_tokens):
                raise ValueError(f"{ICMP_token} requires a value")
            ICMP_value = _ICMP_parse_int(ICMP_tokens[ICMP_index + 1], ICMP_token)
            if ICMP_token == "-c":
                _ICMP_validate_range(ICMP_token, ICMP_value, 1, 65535)
                ICMP_options["ICMP_count"] = ICMP_value
            elif ICMP_token == "-s":
                _ICMP_validate_range(ICMP_token, ICMP_value, 0, 65500)
                ICMP_options["ICMP_packet_size"] = ICMP_value
            elif ICMP_token == "-t":
                _ICMP_validate_range(ICMP_token, ICMP_value, 1, 60)
                ICMP_options["ICMP_timeout_seconds"] = ICMP_value
            elif ICMP_token == "-m":
                _ICMP_validate_range(ICMP_token, ICMP_value, 0, 60)
                ICMP_options["ICMP_interval_seconds"] = ICMP_value
            elif ICMP_token == "-h":
                _ICMP_validate_range(ICMP_token, ICMP_value, 1, 255)
                ICMP_options["ICMP_ttl"] = ICMP_value
            ICMP_index += 2
            continue
        if ICMP_token == "-a":
            raise ValueError("-a source address is not supported yet")
        if ICMP_token.startswith("-"):
            raise ValueError(f"unsupported option: {ICMP_token}")
        if ICMP_target is not None:
            raise ValueError(f"unexpected extra argument: {ICMP_token}")
        ICMP_target = ICMP_token
        ICMP_index += 1

    if ICMP_target is None:
        raise ValueError("missing destination host")
    ICMP_classify_ping_target(ICMP_target)
    return ICMP_PingOptions(ICMP_target=ICMP_target, **ICMP_options)


def ICMP_print_ping_header(
    ICMP_options: ICMP_PingOptions,
    ICMP_resolved_address: str,
    ICMP_output: TextIO,
) -> None:
    if ICMP_options.ICMP_target == ICMP_resolved_address:
        ICMP_output.write(
            f"  PING {ICMP_resolved_address}: {ICMP_options.ICMP_packet_size} data bytes, press CTRL_C to break\n"
        )
    else:
        ICMP_output.write(
            f"  PING {ICMP_options.ICMP_target} ({ICMP_resolved_address}): "
            f"{ICMP_options.ICMP_packet_size} data bytes, press CTRL_C to break\n"
        )
    ICMP_output.flush()


def ICMP_format_ping_reply(
    ICMP_reply: ICMP_PingReply,
    *,
    ICMP_brief: bool = False,
) -> str:
    if ICMP_brief:
        return "!" if ICMP_reply.ICMP_ok else "."
    if not ICMP_reply.ICMP_ok:
        return f"    {ICMP_reply.ICMP_message or 'Request time out'}"
    ICMP_ttl = "-" if ICMP_reply.ICMP_ttl is None else str(ICMP_reply.ICMP_ttl)
    ICMP_rtt = "-" if ICMP_reply.ICMP_rtt_ms is None else str(ICMP_reply.ICMP_rtt_ms)
    return (
        f"    Reply from {ICMP_reply.ICMP_address}: bytes={ICMP_reply.ICMP_bytes_received} "
        f"Sequence={ICMP_reply.ICMP_sequence} ttl={ICMP_ttl} time={ICMP_rtt} ms"
    )


def ICMP_format_ping_statistics(
    ICMP_target: str,
    ICMP_transmitted: int,
    ICMP_received: int,
    ICMP_rtts: list[int],
) -> str:
    ICMP_loss = (
        100.0
        if ICMP_transmitted == 0
        else ((ICMP_transmitted - ICMP_received) / ICMP_transmitted) * 100
    )
    ICMP_lines = [
        "",
        f"  --- {ICMP_target} ping statistics ---",
        f"    {ICMP_transmitted} packet(s) transmitted",
        f"    {ICMP_received} packet(s) received",
        f"    {ICMP_loss:.2f}% packet loss",
    ]
    if ICMP_rtts:
        ICMP_minimum = min(ICMP_rtts)
        ICMP_maximum = max(ICMP_rtts)
        ICMP_average = round(sum(ICMP_rtts) / len(ICMP_rtts))
        ICMP_lines.append(
            f"    round-trip min/avg/max = {ICMP_minimum}/{ICMP_average}/{ICMP_maximum} ms"
        )
    return "\n".join(ICMP_lines)


def ICMP_classify_ping_target(ICMP_target: str) -> str:
    if not ICMP_target:
        raise ValueError("empty target")
    if ICMP_target.startswith("-"):
        raise ValueError("target must not start with '-'")

    try:
        ICMP_address = ipaddress.ip_address(ICMP_target)
    except ValueError:
        if _ICMP_is_valid_hostname(ICMP_target):
            return "hostname"
        raise ValueError("expected IPv4, IPv6, hostname, or domain name") from None

    return "ipv6" if ICMP_address.version == 6 else "ipv4"


def ICMP_resolve_ipv4_target(ICMP_target: str) -> str:
    ICMP_address = socket.gethostbyname(ICMP_target)
    ipaddress.IPv4Address(ICMP_address)
    return ICMP_address


def ICMP_build_echo_packet(
    ICMP_identifier: int,
    ICMP_sequence: int,
    ICMP_payload: bytes,
) -> bytes:
    return ICMP_build_echo_request(ICMP_identifier, ICMP_sequence, ICMP_payload)


def ICMP_build_ipv4_packet(
    ICMP_source: str,
    ICMP_destination: str,
    ICMP_protocol: int,
    ICMP_payload: bytes,
    *,
    ICMP_ttl: int = g_ICMP_DEFAULT_TTL,
    ICMP_identification: int = 0,
) -> bytes:
    ICMP_source_bytes = ipaddress.IPv4Address(ICMP_source).packed
    ICMP_destination_bytes = ipaddress.IPv4Address(ICMP_destination).packed
    ICMP_total_length = g_ICMP_IPV4_HEADER_LENGTH + len(ICMP_payload)
    ICMP_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        ICMP_total_length,
        ICMP_identification & 0xFFFF,
        0x4000,
        ICMP_ttl,
        ICMP_protocol,
        0,
        ICMP_source_bytes,
        ICMP_destination_bytes,
    )
    ICMP_check = ICMP_checksum(ICMP_header)
    ICMP_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        ICMP_total_length,
        ICMP_identification & 0xFFFF,
        0x4000,
        ICMP_ttl,
        ICMP_protocol,
        ICMP_check,
        ICMP_source_bytes,
        ICMP_destination_bytes,
    )
    return ICMP_header + bytes(ICMP_payload)


def ICMP_parse_ipv4_packet(ICMP_data: bytes) -> _ICMP_Ipv4Packet:
    ICMP_raw = bytes(ICMP_data)
    if len(ICMP_raw) < g_ICMP_IPV4_HEADER_LENGTH:
        raise ValueError("IPv4 packet is shorter than 20 bytes")
    ICMP_version = ICMP_raw[0] >> 4
    if ICMP_version != 4:
        raise ValueError("packet is not IPv4")
    ICMP_header_length = (ICMP_raw[0] & 0x0F) * 4
    if ICMP_header_length < g_ICMP_IPV4_HEADER_LENGTH or len(ICMP_raw) < ICMP_header_length:
        raise ValueError("invalid IPv4 header length")
    ICMP_total_length = int.from_bytes(ICMP_raw[2:4], "big")
    if ICMP_total_length < ICMP_header_length or len(ICMP_raw) < ICMP_total_length:
        raise ValueError("invalid IPv4 total length")
    return _ICMP_Ipv4Packet(
        ICMP_source=str(ipaddress.IPv4Address(ICMP_raw[12:16])),
        ICMP_destination=str(ipaddress.IPv4Address(ICMP_raw[16:20])),
        ICMP_protocol=ICMP_raw[9],
        ICMP_ttl=ICMP_raw[8],
        ICMP_payload=ICMP_raw[ICMP_header_length:ICMP_total_length],
        ICMP_raw=ICMP_raw[:ICMP_total_length],
    )


def ICMP_parse_reply(
    ICMP_data: bytes,
    ICMP_identifier: int,
    ICMP_sequence: int,
) -> bool | None:
    if len(ICMP_data) < 28:
        return None
    ICMP_ip_header_length = (ICMP_data[0] & 0x0F) * 4
    ICMP_header = ICMP_data[ICMP_ip_header_length:ICMP_ip_header_length + 8]
    if len(ICMP_header) < 8:
        return None
    ICMP_echo = ICMP_parse_echo(ICMP_header + ICMP_data[ICMP_ip_header_length + 8:])
    if (
        ICMP_echo is not None
        and ICMP_echo.ICMP_is_echo_reply
        and ICMP_echo.ICMP_identifier == ICMP_identifier
        and ICMP_echo.ICMP_sequence == ICMP_sequence
    ):
        return True
    return None


def _ICMP_interface_from_fib_entry(ICMP_route: FIBEntry) -> NetworkInterface:
    return NetworkInterface(
        name=ICMP_route.out_if_name,
        ifnet_index=ICMP_route.out_if_index or 0,
        index=None,
        kind="ethernet",
        is_up=True,
        mac_address=ICMP_route.source_mac,
        mtu=ICMP_route.mtu,
        speed_mbps=None,
        addresses=(
            InterfaceAddress(
                family="ipv4",
                address=ICMP_route.source_ip,
                prefix_length=ICMP_route.destination.prefixlen,
            ),
        ),
    )


def _ICMP_frame_belongs_to_interface(
    ICMP_frame: EthernetFrame,
    ICMP_interface: NetworkInterface,
) -> bool:
    ICMP_mac = ICMP_interface.mac_address.lower()
    ICMP_source = ICMP_frame.source.lower()
    ICMP_destination = ICMP_frame.destination.lower()
    return (
        ICMP_source == ICMP_mac
        or ICMP_destination == ICMP_mac
        or _ICMP_is_group_address(ICMP_destination)
    )


def _ICMP_is_group_address(ICMP_mac_address: str) -> bool:
    try:
        ICMP_first_octet = int(ICMP_mac_address.split(":", 1)[0], 16)
    except (ValueError, IndexError):
        return False
    return bool(ICMP_first_octet & 1)


def _ICMP_payload(ICMP_size: int) -> bytes:
    ICMP_pattern = bytes(range(32, 32 + 64))
    ICMP_repeats, ICMP_remainder = divmod(ICMP_size, len(ICMP_pattern))
    return ICMP_pattern * ICMP_repeats + ICMP_pattern[:ICMP_remainder]


def _ICMP_parse_int(ICMP_value: str, ICMP_option: str) -> int:
    try:
        return int(ICMP_value, 10)
    except ValueError as ICMP_exc:
        raise ValueError(f"{ICMP_option} expects an integer") from ICMP_exc


def _ICMP_validate_range(
    ICMP_option: str,
    ICMP_value: int,
    ICMP_minimum: int,
    ICMP_maximum: int,
) -> None:
    if not ICMP_minimum <= ICMP_value <= ICMP_maximum:
        raise ValueError(f"{ICMP_option} value must be in range {ICMP_minimum}..{ICMP_maximum}")


def _ICMP_is_valid_hostname(ICMP_target: str) -> bool:
    ICMP_normalized = ICMP_target.rstrip(".")
    if not ICMP_normalized or len(ICMP_normalized) > 253:
        return False
    return all(g_ICMP_HOST_LABEL_RE.fullmatch(ICMP_label) for ICMP_label in ICMP_normalized.split("."))


class _ICMP_NullOutput:
    def write(self, ICMP_text: str) -> int:
        return len(ICMP_text)

    def flush(self) -> None:
        return None
