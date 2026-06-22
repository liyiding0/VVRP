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

from VVRP.ARP import ArpPacketError, ArpProtocol, arp_packet_from_ethernet, get_arp_table
from VVRP.CCmd.models import CliContext
from VVRP.DPlane.Windows.npcap import (
    NpcapDevice,
    NpcapError,
    NpcapLibrary,
    NpcapPacketPort,
    find_npcap_device_for_interface,
)
from VVRP.ETHERNET import ETHERTYPE_ARP, ETHERTYPE_IPV4, EthernetFrame, debug_ethernet_frame, parse_ethernet_ii_frame
from VVRP.ETHERNET.frame import EthernetFrameError
from VVRP.IFNET.admin import InterfaceAdminProvider
from VVRP.IFNET.discovery import InterfaceDiscoveryError, InterfaceProvider
from VVRP.IFNET.imports import imported_interfaces
from VVRP.IFNET.inventory import get_ifnet_manager
from VVRP.IFNET.models import NetworkInterface
from VVRP.IFNET.state import is_admin_down
from VVRP.IP.ICMP.packet import (
    ICMP_CODE,
    ICMP_ECHO_REPLY,
    ICMP_ECHO_REQUEST,
    build_icmp_echo_request,
    icmp_checksum,
    parse_icmp_echo,
)


PING_ARGUMENT_PATTERN = r".+"
DEFAULT_PING_COUNT = 5
DEFAULT_PACKET_SIZE = 56
DEFAULT_TIMEOUT_SECONDS = 2
DEFAULT_INTERVAL_SECONDS = 1
DEFAULT_TTL = 255
IPV4_HEADER_LENGTH = 20
IPV4_PROTOCOL_ICMP = 1
VVRP_PING_FILTER = "ether proto 0x0806 or ether proto 0x0800"
_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


@dataclass(frozen=True)
class PingOptions:
    target: str
    count: int = DEFAULT_PING_COUNT
    packet_size: int = DEFAULT_PACKET_SIZE
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    interval_seconds: int = DEFAULT_INTERVAL_SECONDS
    ttl: int = DEFAULT_TTL
    brief: bool = False


@dataclass(frozen=True)
class PingReply:
    ok: bool
    sequence: int
    address: str = ""
    bytes_received: int = 0
    ttl: int | None = None
    rtt_ms: int | None = None
    message: str = ""


@dataclass(frozen=True)
class PingResult:
    ok: bool
    message: str = ""


@dataclass(frozen=True)
class _PingRoute:
    interface: NetworkInterface
    source_ip: str
    device: NpcapDevice


@dataclass(frozen=True)
class _Ipv4Packet:
    source: str
    destination: str
    protocol: int
    ttl: int
    payload: bytes
    raw: bytes


class IcmpSocketPinger:
    def __init__(
        self,
        *,
        socket_factory: Callable[..., socket.socket] = socket.socket,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        selector: Callable[[list[socket.socket], list, list, float], tuple[list, list, list]] = select.select,
        identifier: int | None = None,
    ) -> None:
        self.socket_factory = socket_factory
        self.monotonic = monotonic
        self.sleep = sleep
        self.selector = selector
        self.identifier = identifier if identifier is not None else random.randint(0, 0xFFFF)

    def ping(
        self,
        options: PingOptions,
        resolved_address: str,
        output: TextIO,
    ) -> PingResult:
        sent = 0
        received = 0
        rtts: list[int] = []

        try:
            with self.socket_factory(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, options.ttl)
                sock.settimeout(options.timeout_seconds)
                if options.brief:
                    output.write("    ")
                    output.flush()
                for sequence in range(1, options.count + 1):
                    sent += 1
                    try:
                        reply = self._send_one(sock, options, resolved_address, sequence)
                    except TimeoutError:
                        reply = PingReply(ok=False, sequence=sequence, message="Request time out")

                    if reply.ok:
                        received += 1
                        if reply.rtt_ms is not None:
                            rtts.append(reply.rtt_ms)
                    if options.brief:
                        output.write(format_ping_reply(reply, brief=True))
                    else:
                        output.write(format_ping_reply(reply) + "\n")
                    output.flush()
                    if sequence < options.count and options.interval_seconds > 0:
                        self.sleep(options.interval_seconds)
                if options.brief:
                    output.write("\n")
                    output.flush()
        except PermissionError:
            return PingResult(
                ok=False,
                message="% ICMP socket permission denied: run VVRP with Administrator/root privileges",
            )
        except OSError as exc:
            return PingResult(ok=False, message=f"% ICMP socket error: {exc}")

        output.write(format_ping_statistics(options.target, sent, received, rtts) + "\n")
        output.flush()
        return PingResult(ok=received > 0)

    def _send_one(
        self,
        sock: socket.socket,
        options: PingOptions,
        resolved_address: str,
        sequence: int,
    ) -> PingReply:
        payload = _payload(options.packet_size)
        packet = build_icmp_echo_packet(self.identifier, sequence, payload)
        started = self.monotonic()
        sock.sendto(packet, (resolved_address, 0))
        deadline = started + options.timeout_seconds

        while True:
            remaining = deadline - self.monotonic()
            if remaining <= 0:
                raise TimeoutError

            ready, _, _ = self.selector([sock], [], [], remaining)
            if not ready:
                raise TimeoutError

            received_at = self.monotonic()
            data, address = sock.recvfrom(65535)
            reply = parse_icmp_reply(data, self.identifier, sequence)
            if reply is None:
                continue

            ttl = data[8] if len(data) >= 9 else None
            ip_header_length = (data[0] & 0x0F) * 4 if data else 20
            bytes_received = max(0, len(data) - ip_header_length - 8)
            rtt_ms = max(0, int(round((received_at - started) * 1000)))
            return PingReply(
                ok=True,
                sequence=sequence,
                address=address[0],
                bytes_received=bytes_received,
                ttl=ttl,
                rtt_ms=rtt_ms,
            )


class VvrpPacketPinger:
    def __init__(
        self,
        ctx: CliContext,
        *,
        ifnet_provider: InterfaceProvider | None = None,
        ifnet_admin_provider: InterfaceAdminProvider | None = None,
        npcap_library: NpcapLibrary | None = None,
        port_factory: Callable[[str], object] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        identifier: int | None = None,
    ) -> None:
        self.ctx = ctx
        self.ifnet_provider = ifnet_provider
        self.ifnet_admin_provider = ifnet_admin_provider
        self.npcap_library = npcap_library
        self.port_factory = port_factory or self._default_port_factory
        self.monotonic = monotonic
        self.sleep = sleep
        self.identifier = identifier if identifier is not None else random.randint(0, 0xFFFF)

    def ping(
        self,
        options: PingOptions,
        resolved_address: str,
        output: TextIO,
    ) -> PingResult:
        try:
            route = self._select_route(resolved_address)
        except ValueError as exc:
            return PingResult(ok=False, message=f"% {exc}")
        except (InterfaceDiscoveryError, NpcapError) as exc:
            return PingResult(ok=False, message=f"% DPlane ping failed: {exc}")

        if route.interface.mtu is not None and options.packet_size + IPV4_HEADER_LENGTH + 8 > route.interface.mtu:
            return PingResult(
                ok=False,
                message=f"% Packet size exceeds interface MTU: {route.interface.name}",
            )

        sent = 0
        received = 0
        rtts: list[int] = []
        arp_protocol = ArpProtocol(get_arp_table(self.ctx.state))

        try:
            with self.port_factory(route.device.name) as port:
                port.set_filter(VVRP_PING_FILTER)
                if options.brief:
                    output.write("    ")
                    output.flush()
                for sequence in range(1, options.count + 1):
                    sent += 1
                    reply = self._send_one(port, route, arp_protocol, options, resolved_address, sequence)
                    if reply.ok:
                        received += 1
                        if reply.rtt_ms is not None:
                            rtts.append(reply.rtt_ms)
                    if options.brief:
                        output.write(format_ping_reply(reply, brief=True))
                    else:
                        output.write(format_ping_reply(reply) + "\n")
                    output.flush()
                    if sequence < options.count and options.interval_seconds > 0:
                        self.sleep(options.interval_seconds)
                if options.brief:
                    output.write("\n")
                    output.flush()
        except (OSError, NpcapError) as exc:
            return PingResult(ok=False, message=f"% DPlane ping failed: {exc}")

        output.write(format_ping_statistics(options.target, sent, received, rtts) + "\n")
        output.flush()
        return PingResult(ok=received > 0)

    def _select_route(self, target_ip: str) -> _PingRoute:
        interfaces = get_ifnet_manager(
            self.ctx.state,
            provider=self.ifnet_provider,
            admin_provider=self.ifnet_admin_provider,
        ).list_interfaces()
        devices = (self.npcap_library or NpcapLibrary()).list_devices()
        target = ipaddress.IPv4Address(target_ip)
        candidates: list[tuple[int, NetworkInterface, str, NpcapDevice]] = []

        for interface in imported_interfaces(self.ctx.state, interfaces):
            if interface.kind != "ethernet" or not interface.is_up or is_admin_down(self.ctx.state, interface.name):
                continue
            device = find_npcap_device_for_interface(interface, devices)
            if device is None:
                continue
            for address in interface.addresses_by_family("ipv4"):
                if address.prefix_length is None:
                    continue
                network = ipaddress.IPv4Interface(
                    f"{address.address}/{address.prefix_length}"
                ).network
                if target in network:
                    candidates.append((network.prefixlen, interface, address.address, device))

        if not candidates:
            raise ValueError(f"No VVRP direct route to host: {target_ip}")

        _, interface, source_ip, device = max(candidates, key=lambda item: item[0])
        return _PingRoute(interface=interface, source_ip=source_ip, device=device)

    def _send_one(
        self,
        port,
        route: _PingRoute,
        arp_protocol: ArpProtocol,
        options: PingOptions,
        resolved_address: str,
        sequence: int,
    ) -> PingReply:
        started = self.monotonic()
        target_mac = self._resolve_mac(
            port,
            route,
            arp_protocol,
            resolved_address,
            deadline=started + options.timeout_seconds,
        )
        if target_mac is None:
            return PingReply(ok=False, sequence=sequence, message="Request time out")

        payload = _payload(options.packet_size)
        icmp_payload = build_icmp_echo_packet(self.identifier, sequence, payload)
        ipv4_payload = build_ipv4_packet(
            route.source_ip,
            resolved_address,
            IPV4_PROTOCOL_ICMP,
            icmp_payload,
            ttl=options.ttl,
            identification=self.identifier,
        )
        frame = EthernetFrame(
            destination=target_mac,
            source=route.interface.mac_address,
            ethertype=ETHERTYPE_IPV4,
            payload=ipv4_payload,
        )
        debug_ethernet_frame(self.ctx, route.interface.name, "tx", frame)
        port.send_frame(frame.to_bytes(pad=True))

        deadline = started + options.timeout_seconds
        while self.monotonic() < deadline:
            frame = self._recv_vvrp_frame(port, route.interface, deadline)
            if frame is None:
                continue
            if frame.ethertype == ETHERTYPE_ARP:
                self._handle_arp_frame(port, route, arp_protocol, frame)
                continue
            if frame.ethertype != ETHERTYPE_IPV4:
                continue
            packet = parse_ipv4_packet(frame.payload)
            if (
                packet.protocol != IPV4_PROTOCOL_ICMP
                or packet.source != resolved_address
                or packet.destination != route.source_ip
            ):
                continue
            if parse_icmp_reply(packet.raw, self.identifier, sequence) is None:
                continue
            rtt_ms = max(0, int(round((self.monotonic() - started) * 1000)))
            bytes_received = max(0, len(packet.payload) - 8)
            return PingReply(
                ok=True,
                sequence=sequence,
                address=packet.source,
                bytes_received=bytes_received,
                ttl=packet.ttl,
                rtt_ms=rtt_ms,
            )

        return PingReply(ok=False, sequence=sequence, message="Request time out")

    def _resolve_mac(
        self,
        port,
        route: _PingRoute,
        arp_protocol: ArpProtocol,
        target_ip: str,
        *,
        deadline: float,
    ) -> str | None:
        entry = arp_protocol.table.lookup(target_ip, route.interface.name)
        if entry is not None:
            return entry.mac_address

        request = arp_protocol.build_request(route.interface, target_ip, sender_ip=route.source_ip)
        debug_ethernet_frame(self.ctx, route.interface.name, "tx", request)
        port.send_frame(request.to_bytes(pad=True))

        while self.monotonic() < deadline:
            frame = self._recv_vvrp_frame(port, route.interface, deadline)
            if frame is None:
                continue
            if frame.ethertype != ETHERTYPE_ARP:
                continue
            packet = self._handle_arp_frame(port, route, arp_protocol, frame)
            if (
                packet is not None
                and packet.is_reply
                and packet.sender_ip == target_ip
                and packet.target_ip == route.source_ip
            ):
                return packet.sender_mac
        return None

    def _recv_vvrp_frame(self, port, interface: NetworkInterface, deadline: float) -> EthernetFrame | None:
        while self.monotonic() < deadline:
            raw = port.recv_frame()
            if raw is None:
                continue
            try:
                frame = parse_ethernet_ii_frame(raw)
            except EthernetFrameError:
                continue
            if not _frame_belongs_to_interface(frame, interface):
                continue
            debug_ethernet_frame(self.ctx, interface.name, "rx", frame)
            return frame
        return None

    def _handle_arp_frame(
        self,
        port,
        route: _PingRoute,
        arp_protocol: ArpProtocol,
        frame: EthernetFrame,
    ):
        try:
            packet = arp_packet_from_ethernet(frame)
            reply = arp_protocol.handle_frame(route.interface, frame)
        except (ArpPacketError, EthernetFrameError, ValueError):
            return None
        if reply is not None:
            debug_ethernet_frame(self.ctx, route.interface.name, "tx", reply)
            port.send_frame(reply.to_bytes(pad=True))
        return packet

    def _default_port_factory(self, device_name: str):
        return NpcapPacketPort(device_name, library=self.npcap_library)


def run_ping(
    arguments: str,
    output: TextIO | None = None,
    ctx: CliContext | None = None,
    ifnet_provider: InterfaceProvider | None = None,
    ifnet_admin_provider: InterfaceAdminProvider | None = None,
    npcap_library: NpcapLibrary | None = None,
    pinger: IcmpSocketPinger | None = None,
) -> PingResult:
    try:
        options = parse_ping_arguments(arguments)
        target_kind = classify_ping_target(options.target)
        if target_kind == "ipv6":
            return PingResult(ok=False, message="% IPv6 ping is not supported yet")
        if target_kind == "hostname":
            return PingResult(ok=False, message="% Hostname ping is not supported by VVRP data-plane ping yet")
        resolved_address = str(ipaddress.IPv4Address(options.target))
    except ValueError as exc:
        return PingResult(ok=False, message=f"% Invalid ping command: {exc}")

    active_output = output or _NullOutput()
    print_ping_header(options, resolved_address, active_output)
    if pinger is not None:
        active_pinger = pinger
    else:
        if ctx is None:
            return PingResult(ok=False, message="% VVRP ping requires a CLI context")
        active_pinger = VvrpPacketPinger(
            ctx,
            ifnet_provider=ifnet_provider,
            ifnet_admin_provider=ifnet_admin_provider,
            npcap_library=npcap_library,
        )
    return active_pinger.ping(options, resolved_address, active_output)


def parse_ping_arguments(arguments: str) -> PingOptions:
    tokens = arguments.split()
    if tokens and tokens[0] == "ip":
        tokens = tokens[1:]
    if not tokens:
        raise ValueError("missing destination host")

    options: dict[str, object] = {
        "count": DEFAULT_PING_COUNT,
        "packet_size": DEFAULT_PACKET_SIZE,
        "timeout_seconds": DEFAULT_TIMEOUT_SECONDS,
        "interval_seconds": DEFAULT_INTERVAL_SECONDS,
        "ttl": DEFAULT_TTL,
        "brief": False,
    }
    target: str | None = None
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "-brief":
            options["brief"] = True
            index += 1
            continue
        if token in {"-c", "-s", "-t", "-m", "-h"}:
            if index + 1 >= len(tokens):
                raise ValueError(f"{token} requires a value")
            value = _parse_int(tokens[index + 1], token)
            if token == "-c":
                _validate_range(token, value, 1, 65535)
                options["count"] = value
            elif token == "-s":
                _validate_range(token, value, 0, 65500)
                options["packet_size"] = value
            elif token == "-t":
                _validate_range(token, value, 1, 60)
                options["timeout_seconds"] = value
            elif token == "-m":
                _validate_range(token, value, 0, 60)
                options["interval_seconds"] = value
            elif token == "-h":
                _validate_range(token, value, 1, 255)
                options["ttl"] = value
            index += 2
            continue
        if token == "-a":
            raise ValueError("-a source address is not supported yet")
        if token.startswith("-"):
            raise ValueError(f"unsupported option: {token}")
        if target is not None:
            raise ValueError(f"unexpected extra argument: {token}")
        target = token
        index += 1

    if target is None:
        raise ValueError("missing destination host")
    classify_ping_target(target)
    return PingOptions(target=target, **options)


def print_ping_header(options: PingOptions, resolved_address: str, output: TextIO) -> None:
    if options.target == resolved_address:
        output.write(
            f"  PING {resolved_address}: {options.packet_size} data bytes, press CTRL_C to break\n"
        )
    else:
        output.write(
            f"  PING {options.target} ({resolved_address}): "
            f"{options.packet_size} data bytes, press CTRL_C to break\n"
        )
    output.flush()


def format_ping_reply(reply: PingReply, *, brief: bool = False) -> str:
    if brief:
        return "!" if reply.ok else "."
    if not reply.ok:
        return f"    {reply.message or 'Request time out'}"
    ttl = "-" if reply.ttl is None else str(reply.ttl)
    rtt = "-" if reply.rtt_ms is None else str(reply.rtt_ms)
    return (
        f"    Reply from {reply.address}: bytes={reply.bytes_received} "
        f"Sequence={reply.sequence} ttl={ttl} time={rtt} ms"
    )


def format_ping_statistics(
    target: str,
    transmitted: int,
    received: int,
    rtts: list[int],
) -> str:
    loss = 100.0 if transmitted == 0 else ((transmitted - received) / transmitted) * 100
    lines = [
        "",
        f"  --- {target} ping statistics ---",
        f"    {transmitted} packet(s) transmitted",
        f"    {received} packet(s) received",
        f"    {loss:.2f}% packet loss",
    ]
    if rtts:
        minimum = min(rtts)
        maximum = max(rtts)
        average = round(sum(rtts) / len(rtts))
        lines.append(f"    round-trip min/avg/max = {minimum}/{average}/{maximum} ms")
    return "\n".join(lines)


def classify_ping_target(target: str) -> str:
    if not target:
        raise ValueError("empty target")
    if target.startswith("-"):
        raise ValueError("target must not start with '-'")

    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        if _is_valid_hostname(target):
            return "hostname"
        raise ValueError("expected IPv4, IPv6, hostname, or domain name") from None

    return "ipv6" if address.version == 6 else "ipv4"


def resolve_ipv4_target(target: str) -> str:
    address = socket.gethostbyname(target)
    ipaddress.IPv4Address(address)
    return address


def build_icmp_echo_packet(identifier: int, sequence: int, payload: bytes) -> bytes:
    return build_icmp_echo_request(identifier, sequence, payload)


def build_ipv4_packet(
    source: str,
    destination: str,
    protocol: int,
    payload: bytes,
    *,
    ttl: int = DEFAULT_TTL,
    identification: int = 0,
) -> bytes:
    source_bytes = ipaddress.IPv4Address(source).packed
    destination_bytes = ipaddress.IPv4Address(destination).packed
    total_length = IPV4_HEADER_LENGTH + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        identification & 0xFFFF,
        0x4000,
        ttl,
        protocol,
        0,
        source_bytes,
        destination_bytes,
    )
    checksum = icmp_checksum(header)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        identification & 0xFFFF,
        0x4000,
        ttl,
        protocol,
        checksum,
        source_bytes,
        destination_bytes,
    )
    return header + bytes(payload)


def parse_ipv4_packet(data: bytes) -> _Ipv4Packet:
    raw = bytes(data)
    if len(raw) < IPV4_HEADER_LENGTH:
        raise ValueError("IPv4 packet is shorter than 20 bytes")
    version = raw[0] >> 4
    if version != 4:
        raise ValueError("packet is not IPv4")
    header_length = (raw[0] & 0x0F) * 4
    if header_length < IPV4_HEADER_LENGTH or len(raw) < header_length:
        raise ValueError("invalid IPv4 header length")
    total_length = int.from_bytes(raw[2:4], "big")
    if total_length < header_length or len(raw) < total_length:
        raise ValueError("invalid IPv4 total length")
    return _Ipv4Packet(
        source=str(ipaddress.IPv4Address(raw[12:16])),
        destination=str(ipaddress.IPv4Address(raw[16:20])),
        protocol=raw[9],
        ttl=raw[8],
        payload=raw[header_length:total_length],
        raw=raw[:total_length],
    )


def parse_icmp_reply(data: bytes, identifier: int, sequence: int) -> bool | None:
    if len(data) < 28:
        return None
    ip_header_length = (data[0] & 0x0F) * 4
    icmp_header = data[ip_header_length:ip_header_length + 8]
    if len(icmp_header) < 8:
        return None
    echo = parse_icmp_echo(icmp_header + data[ip_header_length + 8:])
    if (
        echo is not None
        and echo.is_echo_reply
        and echo.identifier == identifier
        and echo.sequence == sequence
    ):
        return True
    return None


def _frame_belongs_to_interface(frame: EthernetFrame, interface: NetworkInterface) -> bool:
    mac = interface.mac_address.lower()
    source = frame.source.lower()
    destination = frame.destination.lower()
    return source == mac or destination == mac or _is_group_address(destination)


def _is_group_address(mac_address: str) -> bool:
    try:
        first_octet = int(mac_address.split(":", 1)[0], 16)
    except (ValueError, IndexError):
        return False
    return bool(first_octet & 1)


def _payload(size: int) -> bytes:
    pattern = bytes(range(32, 32 + 64))
    repeats, remainder = divmod(size, len(pattern))
    return pattern * repeats + pattern[:remainder]


def _parse_int(value: str, option: str) -> int:
    try:
        return int(value, 10)
    except ValueError as exc:
        raise ValueError(f"{option} expects an integer") from exc


def _validate_range(option: str, value: int, minimum: int, maximum: int) -> None:
    if not minimum <= value <= maximum:
        raise ValueError(f"{option} value must be in range {minimum}..{maximum}")


def _is_valid_hostname(target: str) -> bool:
    normalized = target.rstrip(".")
    if not normalized or len(normalized) > 253:
        return False
    return all(_HOST_LABEL_RE.fullmatch(label) for label in normalized.split("."))


class _NullOutput:
    def write(self, text: str) -> int:
        return len(text)

    def flush(self) -> None:
        return None
