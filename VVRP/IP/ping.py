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


PING_ARGUMENT_PATTERN = r".+"
DEFAULT_PING_COUNT = 5
DEFAULT_PACKET_SIZE = 56
DEFAULT_TIMEOUT_SECONDS = 2
DEFAULT_INTERVAL_SECONDS = 1
DEFAULT_TTL = 255
ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
ICMP_CODE = 0
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


def run_ping(
    arguments: str,
    output: TextIO | None = None,
    pinger: IcmpSocketPinger | None = None,
) -> PingResult:
    try:
        options = parse_ping_arguments(arguments)
        target_kind = classify_ping_target(options.target)
        if target_kind == "ipv6":
            return PingResult(ok=False, message="% IPv6 ping is not supported yet")
        resolved_address = resolve_ipv4_target(options.target)
    except ValueError as exc:
        return PingResult(ok=False, message=f"% Invalid ping command: {exc}")
    except socket.gaierror as exc:
        return PingResult(ok=False, message=f"% Cannot resolve host: {exc}")

    active_output = output or _NullOutput()
    print_ping_header(options, resolved_address, active_output)
    active_pinger = pinger or IcmpSocketPinger()
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
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, ICMP_CODE, 0, identifier, sequence)
    checksum = icmp_checksum(header + payload)
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, ICMP_CODE, checksum, identifier, sequence)
    return header + payload


def parse_icmp_reply(data: bytes, identifier: int, sequence: int) -> bool | None:
    if len(data) < 28:
        return None
    ip_header_length = (data[0] & 0x0F) * 4
    icmp_header = data[ip_header_length:ip_header_length + 8]
    if len(icmp_header) < 8:
        return None
    icmp_type, _, _, reply_identifier, reply_sequence = struct.unpack("!BBHHH", icmp_header)
    if (
        icmp_type == ICMP_ECHO_REPLY
        and reply_identifier == identifier
        and reply_sequence == sequence
    ):
        return True
    return None


def icmp_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for index in range(0, len(data), 2):
        total += (data[index] << 8) + data[index + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


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
