from __future__ import annotations

import ipaddress
import platform
import re
import shutil
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class PingResult:
    ok: bool
    message: str


PING_TARGET_PATTERN = r"[A-Za-z0-9_.:%-]+"
_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def run_ping(target: str, count: int = 4, timeout_seconds: int = 1) -> PingResult:
    try:
        target_kind = classify_ping_target(target)
        command = build_ping_command(target, target_kind, count, timeout_seconds)
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=max(5, count * (timeout_seconds + 2)),
        )
    except ValueError as exc:
        return PingResult(ok=False, message=f"% Invalid ping target: {exc}")
    except FileNotFoundError:
        return PingResult(ok=False, message="% ping command not found")
    except subprocess.TimeoutExpired:
        return PingResult(ok=False, message="% ping timed out")

    output = "\n".join(
        part for part in (completed.stdout.strip(), completed.stderr.strip()) if part
    )
    if not output:
        output = f"ping exited with status {completed.returncode}"

    return PingResult(ok=completed.returncode == 0, message=output)


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

    if address.version == 6:
        return "ipv6"
    return "ipv4"


def build_ping_command(
    target: str,
    target_kind: str,
    count: int = 4,
    timeout_seconds: int = 1,
) -> list[str]:
    if platform.system().lower() == "windows":
        command = ["ping"]
        if target_kind == "ipv6":
            command.append("-6")
        command.extend(["-n", str(count), "-w", str(timeout_seconds * 1000), target])
        return command

    ping_binary = "ping"
    if target_kind == "ipv6":
        ping_binary = shutil.which("ping6") or "ping"
        if ping_binary == "ping":
            return [ping_binary, "-6", "-c", str(count), "-W", str(timeout_seconds), target]

    return [ping_binary, "-c", str(count), "-W", str(timeout_seconds), target]


def _is_valid_hostname(target: str) -> bool:
    normalized = target.rstrip(".")
    if not normalized or len(normalized) > 253:
        return False
    return all(_HOST_LABEL_RE.fullmatch(label) for label in normalized.split("."))
