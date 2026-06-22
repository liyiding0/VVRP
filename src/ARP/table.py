from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Literal

from src.ETHERNET import format_mac_address, parse_mac_address


DEFAULT_ARP_AGE_SECONDS = 20 * 60
ArpEntryType = Literal["dynamic", "static"]


@dataclass(frozen=True)
class ArpEntry:
    ip_address: str
    mac_address: str
    interface_name: str
    entry_type: ArpEntryType = "dynamic"
    updated_at: float = 0.0
    age_seconds: int = DEFAULT_ARP_AGE_SECONDS

    def is_expired(self, now: float) -> bool:
        if self.entry_type == "static":
            return False
        return now - self.updated_at >= self.age_seconds


class ArpTable:
    def __init__(self, default_age_seconds: int = DEFAULT_ARP_AGE_SECONDS) -> None:
        self.default_age_seconds = int(default_age_seconds)
        self._entries: dict[tuple[str, str], ArpEntry] = {}

    def learn(
        self,
        ip_address: str,
        mac_address: str,
        interface_name: str,
        now: float | None = None,
        entry_type: ArpEntryType = "dynamic",
    ) -> ArpEntry:
        timestamp = time.time() if now is None else float(now)
        entry = ArpEntry(
            ip_address=str(ip_address),
            mac_address=format_mac_address(parse_mac_address(mac_address)),
            interface_name=str(interface_name),
            entry_type=entry_type,
            updated_at=timestamp,
            age_seconds=self.default_age_seconds,
        )
        self._entries[(entry.interface_name, entry.ip_address)] = entry
        return entry

    def lookup(self, ip_address: str, interface_name: str, now: float | None = None) -> ArpEntry | None:
        timestamp = time.time() if now is None else float(now)
        entry = self._entries.get((str(interface_name), str(ip_address)))
        if entry is None:
            return None
        if entry.is_expired(timestamp):
            self._entries.pop((entry.interface_name, entry.ip_address), None)
            return None
        return entry

    def remove(self, ip_address: str, interface_name: str) -> bool:
        return self._entries.pop((str(interface_name), str(ip_address)), None) is not None

    def age(self, now: float | None = None) -> tuple[ArpEntry, ...]:
        timestamp = time.time() if now is None else float(now)
        expired: list[ArpEntry] = []
        for key, entry in tuple(self._entries.items()):
            if entry.is_expired(timestamp):
                expired.append(entry)
                self._entries.pop(key, None)
        return tuple(expired)

    def entries(self, now: float | None = None) -> tuple[ArpEntry, ...]:
        self.age(now)
        return tuple(sorted(self._entries.values(), key=lambda entry: (entry.interface_name, entry.ip_address)))

    def clear_dynamic(self) -> None:
        for key, entry in tuple(self._entries.items()):
            if entry.entry_type == "dynamic":
                self._entries.pop(key, None)

    def clear(self) -> None:
        self._entries.clear()
