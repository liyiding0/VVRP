from __future__ import annotations

import ctypes
import os
import platform
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from VVRP.DPlane.packet import CapturedFrame
from VVRP.IFNET.models import NetworkInterface


PCAP_ERRBUF_SIZE = 256
DEFAULT_SNAPLEN = 65535
DEFAULT_READ_TIMEOUT_MS = 100
PCAP_NEXT_TIMEOUT = 0
PCAP_NEXT_PACKET = 1
PCAP_NEXT_ERROR = -1
PCAP_NEXT_EOF = -2
PCAP_NETMASK_UNKNOWN = 0xFFFFFFFF


class NpcapError(RuntimeError):
    pass


@dataclass(frozen=True)
class NpcapDevice:
    name: str
    description: str = ""


class _Timeval(ctypes.Structure):
    _fields_ = [
        ("tv_sec", ctypes.c_long),
        ("tv_usec", ctypes.c_long),
    ]


class _PcapPkthdr(ctypes.Structure):
    _fields_ = [
        ("ts", _Timeval),
        ("caplen", ctypes.c_uint),
        ("len", ctypes.c_uint),
    ]


class _PcapIf(ctypes.Structure):
    pass


_PcapIfPointer = ctypes.POINTER(_PcapIf)
_PcapIf._fields_ = [
    ("next", _PcapIfPointer),
    ("name", ctypes.c_char_p),
    ("description", ctypes.c_char_p),
    ("addresses", ctypes.c_void_p),
    ("flags", ctypes.c_uint),
]


class _BpfProgram(ctypes.Structure):
    _fields_ = [
        ("bf_len", ctypes.c_uint),
        ("bf_insns", ctypes.c_void_p),
    ]


class NpcapLibrary:
    def __init__(self, dll: Any | None = None) -> None:
        self.dll = dll or _load_wpcap_dll()
        self._configure_signatures()

    def list_devices(self) -> tuple[NpcapDevice, ...]:
        devices = _PcapIfPointer()
        errbuf = _errbuf()
        result = self.dll.pcap_findalldevs(ctypes.byref(devices), errbuf)
        if result != 0:
            raise NpcapError(_decode_errbuf(errbuf) or "pcap_findalldevs failed")

        try:
            output: list[NpcapDevice] = []
            current = devices
            while bool(current):
                item = current.contents
                if item.name:
                    output.append(
                        NpcapDevice(
                            name=_decode_c_string(item.name),
                            description=_decode_c_string(item.description),
                        )
                    )
                current = item.next
            return tuple(output)
        finally:
            if bool(devices):
                self.dll.pcap_freealldevs(devices)

    def open_live(
        self,
        device_name: str,
        snaplen: int = DEFAULT_SNAPLEN,
        promiscuous: bool = True,
        read_timeout_ms: int = DEFAULT_READ_TIMEOUT_MS,
    ) -> ctypes.c_void_p:
        errbuf = _errbuf()
        handle = self.dll.pcap_open_live(
            device_name.encode("utf-8"),
            int(snaplen),
            1 if promiscuous else 0,
            int(read_timeout_ms),
            errbuf,
        )
        if not handle:
            raise NpcapError(_decode_errbuf(errbuf) or f"pcap_open_live failed: {device_name}")
        return handle

    def close(self, handle) -> None:
        self.dll.pcap_close(handle)

    def next_frame(self, handle) -> CapturedFrame | None:
        header = ctypes.POINTER(_PcapPkthdr)()
        payload = ctypes.POINTER(ctypes.c_ubyte)()
        result = self.dll.pcap_next_ex(handle, ctypes.byref(header), ctypes.byref(payload))
        if result == PCAP_NEXT_TIMEOUT:
            return None
        if result == PCAP_NEXT_EOF:
            return None
        if result == PCAP_NEXT_ERROR:
            raise NpcapError(self.get_error(handle) or "pcap_next_ex failed")
        if result != PCAP_NEXT_PACKET or not header or not payload:
            raise NpcapError(f"unexpected pcap_next_ex result: {result}")

        packet_header = header.contents
        data = ctypes.string_at(payload, int(packet_header.caplen))
        return CapturedFrame(
            data=data,
            captured_length=int(packet_header.caplen),
            original_length=int(packet_header.len),
            timestamp_seconds=int(packet_header.ts.tv_sec),
            timestamp_microseconds=int(packet_header.ts.tv_usec),
        )

    def send_packet(self, handle, frame: bytes) -> None:
        buffer = (ctypes.c_ubyte * len(frame)).from_buffer_copy(frame)
        result = self.dll.pcap_sendpacket(handle, buffer, len(frame))
        if result != 0:
            raise NpcapError(self.get_error(handle) or "pcap_sendpacket failed")

    def set_filter(self, handle, expression: str, optimize: bool = True) -> None:
        program = _BpfProgram()
        encoded = expression.encode("utf-8")
        result = self.dll.pcap_compile(
            handle,
            ctypes.byref(program),
            encoded,
            1 if optimize else 0,
            PCAP_NETMASK_UNKNOWN,
        )
        if result != 0:
            raise NpcapError(self.get_error(handle) or f"pcap_compile failed: {expression}")
        try:
            result = self.dll.pcap_setfilter(handle, ctypes.byref(program))
            if result != 0:
                raise NpcapError(self.get_error(handle) or f"pcap_setfilter failed: {expression}")
        finally:
            self.dll.pcap_freecode(ctypes.byref(program))

    def get_error(self, handle) -> str:
        if not hasattr(self.dll, "pcap_geterr"):
            return ""
        raw = self.dll.pcap_geterr(handle)
        return _decode_c_string(raw)

    def _configure_signatures(self) -> None:
        self._signature(
            "pcap_findalldevs",
            ctypes.c_int,
            [ctypes.POINTER(_PcapIfPointer), ctypes.c_char_p],
        )
        self._signature("pcap_freealldevs", None, [_PcapIfPointer])
        self._signature(
            "pcap_open_live",
            ctypes.c_void_p,
            [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_char_p],
        )
        self._signature("pcap_close", None, [ctypes.c_void_p])
        self._signature(
            "pcap_next_ex",
            ctypes.c_int,
            [
                ctypes.c_void_p,
                ctypes.POINTER(ctypes.POINTER(_PcapPkthdr)),
                ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)),
            ],
        )
        self._signature(
            "pcap_sendpacket",
            ctypes.c_int,
            [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int],
        )
        self._signature("pcap_geterr", ctypes.c_char_p, [ctypes.c_void_p])
        self._signature(
            "pcap_compile",
            ctypes.c_int,
            [ctypes.c_void_p, ctypes.POINTER(_BpfProgram), ctypes.c_char_p, ctypes.c_int, ctypes.c_uint],
        )
        self._signature("pcap_setfilter", ctypes.c_int, [ctypes.c_void_p, ctypes.POINTER(_BpfProgram)])
        self._signature("pcap_freecode", None, [ctypes.POINTER(_BpfProgram)])

    def _signature(self, name: str, restype, argtypes: list[Any]) -> None:
        func = getattr(self.dll, name, None)
        if func is None:
            return
        try:
            func.restype = restype
            func.argtypes = argtypes
        except AttributeError:
            return


class NpcapPacketPort:
    def __init__(
        self,
        device_name: str,
        library: NpcapLibrary | None = None,
        snaplen: int = DEFAULT_SNAPLEN,
        promiscuous: bool = True,
        read_timeout_ms: int = DEFAULT_READ_TIMEOUT_MS,
    ) -> None:
        self.device_name = device_name
        self.library = library or NpcapLibrary()
        self.snaplen = snaplen
        self.promiscuous = promiscuous
        self.read_timeout_ms = read_timeout_ms
        self._handle = None

    @property
    def is_open(self) -> bool:
        return self._handle is not None

    def open(self) -> None:
        if self._handle is not None:
            return
        self._handle = self.library.open_live(
            self.device_name,
            snaplen=self.snaplen,
            promiscuous=self.promiscuous,
            read_timeout_ms=self.read_timeout_ms,
        )

    def close(self) -> None:
        if self._handle is None:
            return
        handle = self._handle
        self._handle = None
        self.library.close(handle)

    def recv_frame(self) -> bytes | None:
        captured = self.recv_captured_frame()
        if captured is None:
            return None
        return captured.data

    def recv_captured_frame(self) -> CapturedFrame | None:
        return self.library.next_frame(self._require_handle())

    def send_frame(self, frame: bytes) -> None:
        if not frame:
            raise NpcapError("cannot send an empty Ethernet frame")
        self.library.send_packet(self._require_handle(), bytes(frame))

    def set_filter(self, expression: str) -> None:
        self.library.set_filter(self._require_handle(), expression)

    def _require_handle(self):
        if self._handle is None:
            raise NpcapError(f"Npcap packet port is not open: {self.device_name}")
        return self._handle

    def __enter__(self) -> NpcapPacketPort:
        self.open()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()


def find_npcap_device_for_interface(
    interface: NetworkInterface,
    devices: tuple[NpcapDevice, ...],
) -> NpcapDevice | None:
    interface_keys = _interface_match_keys(interface)
    for device in devices:
        if interface_keys & _device_match_keys(device):
            return device
    return None


def _load_wpcap_dll():
    if platform.system().lower() != "windows":
        raise NpcapError("Npcap packet I/O is supported only on Windows")

    loader = getattr(ctypes, "WinDLL", ctypes.CDLL)
    candidates = [
        "wpcap.dll",
        str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "Npcap" / "wpcap.dll"),
        str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "SysWOW64" / "Npcap" / "wpcap.dll"),
    ]
    errors: list[str] = []
    for candidate in candidates:
        try:
            return loader(candidate)
        except OSError as exc:
            errors.append(f"{candidate}: {exc}")
    raise NpcapError("Npcap wpcap.dll could not be loaded. Install Npcap first. " + "; ".join(errors))


def _errbuf():
    return ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)


def _decode_errbuf(errbuf) -> str:
    return _decode_c_string(errbuf.value)


def _decode_c_string(value) -> str:
    if not value:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _interface_match_keys(interface: NetworkInterface) -> set[str]:
    values = [interface.name, interface.os_id, *interface.os_aliases]
    keys = set()
    for value in values:
        keys.update(_match_keys(value))
    return keys


def _device_match_keys(device: NpcapDevice) -> set[str]:
    keys = set()
    for value in (device.name, device.description):
        keys.update(_match_keys(value))
    return keys


def _match_keys(value: str) -> set[str]:
    if not value:
        return set()
    normalized = _normalize_match_key(value)
    keys = {normalized} if normalized else set()
    guid = _extract_guid(value)
    if guid:
        keys.add(guid)
        keys.add(f"{{{guid}}}")
    return keys


def _extract_guid(value: str) -> str:
    match = re.search(
        r"\{?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\}?",
        value,
    )
    if not match:
        return ""
    return match.group(1).lower()


def _normalize_match_key(value: str) -> str:
    normalized = value.strip().lower().replace("/", "\\")
    if normalized.startswith("\\device\\npf_"):
        normalized = normalized.removeprefix("\\device\\npf_")
    return normalized.strip("{}")
