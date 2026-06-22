from __future__ import annotations

import socket

from src.DPlane.backend import DPlane_LegacyHostBackend
from src.DPlane.models import DPlane_PacketDevice, DPlane_PlatformInfo
from src.IFNET.models import NetworkInterface


g_DPlane_ETH_P_ALL = 0x0003
g_DPlane_DEFAULT_RECV_SIZE = 65535
g_DPlane_DEFAULT_TIMEOUT_SECONDS = 0.1


class DPlane_LinuxRawSocketPort:
    def __init__(
        self,
        DPlane_interface_name: str,
        DPlane_timeout_seconds: float = g_DPlane_DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self.DPlane_interface_name = DPlane_interface_name
        self.DPlane_timeout_seconds = DPlane_timeout_seconds
        self._DPlane_socket: socket.socket | None = None

    def open(self) -> None:
        if self._DPlane_socket is not None:
            return
        DPlane_sock = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.htons(g_DPlane_ETH_P_ALL),
        )
        DPlane_sock.bind((self.DPlane_interface_name, 0))
        DPlane_sock.settimeout(self.DPlane_timeout_seconds)
        self._DPlane_socket = DPlane_sock

    def close(self) -> None:
        DPlane_sock = self._DPlane_socket
        self._DPlane_socket = None
        if DPlane_sock is not None:
            DPlane_sock.close()

    def recv_frame(self) -> bytes | None:
        DPlane_sock = self._DPlane_require_socket()
        try:
            return DPlane_sock.recv(g_DPlane_DEFAULT_RECV_SIZE)
        except TimeoutError:
            return None
        except socket.timeout:
            return None

    def send_frame(self, frame: bytes) -> None:
        if not frame:
            raise OSError("cannot send an empty Ethernet frame")
        self._DPlane_require_socket().send(bytes(frame))

    def set_filter(self, expression: str) -> None:
        # Raw socket BPF attachment is intentionally deferred; callers still get
        # correct behavior because protocol modules filter frames after receive.
        return None

    def _DPlane_require_socket(self) -> socket.socket:
        if self._DPlane_socket is None:
            raise OSError(f"Linux raw socket port is not open: {self.DPlane_interface_name}")
        return self._DPlane_socket

    def __enter__(self) -> DPlane_LinuxRawSocketPort:
        self.open()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()


class DPlane_LinuxRawSocketBackend(DPlane_LegacyHostBackend):
    def __init__(
        self,
        DPlane_ifnet_provider=None,
        DPlane_admin_provider=None,
        DPlane_platform: DPlane_PlatformInfo | None = None,
    ) -> None:
        super().__init__(
            DPlane_ifnet_provider=DPlane_ifnet_provider,
            DPlane_admin_provider=DPlane_admin_provider,
        )
        if DPlane_platform is not None:
            self._DPlane_platform = DPlane_platform

    def DPlane_list_packet_devices(self) -> tuple[DPlane_PacketDevice, ...]:
        return tuple(
            DPlane_PacketDevice(
                name=DPlane_interface.name,
                description=f"kernel interface {DPlane_interface.name}",
                backend="af_packet",
            )
            for DPlane_interface in self.DPlane_list_host_interfaces()
            if DPlane_interface.kind == "ethernet"
        )

    def DPlane_find_packet_device(
        self,
        DPlane_interface: NetworkInterface,
        DPlane_devices: tuple[DPlane_PacketDevice, ...] | None = None,
    ) -> DPlane_PacketDevice | None:
        DPlane_active_devices = DPlane_devices
        if DPlane_active_devices is None:
            DPlane_active_devices = self.DPlane_list_packet_devices()
        for DPlane_device in DPlane_active_devices:
            if DPlane_device.name == DPlane_interface.name:
                return DPlane_device
        return None

    def DPlane_open_packet_port(self, DPlane_device: DPlane_PacketDevice) -> DPlane_LinuxRawSocketPort:
        return DPlane_LinuxRawSocketPort(DPlane_device.name)
