from __future__ import annotations

import socket
import errno
import os
import struct

from src.DPlane.backend import DPlane_LegacyHostBackend
from src.DPlane.models import DPlane_PacketDevice, DPlane_PlatformInfo, DPlane_Result
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

    def DPlane_set_interface_enabled(
        self,
        DPlane_interface: NetworkInterface,
        DPlane_enabled: bool,
    ) -> DPlane_Result:
        try:
            DPlane_set_linux_interface_enabled(DPlane_interface, DPlane_enabled)
        except PermissionError as DPlane_exc:
            return DPlane_Result(ok=False, message=f"% permission denied: {DPlane_exc}")
        except OSError as DPlane_exc:
            return DPlane_Result(ok=False, message=f"% OS interface API failed: {DPlane_exc}")
        return DPlane_Result(ok=True)


def DPlane_set_linux_interface_enabled(
    DPlane_interface: NetworkInterface,
    DPlane_enabled: bool,
) -> None:
    if DPlane_interface.index is None:
        raise OSError("missing OS interface index")

    DPlane_af_netlink = getattr(socket, "AF_NETLINK", 16)
    DPlane_netlink_route = getattr(socket, "NETLINK_ROUTE", 0)
    DPlane_nlmsg_error = 2
    DPlane_nlm_f_request = 1
    DPlane_nlm_f_ack = 4
    DPlane_rtm_setlink = 19
    DPlane_iff_up = 1

    DPlane_flags = DPlane_iff_up if DPlane_enabled else 0
    DPlane_change = DPlane_iff_up
    DPlane_ifinfomsg = struct.pack(
        "=BBHiII",
        socket.AF_UNSPEC,
        0,
        0,
        DPlane_interface.index,
        DPlane_flags,
        DPlane_change,
    )
    DPlane_sequence = 1
    DPlane_header = struct.pack(
        "=IHHII",
        16 + len(DPlane_ifinfomsg),
        DPlane_rtm_setlink,
        DPlane_nlm_f_request | DPlane_nlm_f_ack,
        DPlane_sequence,
        0,
    )
    DPlane_message = DPlane_header + DPlane_ifinfomsg

    with socket.socket(DPlane_af_netlink, socket.SOCK_RAW, DPlane_netlink_route) as DPlane_socket:
        DPlane_socket.bind((0, 0))
        DPlane_socket.send(DPlane_message)
        DPlane_response = DPlane_socket.recv(65535)

    if len(DPlane_response) < 20:
        raise OSError("short netlink response")

    _, DPlane_message_type, _, _, _ = struct.unpack("=IHHII", DPlane_response[:16])
    if DPlane_message_type != DPlane_nlmsg_error:
        return

    (DPlane_netlink_error,) = struct.unpack("=i", DPlane_response[16:20])
    if DPlane_netlink_error == 0:
        return

    DPlane_error_number = -DPlane_netlink_error
    if DPlane_error_number in {errno.EPERM, errno.EACCES}:
        raise PermissionError(os.strerror(DPlane_error_number))
    raise OSError(DPlane_error_number, os.strerror(DPlane_error_number))
