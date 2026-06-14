from __future__ import annotations

import errno
import os
import platform
import socket
import struct

from VVRP.IFNET.models import NetworkInterface


class EthernetAdminProvider:
    def __init__(self, system: str | None = None) -> None:
        self.system = _normalize_system(system or platform.system())

    def shutdown(self, interface: NetworkInterface):
        return _set_interface_enabled(interface, enabled=False, system=self.system)

    def no_shutdown(self, interface: NetworkInterface):
        return _set_interface_enabled(interface, enabled=True, system=self.system)


def _normalize_system(system: str) -> str:
    return system.lower()


def _set_interface_enabled(interface: NetworkInterface, enabled: bool, system: str):
    from VVRP.IFNET.admin import InterfaceAdminResult

    try:
        if system == "windows":
            _set_windows_interface_enabled(interface, enabled)
        elif system == "linux":
            _set_linux_interface_enabled(interface, enabled)
        else:
            return InterfaceAdminResult(
                ok=False,
                message=f"% unsupported OS API backend for interface admin: {system}",
            )
    except PermissionError as exc:
        return InterfaceAdminResult(ok=False, message=f"% permission denied: {exc}")
    except OSError as exc:
        return InterfaceAdminResult(ok=False, message=f"% OS interface API failed: {exc}")

    return InterfaceAdminResult(ok=True)


def _set_windows_interface_enabled(interface: NetworkInterface, enabled: bool) -> None:
    from .windows import set_windows_network_adapter_enabled

    set_windows_network_adapter_enabled(interface, enabled)


def _set_linux_interface_enabled(interface: NetworkInterface, enabled: bool) -> None:
    if interface.index is None:
        raise OSError("missing OS interface index")

    af_netlink = getattr(socket, "AF_NETLINK", 16)
    netlink_route = getattr(socket, "NETLINK_ROUTE", 0)
    nlmsg_error = 2
    nlm_f_request = 1
    nlm_f_ack = 4
    rtm_setlink = 19
    iff_up = 1

    flags = iff_up if enabled else 0
    change = iff_up
    ifinfomsg = struct.pack("=BBHiII", socket.AF_UNSPEC, 0, 0, interface.index, flags, change)
    sequence = 1
    header = struct.pack(
        "=IHHII",
        16 + len(ifinfomsg),
        rtm_setlink,
        nlm_f_request | nlm_f_ack,
        sequence,
        0,
    )
    message = header + ifinfomsg

    with socket.socket(af_netlink, socket.SOCK_RAW, netlink_route) as netlink_socket:
        netlink_socket.bind((0, 0))
        netlink_socket.send(message)
        response = netlink_socket.recv(65535)

    if len(response) < 20:
        raise OSError("short netlink response")

    _, message_type, _, _, _ = struct.unpack("=IHHII", response[:16])
    if message_type != nlmsg_error:
        return

    (netlink_error,) = struct.unpack("=i", response[16:20])
    if netlink_error == 0:
        return

    error_number = -netlink_error
    if error_number in {errno.EPERM, errno.EACCES}:
        raise PermissionError(os.strerror(error_number))
    raise OSError(error_number, os.strerror(error_number))
