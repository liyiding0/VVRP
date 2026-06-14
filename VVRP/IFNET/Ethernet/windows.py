from __future__ import annotations

import ctypes
import socket
from ctypes import wintypes

from VVRP.IFNET.models import NetworkInterface


ERROR_ACCESS_DENIED = 5
ERROR_NO_MORE_ITEMS = 259
ERROR_NO_MORE_DATA = 234
ERROR_SUCCESS = 0
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_BUFFER_OVERFLOW = 111

KEY_READ = 0x20019
DICS_ENABLE = 0x00000001
DICS_DISABLE = 0x00000002
DICS_FLAG_GLOBAL = 0x00000001
DIF_PROPERTYCHANGE = 0x00000012
DIREG_DRV = 0x00000001
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
SPDRP_DEVICEDESC = 0x00000000
SPDRP_FRIENDLYNAME = 0x0000000C

CR_SUCCESS = 0
DN_HAS_PROBLEM = 0x00000400
CM_PROB_DISABLED = 0x00000016

MAX_ADAPTER_ADDRESS_LENGTH = 8
AF_UNSPEC = 0


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


GUID_DEVCLASS_NET = GUID(
    0x4D36E972,
    0xE325,
    0x11CE,
    (ctypes.c_ubyte * 8)(0xBF, 0xC1, 0x08, 0x00, 0x2B, 0xE1, 0x03, 0x18),
)


class SP_DEVINFO_DATA(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("ClassGuid", GUID),
        ("DevInst", wintypes.DWORD),
        ("Reserved", ctypes.c_size_t),
    ]


class SP_CLASSINSTALL_HEADER(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("InstallFunction", wintypes.DWORD),
    ]


class SP_PROPCHANGE_PARAMS(ctypes.Structure):
    _fields_ = [
        ("ClassInstallHeader", SP_CLASSINSTALL_HEADER),
        ("StateChange", wintypes.DWORD),
        ("Scope", wintypes.DWORD),
        ("HwProfile", wintypes.DWORD),
    ]


class IP_ADAPTER_ADDRESSES(ctypes.Structure):
    pass


IP_ADAPTER_ADDRESSES_POINTER = ctypes.POINTER(IP_ADAPTER_ADDRESSES)
IP_ADAPTER_ADDRESSES._fields_ = [
    ("Length", wintypes.ULONG),
    ("IfIndex", wintypes.DWORD),
    ("Next", IP_ADAPTER_ADDRESSES_POINTER),
    ("AdapterName", ctypes.c_char_p),
    ("FirstUnicastAddress", ctypes.c_void_p),
    ("FirstAnycastAddress", ctypes.c_void_p),
    ("FirstMulticastAddress", ctypes.c_void_p),
    ("FirstDnsServerAddress", ctypes.c_void_p),
    ("DnsSuffix", wintypes.LPWSTR),
    ("Description", wintypes.LPWSTR),
    ("FriendlyName", wintypes.LPWSTR),
    ("PhysicalAddress", ctypes.c_ubyte * MAX_ADAPTER_ADDRESS_LENGTH),
    ("PhysicalAddressLength", wintypes.DWORD),
    ("Flags", wintypes.DWORD),
    ("Mtu", wintypes.DWORD),
    ("IfType", wintypes.DWORD),
    ("OperStatus", wintypes.DWORD),
    ("Ipv6IfIndex", wintypes.DWORD),
    ("ZoneIndices", wintypes.DWORD * 16),
    ("FirstPrefix", ctypes.c_void_p),
]


def set_windows_network_adapter_enabled(
    interface: NetworkInterface,
    enabled: bool,
) -> None:
    identity = _adapter_identity_for_interface(interface)
    with _network_device(identity["adapter_name"], identity["names"]) as device:
        _change_device_state(device.info_set, device.data, enabled)
        actual_enabled = _is_device_enabled(device.data.DevInst)

    if actual_enabled != enabled:
        actual_state = "enabled" if actual_enabled else "disabled"
        expected_state = "enabled" if enabled else "disabled"
        raise OSError(
            "Windows network adapter state did not change: "
            f"{interface.name} is still {actual_state}, expected {expected_state}"
        )


def _adapter_identity_for_interface(interface: NetworkInterface) -> dict[str, object]:
    if interface.os_id:
        return {
            "adapter_name": interface.os_id,
            "names": tuple(
                name
                for name in (interface.name, interface.os_id, *interface.os_aliases)
                if name
            ),
        }
    if interface.index is None:
        raise OSError("missing OS interface index")
    return _adapter_identity_for_ifindex(interface.index)


class _DeviceInfo:
    def __init__(self, info_set, data: SP_DEVINFO_DATA) -> None:
        self.info_set = info_set
        self.data = data
        self._setupapi = _setupapi()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self._setupapi.SetupDiDestroyDeviceInfoList(self.info_set)


def _network_device(adapter_guid: str, candidate_names: tuple[str, ...] = ()) -> _DeviceInfo:
    setupapi = _setupapi()
    info_set = setupapi.SetupDiGetClassDevsW(
        ctypes.byref(GUID_DEVCLASS_NET),
        None,
        None,
        0,
    )
    if _is_invalid_handle(info_set):
        _raise_last_windows_error("SetupDiGetClassDevsW")

    try:
        normalized_adapter_guid = _normalize_guid(adapter_guid)
        normalized_candidate_names = {
            _normalize_name(name)
            for name in candidate_names
            if name
        }
        index = 0
        while True:
            data = SP_DEVINFO_DATA()
            data.cbSize = ctypes.sizeof(SP_DEVINFO_DATA)
            if not setupapi.SetupDiEnumDeviceInfo(info_set, index, ctypes.byref(data)):
                error = ctypes.get_last_error()
                if error == ERROR_NO_MORE_ITEMS:
                    break
                _raise_windows_error(error, "SetupDiEnumDeviceInfo")

            device_guid = _netcfg_instance_id(info_set, data)
            if device_guid and _normalize_guid(device_guid) == normalized_adapter_guid:
                return _DeviceInfo(info_set, data)

            device_names = {
                _normalize_name(_device_registry_property(info_set, data, SPDRP_FRIENDLYNAME)),
                _normalize_name(_device_registry_property(info_set, data, SPDRP_DEVICEDESC)),
            }
            device_names.discard("")
            if device_names & normalized_candidate_names:
                return _DeviceInfo(info_set, data)

            index += 1
    except Exception:
        setupapi.SetupDiDestroyDeviceInfoList(info_set)
        raise

    setupapi.SetupDiDestroyDeviceInfoList(info_set)
    raise OSError(f"Windows network adapter device not found: {adapter_guid}")


def _change_device_state(info_set, data: SP_DEVINFO_DATA, enabled: bool) -> None:
    setupapi = _setupapi()
    params = SP_PROPCHANGE_PARAMS()
    params.ClassInstallHeader.cbSize = ctypes.sizeof(SP_CLASSINSTALL_HEADER)
    params.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE
    params.StateChange = DICS_ENABLE if enabled else DICS_DISABLE
    params.Scope = DICS_FLAG_GLOBAL
    params.HwProfile = 0

    params_pointer = ctypes.cast(
        ctypes.byref(params),
        ctypes.POINTER(SP_CLASSINSTALL_HEADER),
    )
    if not setupapi.SetupDiSetClassInstallParamsW(
        info_set,
        ctypes.byref(data),
        params_pointer,
        ctypes.sizeof(params),
    ):
        _raise_last_windows_error("SetupDiSetClassInstallParamsW")

    if not setupapi.SetupDiCallClassInstaller(
        DIF_PROPERTYCHANGE,
        info_set,
        ctypes.byref(data),
    ):
        _raise_last_windows_error("SetupDiCallClassInstaller")


def _is_device_enabled(dev_inst: int) -> bool:
    cfgmgr32 = _cfgmgr32()
    status = wintypes.ULONG()
    problem = wintypes.ULONG()
    result = cfgmgr32.CM_Get_DevNode_Status(
        ctypes.byref(status),
        ctypes.byref(problem),
        dev_inst,
        0,
    )
    if result != CR_SUCCESS:
        raise OSError(f"CM_Get_DevNode_Status failed: {result}")

    return not (status.value & DN_HAS_PROBLEM and problem.value == CM_PROB_DISABLED)


def _netcfg_instance_id(info_set, data: SP_DEVINFO_DATA) -> str:
    setupapi = _setupapi()
    advapi32 = _advapi32()
    key = setupapi.SetupDiOpenDevRegKey(
        info_set,
        ctypes.byref(data),
        DICS_FLAG_GLOBAL,
        0,
        DIREG_DRV,
        KEY_READ,
    )
    if _is_invalid_handle(key):
        return ""

    try:
        value_type = wintypes.DWORD()
        buffer_size = wintypes.DWORD(512 * ctypes.sizeof(wintypes.WCHAR))
        buffer = ctypes.create_unicode_buffer(512)
        error = advapi32.RegQueryValueExW(
            key,
            "NetCfgInstanceId",
            None,
            ctypes.byref(value_type),
            ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)),
            ctypes.byref(buffer_size),
        )
        if error == ERROR_SUCCESS:
            return buffer.value
        if error in {ERROR_NO_MORE_DATA, ERROR_INSUFFICIENT_BUFFER}:
            length = max(512, buffer_size.value // ctypes.sizeof(wintypes.WCHAR) + 1)
            buffer = ctypes.create_unicode_buffer(length)
            error = advapi32.RegQueryValueExW(
                key,
                "NetCfgInstanceId",
                None,
                ctypes.byref(value_type),
                ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)),
                ctypes.byref(buffer_size),
            )
            if error == ERROR_SUCCESS:
                return buffer.value
        return ""
    finally:
        advapi32.RegCloseKey(key)


def _adapter_guid_for_ifindex(index: int) -> str:
    return _adapter_identity_for_ifindex(index)["adapter_name"]


def _adapter_identity_for_ifindex(index: int) -> dict[str, object]:
    for row in _adapter_index_rows():
        ipv4_index, ipv6_index, adapter_name, friendly_name, description = row
        if ipv4_index == index or ipv6_index == index:
            return {
                "adapter_name": adapter_name,
                "names": tuple(
                    name
                    for name in (friendly_name, adapter_name, description)
                    if name
                ),
            }
    raise OSError(f"Windows adapter GUID not found for interface index {index}")


def _adapter_index_rows() -> list[tuple[int, int, str, str, str]]:
    iphlpapi = _iphlpapi()
    buffer_size = wintypes.ULONG(15_000)
    buffer = ctypes.create_string_buffer(buffer_size.value)
    result = iphlpapi.GetAdaptersAddresses(
        AF_UNSPEC,
        0,
        None,
        ctypes.cast(buffer, IP_ADAPTER_ADDRESSES_POINTER),
        ctypes.byref(buffer_size),
    )
    if result == ERROR_BUFFER_OVERFLOW:
        buffer = ctypes.create_string_buffer(buffer_size.value)
        result = iphlpapi.GetAdaptersAddresses(
            AF_UNSPEC,
            0,
            None,
            ctypes.cast(buffer, IP_ADAPTER_ADDRESSES_POINTER),
            ctypes.byref(buffer_size),
        )
    if result != ERROR_SUCCESS:
        raise OSError(f"GetAdaptersAddresses failed: {result}")

    adapters: list[tuple[int, int, str, str, str]] = []
    current = ctypes.cast(buffer, IP_ADAPTER_ADDRESSES_POINTER)
    while current:
        adapter = current.contents
        adapters.append(
            (
                int(adapter.IfIndex),
                int(adapter.Ipv6IfIndex),
                _decode_adapter_name(adapter.AdapterName),
                adapter.FriendlyName or "",
                adapter.Description or "",
            )
        )
        current = adapter.Next
    return adapters


def _decode_adapter_name(adapter_name: bytes | None) -> str:
    if not adapter_name:
        return ""
    return adapter_name.decode("ascii", errors="ignore")


def _normalize_guid(value: str) -> str:
    return value.strip("{}").casefold()


def _normalize_name(value: str) -> str:
    return value.casefold().strip()


def _device_registry_property(
    info_set,
    data: SP_DEVINFO_DATA,
    property_id: int,
) -> str:
    setupapi = _setupapi()
    value_type = wintypes.DWORD()
    required_size = wintypes.DWORD()
    buffer = ctypes.create_unicode_buffer(512)
    if setupapi.SetupDiGetDeviceRegistryPropertyW(
        info_set,
        ctypes.byref(data),
        property_id,
        ctypes.byref(value_type),
        ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)),
        ctypes.sizeof(buffer),
        ctypes.byref(required_size),
    ):
        return buffer.value
    return ""


def _is_invalid_handle(handle) -> bool:
    return ctypes.c_void_p(handle).value == INVALID_HANDLE_VALUE


def _setupapi():
    library = ctypes.WinDLL("setupapi", use_last_error=True)
    library.SetupDiGetClassDevsW.argtypes = [
        ctypes.POINTER(GUID),
        wintypes.LPCWSTR,
        wintypes.HWND,
        wintypes.DWORD,
    ]
    library.SetupDiGetClassDevsW.restype = wintypes.HANDLE
    library.SetupDiEnumDeviceInfo.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(SP_DEVINFO_DATA),
    ]
    library.SetupDiEnumDeviceInfo.restype = wintypes.BOOL
    library.SetupDiDestroyDeviceInfoList.argtypes = [wintypes.HANDLE]
    library.SetupDiDestroyDeviceInfoList.restype = wintypes.BOOL
    library.SetupDiOpenDevRegKey.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(SP_DEVINFO_DATA),
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    library.SetupDiOpenDevRegKey.restype = wintypes.HKEY
    library.SetupDiGetDeviceRegistryPropertyW.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(SP_DEVINFO_DATA),
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(ctypes.c_ubyte),
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    library.SetupDiGetDeviceRegistryPropertyW.restype = wintypes.BOOL
    library.SetupDiSetClassInstallParamsW.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(SP_DEVINFO_DATA),
        ctypes.POINTER(SP_CLASSINSTALL_HEADER),
        wintypes.DWORD,
    ]
    library.SetupDiSetClassInstallParamsW.restype = wintypes.BOOL
    library.SetupDiCallClassInstaller.argtypes = [
        wintypes.DWORD,
        wintypes.HANDLE,
        ctypes.POINTER(SP_DEVINFO_DATA),
    ]
    library.SetupDiCallClassInstaller.restype = wintypes.BOOL
    return library


def _cfgmgr32():
    library = ctypes.WinDLL("cfgmgr32", use_last_error=True)
    library.CM_Get_DevNode_Status.argtypes = [
        ctypes.POINTER(wintypes.ULONG),
        ctypes.POINTER(wintypes.ULONG),
        wintypes.DWORD,
        wintypes.ULONG,
    ]
    library.CM_Get_DevNode_Status.restype = wintypes.DWORD
    return library


def _advapi32():
    library = ctypes.WinDLL("advapi32", use_last_error=True)
    library.RegQueryValueExW.argtypes = [
        wintypes.HKEY,
        wintypes.LPCWSTR,
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.POINTER(wintypes.DWORD),
    ]
    library.RegQueryValueExW.restype = wintypes.LONG
    library.RegCloseKey.argtypes = [wintypes.HKEY]
    library.RegCloseKey.restype = wintypes.LONG
    return library


def _iphlpapi():
    library = ctypes.WinDLL("iphlpapi", use_last_error=True)
    library.GetAdaptersAddresses.argtypes = [
        wintypes.ULONG,
        wintypes.ULONG,
        ctypes.c_void_p,
        IP_ADAPTER_ADDRESSES_POINTER,
        ctypes.POINTER(wintypes.ULONG),
    ]
    library.GetAdaptersAddresses.restype = wintypes.ULONG
    return library


def _raise_last_windows_error(function_name: str) -> None:
    _raise_windows_error(ctypes.get_last_error(), function_name)


def _raise_windows_error(error: int, function_name: str) -> None:
    if error == ERROR_ACCESS_DENIED:
        raise PermissionError(f"{function_name}: Administrator privileges are required")
    raise OSError(f"{function_name}: Windows API error {error}")


def validate_windows_imports_for_tests() -> None:
    # Keeps static import checks explicit without touching the OS.
    _ = socket.AF_UNSPEC
