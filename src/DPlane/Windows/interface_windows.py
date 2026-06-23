from __future__ import annotations

import ctypes
import ipaddress
import socket
from ctypes import wintypes

from src.IFNET.models import NetworkInterface
from src.IP.static import IP_StaticIpv4Address


ERROR_ACCESS_DENIED = 5
ERROR_NO_MORE_ITEMS = 259
ERROR_NO_MORE_DATA = 234
ERROR_NOT_FOUND = 1168
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
AF_INET = 2
ADDRESS_FAMILY_IPV4 = 2
PREFIX_ORIGIN_MANUAL = 1
SUFFIX_ORIGIN_MANUAL = 1

WMI_SUCCESS_REBOOT_NOT_REQUIRED = 0
WMI_SUCCESS_REBOOT_REQUIRED = 1
WMI_DHCP_NOT_ENABLED = 100
WMI_ACCESS_DENIED = 91

WMI_RETURN_MESSAGES = {
    64: "method not supported on this platform",
    65: "unknown failure",
    66: "invalid subnet mask",
    67: "error processing an instance",
    68: "invalid input parameter",
    69: "more than five gateways specified",
    70: "invalid IP address",
    71: "invalid gateway IP address",
    72: "error accessing registry",
    73: "invalid domain name",
    74: "invalid host name",
    75: "no primary/secondary WINS server defined",
    76: "invalid file",
    77: "invalid system path",
    78: "file copy failed",
    79: "invalid security parameter",
    80: "unable to configure TCP/IP service",
    81: "unable to configure DHCP service",
    82: "unable to renew DHCP lease",
    83: "unable to release DHCP lease",
    84: "IP not enabled on adapter",
    85: "IPX not enabled on adapter",
    WMI_ACCESS_DENIED: "access denied",
    97: "interface not configurable",
    98: "DHCP not enabled on adapter",
    WMI_DHCP_NOT_ENABLED: "DHCP not enabled on adapter",
}

IPHELPER_ERROR_MESSAGES = {
    5: "access denied",
    87: "invalid parameter",
    5010: "object already exists",
}


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


class IN_ADDR(ctypes.Union):
    _fields_ = [
        ("S_addr", wintypes.ULONG),
        ("S_un_b", ctypes.c_ubyte * 4),
    ]


class SOCKADDR_IN(ctypes.Structure):
    _fields_ = [
        ("sin_family", wintypes.USHORT),
        ("sin_port", wintypes.USHORT),
        ("sin_addr", IN_ADDR),
        ("sin_zero", ctypes.c_char * 8),
    ]


class IN6_ADDR(ctypes.Union):
    _fields_ = [
        ("Byte", ctypes.c_ubyte * 16),
        ("Word", wintypes.USHORT * 8),
    ]


class SOCKADDR_IN6(ctypes.Structure):
    _fields_ = [
        ("sin6_family", wintypes.USHORT),
        ("sin6_port", wintypes.USHORT),
        ("sin6_flowinfo", wintypes.ULONG),
        ("sin6_addr", IN6_ADDR),
        ("sin6_scope_id", wintypes.ULONG),
    ]


class SOCKADDR_INET(ctypes.Union):
    _fields_ = [
        ("Ipv4", SOCKADDR_IN),
        ("Ipv6", SOCKADDR_IN6),
        ("si_family", wintypes.USHORT),
    ]


class NET_LUID(ctypes.Union):
    _fields_ = [
        ("Value", ctypes.c_ulonglong),
    ]


class SCOPE_ID(ctypes.Union):
    _fields_ = [
        ("Value", wintypes.ULONG),
    ]


class LARGE_INTEGER(ctypes.Union):
    _fields_ = [
        ("QuadPart", ctypes.c_longlong),
    ]


class MIB_UNICASTIPADDRESS_ROW(ctypes.Structure):
    _fields_ = [
        ("Address", SOCKADDR_INET),
        ("InterfaceLuid", NET_LUID),
        ("InterfaceIndex", wintypes.ULONG),
        ("PrefixOrigin", ctypes.c_int),
        ("SuffixOrigin", ctypes.c_int),
        ("ValidLifetime", wintypes.ULONG),
        ("PreferredLifetime", wintypes.ULONG),
        ("OnLinkPrefixLength", ctypes.c_ubyte),
        ("SkipAsSource", wintypes.BOOLEAN),
        ("DadState", ctypes.c_int),
        ("ScopeId", SCOPE_ID),
        ("CreationTimeStamp", LARGE_INTEGER),
    ]


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


def set_windows_network_adapter_dhcp(
    interface: NetworkInterface,
    enabled: bool,
) -> str:
    _, ip_interface = _wmi_ipv4_interface_for_interface(interface)
    _, adapter_config = _wmi_adapter_configuration_for_interface(interface)

    if enabled:
        _set_msft_netipinterface_dhcp(ip_interface, enabled=True)
        if adapter_config is not None:
            _call_wmi_instance_method(adapter_config, "EnableDHCP")
            renew_code = _call_wmi_instance_method(
                adapter_config,
                "RenewDHCPLease",
                raise_on_error=False,
            )
            if not _wmi_success(renew_code):
                return (
                    "% DHCP client enabled; DHCP lease renewal did not complete: "
                    f"{_format_wmi_return('RenewDHCPLease', renew_code)}"
                )
        return ""

    release_warning = ""
    if adapter_config is not None:
        release_code = _call_wmi_instance_method(
            adapter_config,
            "ReleaseDHCPLease",
            raise_on_error=False,
        )
        if not _wmi_success(release_code) and release_code != WMI_DHCP_NOT_ENABLED:
            release_warning = (
                "% DHCP client disabled; DHCP lease release did not complete: "
                f"{_format_wmi_return('ReleaseDHCPLease', release_code)}"
            )

    _set_msft_netipinterface_dhcp(ip_interface, enabled=False)
    return release_warning


def set_windows_static_ipv4(
    interface: NetworkInterface,
    address: IP_StaticIpv4Address,
) -> str:
    _create_unicast_ipv4_address(interface, address)
    return ""


def _set_windows_primary_static_ipv4(
    interface: NetworkInterface,
    address: IP_StaticIpv4Address,
) -> str:
    service, adapter_config = _wmi_adapter_configuration_for_interface(interface)
    if adapter_config is None:
        raise OSError(f"Windows adapter configuration not found: {interface.name}")

    addresses = [address.address]
    masks = [address.subnet_mask]
    for existing in _wmi_manual_ipv4_addresses(_wmi_service(r"root\StandardCimv2"), interface):
        existing_address = str(getattr(existing, "IPAddress", ""))
        existing_prefix = int(getattr(existing, "PrefixLength", -1))
        if not existing_address or existing_address == address.address:
            continue
        if existing_prefix < 0:
            continue
        addresses.append(existing_address)
        masks.append(IP_StaticIpv4Address(existing_address, existing_prefix, secondary=True).subnet_mask)

    address_values = tuple(addresses)
    mask_values = tuple(masks)
    code = _call_wmi_instance_method(
        adapter_config,
        "EnableStatic",
        address_values,
        mask_values,
        raise_on_error=False,
    )
    if code == 68:
        code = _call_wmi_object_method(
            service,
            adapter_config,
            "EnableStatic",
            {"IPAddress": address_values, "SubnetMask": mask_values},
            raise_on_error=False,
        )
    _check_wmi_return(code, "Win32_NetworkAdapterConfiguration.EnableStatic")
    return ""


def remove_windows_static_ipv4(
    interface: NetworkInterface,
    address: IP_StaticIpv4Address | None = None,
) -> str:
    service = _wmi_service(r"root\StandardCimv2")
    addresses = _wmi_manual_ipv4_addresses(service, interface, address)
    for ip_address in addresses:
        static_address = IP_StaticIpv4Address(
            str(getattr(ip_address, "IPAddress", "")),
            int(getattr(ip_address, "PrefixLength", -1)),
        )
        _delete_unicast_ipv4_address(interface, static_address)
    return ""


def _create_unicast_ipv4_address(
    interface: NetworkInterface,
    address: IP_StaticIpv4Address,
) -> None:
    iphlpapi = _iphlpapi()
    row = _unicast_ipv4_row(interface, address)
    result = iphlpapi.CreateUnicastIpAddressEntry(ctypes.byref(row))
    if result == 5010:
        return
    _check_iphelper_result(result, "CreateUnicastIpAddressEntry")


def _delete_unicast_ipv4_address(
    interface: NetworkInterface,
    address: IP_StaticIpv4Address,
) -> None:
    if not address.address or address.prefix_length < 0:
        return
    iphlpapi = _iphlpapi()
    row = _unicast_ipv4_row(interface, address)
    result = iphlpapi.DeleteUnicastIpAddressEntry(ctypes.byref(row))
    if result == ERROR_NOT_FOUND:
        return
    _check_iphelper_result(result, "DeleteUnicastIpAddressEntry")


def _unicast_ipv4_row(
    interface: NetworkInterface,
    address: IP_StaticIpv4Address,
) -> MIB_UNICASTIPADDRESS_ROW:
    iphlpapi = _iphlpapi()
    row = MIB_UNICASTIPADDRESS_ROW()
    iphlpapi.InitializeUnicastIpAddressEntry(ctypes.byref(row))
    row.Address.Ipv4.sin_family = AF_INET
    row.Address.Ipv4.sin_port = 0
    row.Address.Ipv4.sin_addr.S_un_b[:] = ipaddress.IPv4Address(address.address).packed
    row.InterfaceIndex = _require_windows_interface_index(interface)
    row.PrefixOrigin = PREFIX_ORIGIN_MANUAL
    row.SuffixOrigin = SUFFIX_ORIGIN_MANUAL
    row.OnLinkPrefixLength = address.prefix_length
    row.SkipAsSource = False
    return row


def _adapter_identity_for_interface(interface: NetworkInterface) -> dict[str, object]:
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


def _wmi_ipv4_interface_for_interface(interface: NetworkInterface):
    service = _wmi_service(r"root\StandardCimv2")
    for query in _wmi_netip_interface_queries(interface):
        match = _wmi_first(service, query)
        if match is not None:
            return service, match
    raise OSError(f"Windows IPv4 interface not found: {interface.name}")


def _wmi_adapter_configuration_for_interface(interface: NetworkInterface):
    service = _wmi_service(r"root\cimv2")
    for query in _wmi_adapter_configuration_queries(interface):
        match = _wmi_first(service, query)
        if match is not None:
            return service, match
    return service, None


def _wmi_manual_ipv4_addresses(
    service,
    interface: NetworkInterface,
    address: IP_StaticIpv4Address | None = None,
):
    queries: list[str] = [
        "SELECT * FROM MSFT_NetIPAddress "
        f"WHERE InterfaceIndex = {_require_windows_interface_index(interface)} "
        f"AND AddressFamily = {ADDRESS_FAMILY_IPV4}"
    ]
    for name in _interface_identity_names(interface):
        queries.append(
            "SELECT * FROM MSFT_NetIPAddress "
            f"WHERE InterfaceAlias = {_wql_string(name)} "
            f"AND AddressFamily = {ADDRESS_FAMILY_IPV4}"
        )

    matches = []
    seen_paths: set[str] = set()
    for query in dict.fromkeys(queries):
        try:
            rows = list(service.ExecQuery(query))
        except Exception as exc:
            raise OSError(f"WMI query failed: {query}: {exc}") from exc
        for row in rows:
            path = getattr(getattr(row, "Path_", None), "Path", "")
            if path and path in seen_paths:
                continue
            if not _wmi_ipv4_address_is_manual(row):
                continue
            if address is not None and not _wmi_ipv4_address_matches(row, address):
                continue
            if path:
                seen_paths.add(path)
            matches.append(row)
    return tuple(matches)


def _wmi_ipv4_address_is_manual(row) -> bool:
    prefix_origin = getattr(row, "PrefixOrigin", None)
    suffix_origin = getattr(row, "SuffixOrigin", None)
    return prefix_origin == PREFIX_ORIGIN_MANUAL or suffix_origin == PREFIX_ORIGIN_MANUAL


def _wmi_ipv4_address_matches(row, address: IP_StaticIpv4Address) -> bool:
    return (
        str(getattr(row, "IPAddress", "")) == address.address
        and int(getattr(row, "PrefixLength", -1)) == address.prefix_length
    )


def _require_windows_interface_index(interface: NetworkInterface) -> int:
    if interface.index is not None:
        return int(interface.index)
    identity = _adapter_identity_for_interface(interface)
    for ipv4_index, _, adapter_name, _, _ in _adapter_index_rows():
        if _normalize_guid(adapter_name) == _normalize_guid(str(identity["adapter_name"])):
            return ipv4_index
    raise OSError("missing OS interface index")


def _wmi_netip_interface_queries(interface: NetworkInterface) -> tuple[str, ...]:
    queries: list[str] = []
    if interface.index is not None:
        queries.append(
            "SELECT * FROM MSFT_NetIPInterface "
            f"WHERE InterfaceIndex = {int(interface.index)} "
            f"AND AddressFamily = {ADDRESS_FAMILY_IPV4}"
        )
    for name in _interface_identity_names(interface):
        queries.append(
            "SELECT * FROM MSFT_NetIPInterface "
            f"WHERE InterfaceAlias = {_wql_string(name)} "
            f"AND AddressFamily = {ADDRESS_FAMILY_IPV4}"
        )
    return tuple(dict.fromkeys(queries))


def _wmi_adapter_configuration_queries(interface: NetworkInterface) -> tuple[str, ...]:
    queries: list[str] = []
    if interface.index is not None:
        queries.append(
            "SELECT * FROM Win32_NetworkAdapterConfiguration "
            f"WHERE InterfaceIndex = {int(interface.index)}"
        )
    for name in _interface_identity_names(interface):
        queries.append(
            "SELECT * FROM Win32_NetworkAdapterConfiguration "
            f"WHERE Description = {_wql_string(name)}"
        )
        queries.append(
            "SELECT * FROM Win32_NetworkAdapterConfiguration "
            f"WHERE Caption = {_wql_string(name)}"
        )
    return tuple(dict.fromkeys(queries))


def _interface_identity_names(interface: NetworkInterface) -> tuple[str, ...]:
    names = [interface.name]
    try:
        identity = _adapter_identity_for_interface(interface)
    except OSError:
        pass
    else:
        names.append(str(identity["adapter_name"]))
        names.extend(str(name) for name in identity["names"])
    return tuple(dict.fromkeys(name for name in names if name))


def _set_msft_netipinterface_dhcp(ip_interface, enabled: bool) -> None:
    try:
        ip_interface.Dhcp = 1 if enabled else 0
        ip_interface.Put_()
    except Exception as exc:
        if _is_access_denied_exception(exc):
            raise PermissionError("MSFT_NetIPInterface.Put_: access denied") from exc
        raise OSError(f"MSFT_NetIPInterface.Put_: WMI update failed: {exc}") from exc


def _wmi_first(service, query: str):
    try:
        rows = list(service.ExecQuery(query))
    except Exception as exc:
        raise OSError(f"WMI query failed: {query}: {exc}") from exc
    if not rows:
        return None
    return rows[0]


def _wmi_service(namespace: str):
    try:
        import win32com.client
    except ImportError as exc:
        raise OSError(
            "pywin32 is required for the Windows DHCP API backend"
        ) from exc

    try:
        return win32com.client.GetObject(
            rf"winmgmts:{{impersonationLevel=impersonate}}!\\.\{namespace}"
        )
    except Exception as exc:
        if _is_access_denied_exception(exc):
            raise PermissionError("WMI access denied") from exc
        raise OSError(f"WMI connection failed: {exc}") from exc


def _call_wmi_instance_method(
    instance,
    method_name: str,
    *args,
    raise_on_error: bool = True,
) -> int:
    try:
        result = getattr(instance, method_name)
        if callable(result):
            result = result(*args)
        code = _wmi_return_code(result)
    except Exception as exc:
        if _is_access_denied_exception(exc):
            raise PermissionError(f"{method_name}: access denied") from exc
        detail = f"{method_name}: WMI method failed"
        if args:
            detail += f" with args {args!r}"
        raise OSError(f"{detail}: {exc}") from exc

    if raise_on_error:
        _check_wmi_return(code, method_name)
    return code


def _call_wmi_class_method(
    service,
    wmi_class,
    method_name: str,
    input_values: dict[str, object],
    raise_on_error: bool = True,
) -> int:
    try:
        method = wmi_class.Methods_(method_name)
        in_params = method.InParameters.SpawnInstance_()
        for key, value in input_values.items():
            setattr(in_params, key, value)
        result = service.ExecMethod_(wmi_class.Path_.Path, method_name, in_params)
        code = _wmi_return_code(result)
    except Exception as exc:
        if _is_access_denied_exception(exc):
            raise PermissionError(f"{method_name}: access denied") from exc
        raise OSError(
            f"{method_name}: WMI class method failed with inputs {input_values!r}: {exc}"
        ) from exc

    if raise_on_error:
        _check_wmi_return(code, method_name)
    return code


def _call_wmi_object_method(
    service,
    instance,
    method_name: str,
    input_values: dict[str, object],
    raise_on_error: bool = True,
) -> int:
    try:
        method = instance.Methods_(method_name)
        in_params = method.InParameters.SpawnInstance_()
        for key, value in input_values.items():
            setattr(in_params, key, value)
        path = getattr(getattr(instance, "Path_", None), "Path", "")
        result = service.ExecMethod_(path, method_name, in_params)
        code = _wmi_return_code(result)
    except Exception as exc:
        if _is_access_denied_exception(exc):
            raise PermissionError(f"{method_name}: access denied") from exc
        raise OSError(
            f"{method_name}: WMI object method failed with inputs {input_values!r}: {exc}"
        ) from exc

    if raise_on_error:
        _check_wmi_return(code, method_name)
    return code


def _delete_wmi_instance(instance, method_name: str) -> None:
    try:
        result = getattr(instance, "Delete_")
        if callable(result):
            result = result()
        code = _wmi_return_code(result)
    except Exception as exc:
        if _is_access_denied_exception(exc):
            raise PermissionError(f"{method_name}: access denied") from exc
        raise OSError(f"{method_name}: WMI delete failed: {exc}") from exc

    _check_wmi_return(code, method_name)


def _wmi_return_code(result) -> int:
    if result is None:
        return WMI_SUCCESS_REBOOT_NOT_REQUIRED
    if isinstance(result, tuple):
        for item in result:
            if isinstance(item, int):
                return int(item)
        return WMI_SUCCESS_REBOOT_NOT_REQUIRED
    return int(getattr(result, "ReturnValue", result))


def _check_wmi_return(code: int, method_name: str) -> None:
    if _wmi_success(code):
        return
    if code == WMI_ACCESS_DENIED:
        raise PermissionError(f"{method_name}: access denied")
    raise OSError(_format_wmi_return(method_name, code))


def _wmi_success(code: int) -> bool:
    return code in {WMI_SUCCESS_REBOOT_NOT_REQUIRED, WMI_SUCCESS_REBOOT_REQUIRED}


def _format_wmi_return(method_name: str, code: int) -> str:
    message = WMI_RETURN_MESSAGES.get(code, "unknown WMI return code")
    return f"{method_name}: WMI return code {code} ({message})"


def _check_iphelper_result(result: int, function_name: str) -> None:
    if result == ERROR_SUCCESS:
        return
    if result == ERROR_ACCESS_DENIED:
        raise PermissionError(f"{function_name}: Administrator privileges are required")
    message = IPHELPER_ERROR_MESSAGES.get(result, "Windows IP Helper API error")
    raise OSError(f"{function_name}: Windows API error {result} ({message})")


def _is_access_denied_exception(exc: Exception) -> bool:
    text = str(exc).casefold()
    return "access denied" in text or "0x80070005" in text


def _wql_string(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


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
    library.InitializeUnicastIpAddressEntry.argtypes = [
        ctypes.POINTER(MIB_UNICASTIPADDRESS_ROW),
    ]
    library.InitializeUnicastIpAddressEntry.restype = None
    library.CreateUnicastIpAddressEntry.argtypes = [
        ctypes.POINTER(MIB_UNICASTIPADDRESS_ROW),
    ]
    library.CreateUnicastIpAddressEntry.restype = wintypes.DWORD
    library.DeleteUnicastIpAddressEntry.argtypes = [
        ctypes.POINTER(MIB_UNICASTIPADDRESS_ROW),
    ]
    library.DeleteUnicastIpAddressEntry.restype = wintypes.DWORD
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

