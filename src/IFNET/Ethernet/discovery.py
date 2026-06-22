from __future__ import annotations


EXCLUDED_ETHERNET_NAME_MARKERS = (
    "wi-fi",
    "wifi",
    "wireless",
    "vpn",
    "tunnel",
    "ppp",
)


def is_ethernet_interface(name: str, mac_address: str) -> bool:
    normalized = name.lower()
    if any(marker in normalized for marker in EXCLUDED_ETHERNET_NAME_MARKERS):
        return False
    return bool(mac_address)

