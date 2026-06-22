from __future__ import annotations

import platform
from pathlib import Path

from .models import DPlane_PlatformInfo


g_DPlane_OPENWRT_RELEASE_PATH = Path("/etc/openwrt_release")
g_DPlane_OS_RELEASE_PATH = Path("/etc/os-release")


def DPlane_detect_platform() -> DPlane_PlatformInfo:
    DPlane_system = platform.system()
    DPlane_normalized = DPlane_system.lower()
    DPlane_release = platform.release()

    if DPlane_normalized == "windows":
        return DPlane_PlatformInfo(
            kind="windows",
            system=DPlane_system,
            release=DPlane_release,
            description=platform.platform(),
        )

    if DPlane_normalized == "linux":
        if DPlane_is_openwrt():
            return DPlane_PlatformInfo(
                kind="openwrt",
                system=DPlane_system,
                release=DPlane_release,
                description="OpenWRT",
            )
        return DPlane_PlatformInfo(
            kind="linux",
            system=DPlane_system,
            release=DPlane_release,
            description=platform.platform(),
        )

    return DPlane_PlatformInfo(
        kind="unsupported",
        system=DPlane_system,
        release=DPlane_release,
        description=platform.platform(),
    )


def DPlane_is_openwrt() -> bool:
    if g_DPlane_OPENWRT_RELEASE_PATH.exists():
        return True
    try:
        DPlane_content = g_DPlane_OS_RELEASE_PATH.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    return "ID=openwrt" in DPlane_content or 'ID="openwrt"' in DPlane_content
