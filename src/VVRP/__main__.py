from __future__ import annotations

import argparse
import os

from src.CMD.module import CMD_start_module
from src.CMD.process_reboot import g_CMD_REBOOT_MODULE_ENV

from .core import VVRP_create_core


def main() -> int:
    VVRP_parser = argparse.ArgumentParser(description="Start the VVRP runtime.")
    VVRP_parser.add_argument(
        "--no-cmd",
        action="store_true",
        help="Start VVRP runtime without launching the CMD CLI.",
    )
    VVRP_args = VVRP_parser.parse_args()
    os.environ[g_CMD_REBOOT_MODULE_ENV] = "VVRP"
    VVRP_hostname = os.environ.get("VVRP_CMD_HOSTNAME", "Router")

    print("VVRP is starting...")
    print("[1/4] Initializing runtime modules...")
    VVRP_core = VVRP_create_core(hostname=VVRP_hostname)
    print("      DPlane, ETHERNET, IFNET, ARP, IP, ICMP, RM, FIB, FWD, SOCK")
    print("[2/4] Starting core services...")
    VVRP_core_status = VVRP_core.start()
    print(f"      Packet input: {VVRP_core_status}")

    if VVRP_args.no_cmd:
        print("[3/4] CMD module disabled by --no-cmd.")
        print("[4/4] VVRP startup sequence complete.")
        return 0

    VVRP_history_file = os.environ.get("VVRP_CMD_HISTORY")
    VVRP_saved_configuration_file = os.environ.get("VVRP_SAVED_CONFIGURATION")
    print("[3/4] Starting CMD module...")

    def VVRP_CMD_ready() -> None:
        print("      CMD module is ready.")
        print("[4/4] VVRP startup complete.")

    return CMD_start_module(
        VVRP_core,
        history_file=VVRP_history_file,
        saved_configuration_file=VVRP_saved_configuration_file,
        CMD_on_ready=VVRP_CMD_ready,
    )


if __name__ == "__main__":
    raise SystemExit(main())
