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
    VVRP_core = VVRP_create_core(hostname=VVRP_hostname)
    VVRP_core.start()
    if VVRP_args.no_cmd:
        return 0

    VVRP_history_file = os.environ.get("VVRP_CMD_HISTORY")
    VVRP_saved_configuration_file = os.environ.get("VVRP_SAVED_CONFIGURATION")
    return CMD_start_module(
        VVRP_core,
        history_file=VVRP_history_file,
        saved_configuration_file=VVRP_saved_configuration_file,
    )


if __name__ == "__main__":
    raise SystemExit(main())
