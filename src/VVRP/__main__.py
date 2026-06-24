from __future__ import annotations

import argparse
import os

from src.CCmd.examples import build_default_registry
from src.CCmd.interactive import run_interactive_cli

from .runtime import VVRP_create_runtime


def main() -> int:
    VVRP_parser = argparse.ArgumentParser(description="Start the VVRP runtime.")
    VVRP_parser.add_argument(
        "--no-ccmd",
        action="store_true",
        help="Start VVRP runtime without launching the CCmd CLI.",
    )
    VVRP_args = VVRP_parser.parse_args()
    VVRP_runtime = VVRP_create_runtime()
    if VVRP_args.no_ccmd:
        return 0

    VVRP_history_file = os.environ.get("VVRP_CCMD_HISTORY")
    VVRP_saved_configuration_file = os.environ.get("VVRP_SAVED_CONFIGURATION")
    VVRP_hostname = os.environ.get("VVRP_CCMD_HOSTNAME", "Router")
    VVRP_registry = build_default_registry(runtime=VVRP_runtime)
    return run_interactive_cli(
        VVRP_registry,
        hostname=VVRP_hostname,
        history_file=VVRP_history_file,
        saved_configuration_file=VVRP_saved_configuration_file,
    )


if __name__ == "__main__":
    raise SystemExit(main())
